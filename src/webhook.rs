//! Webhook-driven credential invalidation (`POST /webhooks/github`, #50).
//!
//! GitHub App webhooks push revocation signals instead of letting minted
//! installation tokens age out — without this endpoint the worst-case
//! revocation latency is the installation-token TTL (~1h) plus a restart.
//!
//! The listener is OPT-IN: it requires ingress from GitHub (or a relay that
//! forwards signed payloads), which trades against the egress-only
//! deployment posture. With no `[webhooks] github_secret` configured the
//! route still wins over the catch-all but fails closed with 404.
//!
//! Every request must carry a valid `X-Hub-Signature-256`
//! (`sha256=` + hex HMAC-SHA256 of the raw body, keyed with the shared
//! secret); anything else is rejected 401 before the payload is parsed.
//!
//! Handled deliveries:
//! - `installation` {suspend, deleted} — drop that installation's token
//!   cache (MCP + git purposes) and kill its pinned upstream sessions.
//! - `installation_repositories` {removed} — drop cached tokens whose repo
//!   scope intersects the removed repositories (sessions keep their pinned
//!   token, which stays valid for whatever it still covers).
//! - `github_app_authorization` {revoked} — the payload names no
//!   installation, so every configured App gets the suspension treatment.
//!
//! All other events/actions are acknowledged 200 and invalidate nothing.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;

use crate::mcp::{rpc_error, PinnedCred};
use crate::AppState;

/// Hard cap on webhook bodies (axum's DefaultBodyLimit is layered on the
/// route). Real installation payloads are a few KB even with long
/// repository lists (~200-400 B per entry); 4 MiB covers ~10k repos.
/// Anything larger gets 413 before verification — GitHub redelivers, and
/// revocation stays fail-closed at token-TTL latency until a payload fits.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

pub async fn github_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(secret) = state
        .config
        .webhooks
        .github_secret
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    else {
        return rpc_error(StatusCode::NOT_FOUND, "webhooks are not configured");
    };
    if !signature_valid(secret, &headers, &body) {
        tracing::warn!("webhook rejected: missing or invalid X-Hub-Signature-256");
        return rpc_error(StatusCode::UNAUTHORIZED, "invalid webhook signature");
    }
    let Some(event) = headers.get("x-github-event").and_then(|v| v.to_str().ok()) else {
        return rpc_error(StatusCode::BAD_REQUEST, "missing X-GitHub-Event header");
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return rpc_error(StatusCode::BAD_REQUEST, "invalid webhook payload"),
    };
    let action = payload.get("action").and_then(|a| a.as_str()).unwrap_or("");

    match (event, action) {
        ("installation", "suspend") | ("installation", "deleted") => {
            let Some((id, login)) = installation_ref(&payload) else {
                return rpc_error(
                    StatusCode::BAD_REQUEST,
                    "installation event missing installation.id",
                );
            };
            let (evicted, single_hit, owners) =
                invalidate_installation(&state, id, login.as_deref());
            let killed = kill_pinned_sessions(&state, single_hit, &owners).await;
            tracing::info!(
                "webhook: installation {} {} — evicted {} cached token(s), killed {} pinned session(s)",
                id,
                action,
                evicted,
                killed
            );
            respond(serde_json::json!({
                "ok": true,
                "evicted_tokens": evicted,
                "killed_sessions": killed,
            }))
        }
        ("installation_repositories", "removed") => {
            let Some((id, login)) = installation_ref(&payload) else {
                return rpc_error(
                    StatusCode::BAD_REQUEST,
                    "installation_repositories event missing installation.id",
                );
            };
            let repos = removed_repo_names(&payload);
            let evicted = invalidate_intersecting(&state, id, login.as_deref(), &repos);
            tracing::info!(
                "webhook: installation {} lost {} repositor(ies) — evicted {} cached token(s)",
                id,
                repos.len(),
                evicted
            );
            respond(serde_json::json!({"ok": true, "evicted_tokens": evicted}))
        }
        ("github_app_authorization", "revoked") => {
            let (evicted, killed) = invalidate_everything(&state).await;
            tracing::info!(
                "webhook: app authorization revoked — evicted {} cached token(s), killed {} pinned session(s)",
                evicted,
                killed
            );
            respond(serde_json::json!({
                "ok": true,
                "evicted_tokens": evicted,
                "killed_sessions": killed,
            }))
        }
        _ => respond(serde_json::json!({"ok": true, "ignored": event})),
    }
}

/// `sha256=` + 64 hex chars, verified in constant time against the raw body.
/// Anything structurally off — missing header, wrong scheme, wrong length —
/// fails closed.
fn signature_valid(secret: &str, headers: &HeaderMap, body: &[u8]) -> bool {
    let Some(sig) = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("sha256="))
    else {
        return false;
    };
    if sig.len() != 64 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let expected: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&sig[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    ring::hmac::verify(&key, body, &expected).is_ok()
}

fn respond(body: Value) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("static webhook response")
}

/// The (installation id, account login) a payload targets. `login` is only
/// a fallback signal — providers that know their installation id match on
/// id alone (an account may host many Apps' installations).
fn installation_ref(payload: &Value) -> Option<(u64, Option<String>)> {
    let inst = payload.get("installation")?;
    let id = inst.get("id")?.as_u64()?;
    let login = inst
        .get("account")
        .and_then(|a| a.get("login"))
        .and_then(|l| l.as_str())
        .map(str::to_string);
    Some((id, login))
}

fn removed_repo_names(payload: &Value) -> Vec<String> {
    payload
        .get("repositories_removed")
        .and_then(|r| r.as_array())
        .map(|repos| {
            repos
                .iter()
                .filter_map(|r| {
                    // `name` is canonical; fall back to the repo segment of
                    // `full_name` for payload variants that omit it.
                    r.get("name")
                        .and_then(|n| n.as_str())
                        .or_else(|| {
                            r.get("full_name").and_then(|f| f.as_str()).and_then(|f| {
                                f.split_once('/')
                                    .map(|(_, name)| name)
                                    .filter(|n| !n.is_empty())
                            })
                        })
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Drop the token caches of every provider serving the named installation.
/// Returns (entries evicted, single-app provider matched, affected owners).
fn invalidate_installation(
    state: &AppState,
    installation_id: u64,
    account_login: Option<&str>,
) -> (usize, bool, HashSet<String>) {
    let mut evicted = 0;
    let mut single_hit = false;
    if let Some(provider) = state
        .app_tokens
        .as_ref()
        .filter(|p| p.serves_installation(installation_id, account_login))
    {
        single_hit = true;
        evicted += provider.invalidate_all();
    }
    let mut owners = HashSet::new();
    if let Some(multi) = &state.multi_app_tokens {
        for owner in multi.serving_owners(installation_id, account_login) {
            if let Some(provider) = multi.get(&owner) {
                evicted += provider.invalidate_all();
            }
            owners.insert(owner);
        }
    }
    (evicted, single_hit, owners)
}

/// `installation_repositories.removed`: drop cached tokens whose repo scope
/// intersects the removed repositories, on the serving provider(s) only.
fn invalidate_intersecting(
    state: &AppState,
    installation_id: u64,
    account_login: Option<&str>,
    repos: &[String],
) -> usize {
    let mut evicted = 0;
    if let Some(provider) = state
        .app_tokens
        .as_ref()
        .filter(|p| p.serves_installation(installation_id, account_login))
    {
        evicted += provider.invalidate_repos(repos);
    }
    if let Some(multi) = &state.multi_app_tokens {
        for owner in multi.serving_owners(installation_id, account_login) {
            if let Some(provider) = multi.get(&owner) {
                evicted += provider.invalidate_repos(repos);
            }
        }
    }
    evicted
}

/// `github_app_authorization.revoked`: the event names no installation, so
/// every configured App gets the full treatment — all caches dropped, all
/// App-pinned sessions killed.
async fn invalidate_everything(state: &AppState) -> (usize, usize) {
    let mut evicted = state
        .app_tokens
        .as_ref()
        .map(|p| p.invalidate_all())
        .unwrap_or(0);
    let owners: HashSet<String> = state
        .multi_app_tokens
        .as_ref()
        .map(|m| m.owners().cloned().collect())
        .unwrap_or_default();
    if let Some(multi) = &state.multi_app_tokens {
        for owner in &owners {
            if let Some(provider) = multi.get(owner) {
                evicted += provider.invalidate_all();
            }
        }
    }
    // Single mode: every App pin was minted by the one provider.
    // Multi mode: every MultiApp pin routes through a dead installation.
    let killed = kill_pinned_sessions(state, state.app_tokens.is_some(), &owners).await;
    (evicted, killed)
}

/// Drop session pins whose credentials came from an affected installation.
/// `single_hit` = the single-App provider was invalidated, so every
/// App-pinned session dies (they were all minted by it — including pins on
/// rotated-out tokens the cache no longer holds). `owners` = multi
/// installations affected: a MultiApp pin dies when ANY of its routes is
/// dead, matching the whole-session expiry semantics. PAT-pinned sessions
/// are never App-minted and always survive.
async fn kill_pinned_sessions(
    state: &AppState,
    single_hit: bool,
    owners: &HashSet<String>,
) -> usize {
    if !single_hit && owners.is_empty() {
        return 0;
    }
    let mut killed = 0;
    // Sweep twice: the iterator is a snapshot, so a pin inserted between the
    // first scan and the invalidates could otherwise survive with a dead
    // credential. A second pass closes the window to microseconds.
    for _ in 0..2 {
        let doomed: Vec<String> = state
            .mcp_sessions
            .iter()
            .filter(|(_, pin)| match &pin.cred {
                PinnedCred::Pat { .. } => false,
                PinnedCred::App { .. } => single_hit,
                PinnedCred::MultiApp { routes, .. } => routes.keys().any(|o| owners.contains(o)),
            })
            .map(|(sid, _)| sid.as_ref().clone())
            .collect();
        if doomed.is_empty() {
            break;
        }
        killed += doomed.len();
        for sid in &doomed {
            state.mcp_sessions.invalidate(sid.as_str()).await;
        }
    }
    killed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_sig(sig: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-hub-signature-256", sig.parse().unwrap());
        h
    }

    #[test]
    fn test_signature_valid() {
        // RFC 4231-flavored: HMAC-SHA256 of a known body under a known key.
        let body = b"hello";
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"secret");
        let tag = ring::hmac::sign(&key, body);
        let hex: String = tag.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
        let h = headers_with_sig(&format!("sha256={}", hex));
        assert!(signature_valid("secret", &h, body));
        assert!(!signature_valid("wrong-secret", &h, body));
        assert!(!signature_valid("secret", &h, b"tampered"));

        // Malformed signatures never reach HMAC comparison.
        for bad in [
            "sha1=88d8499095f29f23a6503b8a2d1a1047a7ae1ea0",
            "sha256=xyz",
            "sha256=88d8499095f29f23a6503b8a2d1a1047a7ae1ea0", // right length? no: 40 chars
            "88d8499095f29f23a6503b8a2d1a1047a7ae1ea0aabbccddeeff00112233445566778899aabb",
            "",
        ] {
            assert!(
                !signature_valid("secret", &headers_with_sig(bad), body),
                "sig {}",
                bad
            );
        }
        // Missing header entirely.
        assert!(!signature_valid("secret", &HeaderMap::new(), body));
    }

    #[test]
    fn test_installation_ref() {
        let p = serde_json::json!({"installation": {"id": 42, "account": {"login": "OpenAb"}}});
        assert_eq!(installation_ref(&p), Some((42, Some("OpenAb".into()))));
        let p = serde_json::json!({"installation": {"id": 7}});
        assert_eq!(installation_ref(&p), Some((7, None)));
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"installation": {}}),
            serde_json::json!({"installation": {"id": "x"}}),
        ] {
            assert_eq!(installation_ref(&bad), None);
        }
    }

    #[test]
    fn test_removed_repo_names() {
        let p = serde_json::json!({
            "repositories_removed": [
                {"name": "openab", "full_name": "openabdev/openab"},
                {"name": "chi"},
                {"full_name": "no/name"},   // falls back to the repo segment
                {"full_name": "noslash"},   // not owner/repo — skipped
                {"id": 123}                  // no name at all — skipped
            ]
        });
        assert_eq!(removed_repo_names(&p), vec!["openab", "chi", "name"]);
        assert_eq!(
            removed_repo_names(&serde_json::json!({})),
            Vec::<String>::new()
        );
    }
}
