//! Secretless agent authentication via AWS SigV4 (Phase 3, #18).
//!
//! `POST /mcp/iam-auth` exchanges a signed `sts:GetCallerIdentity` request
//! for a short-lived `X-Octobroker-Iam-Token` — the Vault AWS-auth pattern.
//! The agent proves control of an ambient IAM credential (ECS task role,
//! EKS IRSA, instance profile) without ever holding a GitHub token or a
//! static octobroker key.
//!
//! The signed request is submitted as its four wire components
//! (`iam_request_method`, `iam_request_url`, `iam_request_headers`,
//! `iam_request_body`). Validation is fail-closed:
//!
//! 1. method must be POST — a signature for a different method is a
//!    different proof;
//! 2. URL must be exactly an allowlisted STS endpoint
//!    (`scheme://authority`, path `/` or empty, no query — presigned-URL
//!    `X-Amz-Signature` forms are rejected);
//! 3. `authorization` must be `AWS4-HMAC-SHA256` with a `sts/aws4_request`
//!    scope whose region matches the endpoint host;
//! 4. `SignedHeaders` must include `host`, `x-amz-date` and
//!    `x-octobroker-server-id` — the freshness timestamp and the
//!    deployment-binding server id must be covered by the signature — and
//!    must be a subset of the forwardable header allowlist;
//! 5. `x-octobroker-server-id` must equal the configured `server_id`
//!    (prevents replaying a proof minted for another deployment);
//! 6. `x-amz-date` must be within `max_proof_age_secs` (≤60s) of now —
//!    limits the replay window;
//! 7. body must be exactly `Action=GetCallerIdentity` + `Version=2011-06-15`;
//! 8. the request is replayed verbatim (allowlisted signed headers only)
//!    to the STS endpoint over TLS — **STS itself is the signature oracle**;
//! 9. the returned ARN must match an agent's `iam_arns` entry (exact, or
//!    trailing-`*` prefix).
//!
//! A success mints a random 256-bit token (`iam_tokens` cache, TTL =
//! `token_ttl_secs`) which `authenticate()` accepts on `/mcp` and
//! `/git-credential` via `X-Octobroker-Iam-Token`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::StatusCode,
    response::{Json, Response},
};
use serde::Deserialize;

use crate::config::{IamConfig, McpAgentConfig};
use crate::mcp::rpc_error;
use crate::AppState;

/// Issued IAM credential: maps an opaque token to an agent, expiring at
/// `expires_at` (unix seconds). Stored in `AppState.iam_tokens`.
#[derive(Clone, Debug)]
pub struct IamSession {
    pub agent_id: String,
    pub expires_at: u64,
}

/// Headers we will forward to STS verbatim — and the ONLY headers a signed
/// proof may cover. Anything signed outside this set cannot be faithfully
/// replayed, so the proof is rejected.
const FORWARDABLE_HEADERS: &[&str] = &[
    "host",
    "content-type",
    "x-amz-date",
    "x-amz-security-token",
    "x-octobroker-server-id",
];

/// The deployment-binding header — must be present, correct, AND signed.
pub const SERVER_ID_HEADER: &str = "x-octobroker-server-id";

/// The header agents use to present an exchanged token.
pub const IAM_TOKEN_HEADER: &str = "x-octobroker-iam-token";

const STS_CALL_TIMEOUT_SECS: u64 = 15;
/// GetCallerIdentity responses are ~500 bytes; anything bigger is junk.
const STS_MAX_BODY: usize = 64 * 1024;

#[derive(Deserialize)]
pub struct IamAuthRequest {
    pub iam_request_method: String,
    pub iam_request_url: String,
    /// Header map (lowercase names) of the signed request.
    pub iam_request_headers: HashMap<String, String>,
    pub iam_request_body: String,
}

struct ValidatedProof {
    /// Exact URL the signed request is replayed to.
    url: String,
    /// Lowercase-name header map to forward (only signed + allowlisted).
    headers: Vec<(String, String)>,
    body: String,
    /// The hex signature — fingerprint used for replay suppression.
    signature: String,
}

/// Global ceiling on iam-auth exchange attempts/minute — the endpoint is
/// unauthenticated and each attempt that passes validation costs an STS
/// round-trip, so it gets its own tight budget.
const IAM_AUTH_RATE_PER_MIN: u32 = 30;
const IAM_AUTH_BUCKET: &str = "__iam_auth";

pub async fn iam_auth(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IamAuthRequest>,
) -> Response {
    let Some(iam) = state.config.mcp.iam.as_ref().filter(|i| i.enabled) else {
        return rpc_error(StatusCode::NOT_FOUND, "iam auth is not enabled");
    };
    if let Err(retry_after) = state
        .rate_limiter
        .check(IAM_AUTH_BUCKET, IAM_AUTH_RATE_PER_MIN)
    {
        return crate::mcp::rpc_error_retry_after(
            StatusCode::TOO_MANY_REQUESTS,
            "iam-auth rate limit exceeded",
            retry_after,
        );
    }
    match exchange(&state, iam, req).await {
        Ok((agent, arn)) => {
            let (token, expires_at) = issue_token(&state, &agent.id, iam.token_ttl_secs).await;
            state.mcp_metrics.record_iam_auth(true);
            tracing::info!("MCP iam-auth: {} → agent {}", redact_arn(&arn), agent.id);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("cache-control", "no-store")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "token": token,
                        "token_type": IAM_TOKEN_HEADER,
                        "agent": agent.id,
                        "expires_at": expires_at,
                    })
                    .to_string(),
                ))
                .unwrap_or_else(|_| {
                    rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "response build failed")
                })
        }
        Err((status, msg)) => {
            state.mcp_metrics.record_iam_auth(false);
            tracing::warn!("MCP iam-auth rejected: {}", msg);
            rpc_error(status, msg)
        }
    }
}

async fn exchange<'a>(
    state: &'a AppState,
    iam: &IamConfig,
    req: IamAuthRequest,
) -> Result<(&'a McpAgentConfig, String), (StatusCode, &'static str)> {
    let proof = validate_proof(iam, &req)?;

    // Replay suppression: reject a signature that already completed an
    // exchange. Deliberately checked-but-not-marked here and marked only
    // after the STS round-trip + ARN map succeed — SigV4 signatures are
    // deterministic, so a legit retry within the same second produces an
    // identical signature and must not be permanently poisoned by a
    // transient STS failure.
    if state.iam_proofs.get(&proof.signature).await.is_some() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "this proof has already been exchanged",
        ));
    }

    let mut fwd = state.http.post(&proof.url).body(proof.body.clone());
    for (name, value) in &proof.headers {
        if name == "host" {
            continue; // reqwest derives Host from the URL
        }
        let Ok(v) = value.parse::<axum::http::HeaderValue>() else {
            return Err((
                StatusCode::BAD_REQUEST,
                "header value is not a valid header",
            ));
        };
        fwd = fwd.header(name.as_str(), v);
    }
    let resp = fwd
        .timeout(std::time::Duration::from_secs(STS_CALL_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "sts endpoint unreachable"))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "sts response unreadable"))?;
    if bytes.len() > STS_MAX_BODY {
        return Err((StatusCode::BAD_GATEWAY, "sts response too large"));
    }
    let body = String::from_utf8_lossy(&bytes);
    if !status.is_success() {
        // STS rejected the signature/proof — the caller's credential is bad.
        return Err((StatusCode::UNAUTHORIZED, "sigv4 proof rejected by STS"));
    }
    let arn = parse_arn(&body).ok_or((StatusCode::BAD_GATEWAY, "sts response missing Arn"))?;
    let agent = agent_for_arn(state, &arn)
        .ok_or((StatusCode::FORBIDDEN, "arn is not mapped to any agent"))?;
    state.iam_proofs.insert(proof.signature, ()).await;
    Ok((agent, arn))
}

/// All fail-closed checks that run BEFORE any network I/O to STS.
fn validate_proof(
    iam: &IamConfig,
    req: &IamAuthRequest,
) -> Result<ValidatedProof, (StatusCode, &'static str)> {
    // 1. method
    if req.iam_request_method != "POST" {
        return Err((StatusCode::BAD_REQUEST, "iam_request_method must be POST"));
    }

    // 2. URL — must be exactly an allowlisted STS endpoint.
    let url = req.iam_request_url.trim_end_matches('/');
    let allow_hit = iam
        .sts_endpoints
        .iter()
        .any(|ep| ep.trim().trim_end_matches('/') == url);
    if !allow_hit {
        return Err((
            StatusCode::FORBIDDEN,
            "iam_request_url is not an allowlisted STS endpoint",
        ));
    }
    let scheme_part = url.split_once("://").map(|(s, _)| s).unwrap_or("");
    if !matches!(scheme_part, "https" | "http") {
        return Err((StatusCode::BAD_REQUEST, "iam_request_url must be http(s)"));
    }
    let authority = url.split_once("://").map(|(_, a)| a).unwrap_or("");
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.contains(char::is_whitespace)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "iam_request_url has a malformed authority",
        ));
    }
    // No query string — rules out presigned-URL (X-Amz-Signature) proofs.
    if req.iam_request_url.contains('?') {
        return Err((
            StatusCode::BAD_REQUEST,
            "presigned-URL proofs are not accepted",
        ));
    }

    let headers: HashMap<String, String> = req
        .iam_request_headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.trim().to_string()))
        .collect();

    // 3. Authorization: AWS4-HMAC-SHA256 with an sts/aws4_request scope.
    let authz = headers
        .get("authorization")
        .ok_or((StatusCode::BAD_REQUEST, "missing authorization header"))?;
    let Some(cred) = parse_sigv4_authorization(authz) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "malformed SigV4 authorization header",
        ));
    };
    // Credential scope: <ak>/<yyyymmdd>/<region>/<service>/aws4_request
    let scope_parts: Vec<&str> = cred.credential.split('/').collect();
    if scope_parts.len() != 5 || scope_parts[3] != "sts" || scope_parts[4] != "aws4_request" {
        return Err((
            StatusCode::BAD_REQUEST,
            "authorization credential scope must be …/region/sts/aws4_request",
        ));
    }
    let scope_region = scope_parts[2];
    if scope_parts[0].is_empty()
        || !scope_parts[0].bytes().all(|b| b.is_ascii_alphanumeric())
        || scope_parts[0].len() < 8
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "authorization credential key id malformed",
        ));
    }
    // Region must match the endpoint host for amazonaws targets.
    if let Some(expected) = sts_region_for_host(authority) {
        if scope_region != expected {
            return Err((
                StatusCode::BAD_REQUEST,
                "credential scope region does not match the STS endpoint",
            ));
        }
    }
    if cred.signature.is_empty()
        || cred.signature.len() != 64
        || !cred.signature.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err((StatusCode::BAD_REQUEST, "signature malformed"));
    }

    // 4. SignedHeaders — must cover host, x-amz-date, the server-id header,
    //    and nothing outside the forwardable allowlist.
    let signed: Vec<String> = cred
        .signed_headers
        .split(';')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    for required in ["host", "x-amz-date", SERVER_ID_HEADER] {
        if !signed.iter().any(|s| s == required) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "signed headers must cover host, x-amz-date and x-octobroker-server-id",
            ));
        }
    }
    for s in &signed {
        if !FORWARDABLE_HEADERS.contains(&s.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                "signed headers contain a header outside the allowed set",
            ));
        }
    }
    // Every signed header must be present in the submitted map.
    for s in &signed {
        if !headers.contains_key(s.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                "a signed header is missing from the request",
            ));
        }
    }
    if let Some(host) = headers.get("host") {
        if host != authority {
            return Err((
                StatusCode::BAD_REQUEST,
                "host header does not match the URL",
            ));
        }
    }

    // 5. Deployment binding: the server-id value must match ours.
    let Some(signed_server_id) = headers.get(SERVER_ID_HEADER) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing x-octobroker-server-id header",
        ));
    };
    if signed_server_id != &iam.server_id {
        return Err((
            StatusCode::UNAUTHORIZED,
            "proof was signed for a different server id",
        ));
    }

    // 6. Freshness: X-Amz-Date within the configured window (≤60s). Its
    //    yyyymmdd must also equal the credential-scope date (defense in
    //    depth — STS rejects the mismatch anyway).
    let amz_date = headers
        .get("x-amz-date")
        .ok_or((StatusCode::BAD_REQUEST, "missing x-amz-date"))?;
    let Some(ts) = parse_amz_date(amz_date) else {
        return Err((StatusCode::BAD_REQUEST, "malformed x-amz-date"));
    };
    if amz_date.len() < 8 || &amz_date[..8] != scope_parts[1] {
        return Err((
            StatusCode::BAD_REQUEST,
            "x-amz-date does not match the credential scope date",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let skew = now.abs_diff(ts);
    if skew > iam.max_proof_age_secs {
        return Err((
            StatusCode::UNAUTHORIZED,
            "proof is stale (outside the validity window)",
        ));
    }

    // 7. Body: exactly Action=GetCallerIdentity&Version=2011-06-15.
    let params: HashMap<String, String> = req
        .iam_request_body
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if params.len() != 2
        || params.get("Action").map(String::as_str) != Some("GetCallerIdentity")
        || params.get("Version").map(String::as_str) != Some("2011-06-15")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "body must be exactly a GetCallerIdentity call",
        ));
    }

    Ok(ValidatedProof {
        url: req.iam_request_url.clone(),
        signature: cred.signature.to_string(),
        // Forward the signed headers (STS recomputes the signature over
        // them) plus `authorization` itself — it carries the signature
        // material and is never part of SignedHeaders.
        headers: std::iter::once(("authorization".to_string(), authz.clone()))
            .chain(
                signed
                    .iter()
                    .map(|s| (s.clone(), headers.get(s).cloned().unwrap_or_default())),
            )
            .collect(),
        body: req.iam_request_body.clone(),
    })
}

struct SigV4Auth<'a> {
    credential: &'a str,
    signed_headers: &'a str,
    signature: &'a str,
}

/// Parse `AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…`.
fn parse_sigv4_authorization(value: &str) -> Option<SigV4Auth<'_>> {
    let rest = value.strip_prefix("AWS4-HMAC-SHA256")?.trim_start();
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for kv in rest.split(',') {
        let (k, v) = kv.trim().split_once('=')?;
        match k {
            "Credential" => credential = Some(v),
            "SignedHeaders" => signed_headers = Some(v),
            "Signature" => signature = Some(v),
            _ => return None,
        }
    }
    Some(SigV4Auth {
        credential: credential?,
        signed_headers: signed_headers?,
        signature: signature?,
    })
}

/// Expected signing region for amazonaws STS hosts; None for anything else
/// (non-AWS hosts are reachable only via an explicit operator allowlist, so
/// the credential scope region is unconstrained there).
fn sts_region_for_host(authority: &str) -> Option<&str> {
    let host = authority.split(':').next()?;
    if host == "sts.amazonaws.com" {
        return Some("us-east-1");
    }
    host.strip_prefix("sts.")
        .and_then(|h| h.strip_suffix(".amazonaws.com"))
        .filter(|r| !r.is_empty() && !r.contains('.'))
}

/// `YYYYMMDD'T'HHMMSS'Z'` → unix seconds. Hand-rolled: the format is fixed
/// width and we only need epoch arithmetic.
fn parse_amz_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { s[from..to].parse::<i64>().ok() };
    let (y, mo, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (h, mi, sec) = (num(9, 11)?, num(11, 13)?, num(13, 15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // days-from-civil (Howard Hinnant) — no time crate needed for UTC math.
    let y_adj = if mo <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + sec) as u64)
}

/// Extract `<Arn>` from a GetCallerIdentityResponse document — anchored on
/// the result element so a stuffed earlier `<Arn>` can't win.
fn parse_arn(xml: &str) -> Option<String> {
    let result_start = xml.find("<GetCallerIdentityResult")?;
    let rest = &xml[result_start..];
    let start = rest.find("<Arn>")? + 5;
    let end = rest[start..].find("</Arn>")? + start;
    let arn = rest[start..end].trim();
    if arn.starts_with("arn:") {
        Some(arn.to_string())
    } else {
        None
    }
}

/// Map an STS-reported ARN to an agent: exact match, or a trailing-`*`
/// prefix match (temporary credentials return `assumed-role/<role>/<session>`
/// ARNs whose session suffix cannot be enumerated).
fn agent_for_arn<'a>(state: &'a AppState, arn: &str) -> Option<&'a McpAgentConfig> {
    state.config.mcp.agents.iter().find(|a| {
        a.iam_arns.iter().any(|entry| {
            if let Some(prefix) = entry.strip_suffix('*') {
                arn.starts_with(prefix)
            } else {
                arn == entry
            }
        })
    })
}

/// Mint the opaque bearer token: 256 bits from /dev/urandom, hex-encoded.
/// The token's *value* is never logged.
async fn issue_token(state: &AppState, agent_id: &str, ttl_secs: u64) -> (String, u64) {
    let bytes = {
        use std::io::Read;
        let mut buf = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .map(|_| buf.to_vec())
    }
    .unwrap_or_else(|_| {
        // Fallback for non-Linux dev machines: hash of nanos+pid.
        // Still unguessable in practice; /dev/urandom is the real path.
        use sha2::{Digest, Sha256};
        let seed = format!("{}:{}:{}", std::process::id(), now_nanos(), agent_id);
        Sha256::digest(seed.as_bytes()).to_vec()
    });
    let token = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        + ttl_secs;
    state
        .iam_tokens
        .insert(
            token.clone(),
            IamSession {
                agent_id: agent_id.to_string(),
                expires_at,
            },
        )
        .await;
    (token, expires_at)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Resolve an `X-Octobroker-Iam-Token` value to its agent. The token's own
/// expiry is authoritative (cache eviction is a secondary bound).
pub async fn resolve_iam_token<'a>(state: &'a AppState, token: &str) -> Option<&'a McpAgentConfig> {
    let sess = state.iam_tokens.get(token).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if sess.expires_at <= now {
        state.iam_tokens.invalidate(token).await;
        return None;
    }
    state
        .config
        .mcp
        .agents
        .iter()
        .find(|a| a.id == sess.agent_id)
}

/// Log-safe ARN prefix: principal type + account + role name. For
/// `assumed-role/<role>/<session>` ARNs the session suffix (least stable,
/// most identifying) is dropped, not the role.
fn redact_arn(arn: &str) -> String {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() >= 6 {
        let resource = parts[5];
        // assumed-role/ROLE/SESSION → ROLE; role/NAME or user/NAME → NAME
        let ident = if let Some(rest) = resource.strip_prefix("assumed-role/") {
            rest.split('/').next().unwrap_or(rest)
        } else {
            resource.rsplit('/').next().unwrap_or(resource)
        };
        format!("{}:{}:…/{}", parts[1], parts[4], ident)
    } else {
        "arn".to_string()
    }
}
