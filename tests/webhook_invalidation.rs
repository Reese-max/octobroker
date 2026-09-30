//! Webhook-driven credential invalidation (`POST /webhooks/github`, #50).
//!
//! End-to-end over the real route table: HMAC-SHA256 signature verification
//! (fail-closed), event dispatch, App token cache drops (MCP + git), and
//! pinned-session termination for the affected installation.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use octobroker::app_token::{AppTokenProvider, MultiAppTokenProvider};
use octobroker::mcp::{AppRoute, PinnedCred, SessionPin};
use octobroker::{base_router, cache, config, pool, AppState};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const PEM: &str = include_str!("../testdata/test-app-key.pem");
const SECRET: &str = "whsec-unit-test-only";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn rfc3339_in(secs: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp((unix_now() + secs) as i64)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// Mock GitHub App API: counts mint calls globally and mints a distinct
/// token per call so a re-mint is always observable.
type MintCount = Arc<AtomicU64>;

async fn spawn_mint_api() -> (String, MintCount) {
    use axum::{extract::State, routing::post, Json, Router};

    async fn mint(State(n): State<MintCount>) -> Json<Value> {
        let n = n.fetch_add(1, Ordering::SeqCst) + 1;
        Json(json!({"token": format!("ghs_mint_{}", n), "expires_at": rfc3339_in(3600)}))
    }

    let count: MintCount = Arc::new(AtomicU64::new(0));
    let app = Router::new()
        .route("/app/installations/{id}/access_tokens", post(mint))
        .with_state(count.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{}", addr), count)
}

fn mints(count: &MintCount) -> u64 {
    count.load(Ordering::SeqCst)
}

/// X-Hub-Signature-256 as GitHub sends it: "sha256=" + hex(HMAC-SHA256).
fn sign(secret: &str, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let tag = ring::hmac::sign(&key, body);
    let hex: String = tag.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
    format!("sha256={}", hex)
}

fn webhook_req(event: &str, payload: &Value, signature: Option<&str>) -> Request<Body> {
    let body = payload.to_string();
    let mut b = Request::builder()
        .method("POST")
        .uri("/webhooks/github")
        .header("content-type", "application/json")
        .header("x-github-event", event);
    if let Some(sig) = signature {
        b = b.header("x-hub-signature-256", sig);
    }
    b.body(Body::from(body)).unwrap()
}

fn signed_req(event: &str, payload: &Value) -> Request<Body> {
    webhook_req(
        event,
        payload,
        Some(&sign(SECRET, payload.to_string().as_bytes())),
    )
}

fn base_config(secret: Option<&str>) -> config::Config {
    config::Config {
        port: 8080,
        identities: vec![],
        allowed_owners: vec![],
        cache: config::CacheConfig::default(),
        mcp: config::McpConfig::default(),
        webhooks: config::WebhooksConfig {
            github_secret: secret.map(str::to_string),
        },
    }
}

fn state(
    cfg: config::Config,
    app_tokens: Option<AppTokenProvider>,
    multi_app_tokens: Option<MultiAppTokenProvider>,
) -> Arc<AppState> {
    Arc::new(AppState {
        pool: pool::PatPool::new(&[]),
        cache: cache::Cache::new(&config::CacheConfig::default()),
        config: cfg,
        token_users: moka::future::Cache::builder().max_capacity(10).build(),
        http: reqwest::Client::new(),
        mcp_sessions: moka::future::Cache::builder().max_capacity(10).build(),
        app_tokens,
        multi_app_tokens,
        audit: None,
        write_inflight: Arc::new(Mutex::new(HashMap::new())),
    })
}

fn single_state(secret: Option<&str>, api_base: &str) -> Arc<AppState> {
    let provider = AppTokenProvider::new(
        "123".into(),
        PEM,
        Some(42),
        Some("openabdev".into()),
        api_base.into(),
    )
    .unwrap();
    state(base_config(secret), Some(provider), None)
}

fn multi_state(secret: Option<&str>, api_base: &str) -> Arc<AppState> {
    let entries = vec![
        config::GithubAppsEntry {
            app_id: "111".into(),
            private_key: PEM.into(),
            installation_id: Some(41),
            owner: "openabdev".into(),
        },
        config::GithubAppsEntry {
            app_id: "222".into(),
            private_key: PEM.into(),
            installation_id: Some(42),
            owner: "oablab".into(),
        },
    ];
    let multi = MultiAppTokenProvider::new(&entries, api_base.into()).unwrap();
    state(base_config(secret), None, Some(multi))
}

fn pin_app(token: &str) -> SessionPin {
    SessionPin {
        agent_id: Some("b0".into()),
        cred: PinnedCred::App {
            token: token.into(),
            expires_at: unix_now() + 3600,
        },
    }
}

fn pin_pat(identity: &str) -> SessionPin {
    SessionPin {
        agent_id: Some("b0".into()),
        cred: PinnedCred::Pat {
            identity_id: identity.into(),
        },
    }
}

fn pin_multi(owners: &[&str]) -> SessionPin {
    let routes: HashMap<String, AppRoute> = owners
        .iter()
        .map(|o| {
            (
                o.to_string(),
                AppRoute {
                    token: format!("ghs_{}", o),
                    expires_at: unix_now() + 3600,
                    upstream_session: Some(format!("us-{}", o)),
                },
            )
        })
        .collect();
    SessionPin {
        agent_id: Some("b0".into()),
        cred: PinnedCred::MultiApp {
            routes,
            primary: owners[0].into(),
        },
    }
}

/// installation.suspend/deleted drops that installation's token cache and
/// kills its pinned App sessions — PAT-pinned sessions are unrelated and
/// must survive.
#[tokio::test]
async fn test_installation_suspend_drops_cache_and_kills_sessions() {
    let (api, mint) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let provider = state.app_tokens.as_ref().unwrap();

    let first = provider.token_scoped(&["openab".into()]).await.unwrap();
    assert_eq!(mints(&mint), 1);

    state
        .mcp_sessions
        .insert("sess-app".into(), pin_app(&first.token))
        .await;
    state
        .mcp_sessions
        .insert("sess-pat".into(), pin_pat("alice"))
        .await;

    let payload = json!({
        "action": "suspend",
        "installation": {"id": 42, "account": {"login": "openabdev"}},
        "repositories": [{"name": "openab"}]
    });
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(signed_req("installation", &payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Cache dropped: the next lookup re-mints instead of hitting the cache.
    let second = provider.token_scoped(&["openab".into()]).await.unwrap();
    assert_eq!(mints(&mint), 2);
    assert_ne!(first.token, second.token);

    // The pinned App session is dead; the PAT session survives.
    assert!(state.mcp_sessions.get("sess-app").await.is_none());
    assert!(state.mcp_sessions.get("sess-pat").await.is_some());
}

/// `deleted` gets the same treatment as `suspend`.
#[tokio::test]
async fn test_installation_deleted_same_treatment() {
    let (api, mint) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let provider = state.app_tokens.as_ref().unwrap();

    provider.token_git("openab", false).await.unwrap();
    state
        .mcp_sessions
        .insert("sess-app".into(), pin_app("ghs_x"))
        .await;

    let payload = json!({
        "action": "deleted",
        "installation": {"id": 42, "account": {"login": "openabdev"}}
    });
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(signed_req("installation", &payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // git-purpose cache entries are dropped too, not just MCP.
    provider.token_git("openab", false).await.unwrap();
    assert_eq!(mints(&mint), 2);
    assert!(state.mcp_sessions.get("sess-app").await.is_none());
}

/// Fail-closed: a missing or wrong signature rejects the request and
/// invalidates nothing.
#[tokio::test]
async fn test_invalid_or_missing_signature_rejects_and_changes_nothing() {
    let (api, mint) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let provider = state.app_tokens.as_ref().unwrap();

    let first = provider.token_scoped(&["openab".into()]).await.unwrap();
    state
        .mcp_sessions
        .insert("sess-app".into(), pin_app(&first.token))
        .await;

    let payload = json!({
        "action": "suspend",
        "installation": {"id": 42, "account": {"login": "openabdev"}}
    });

    // Wrong signature.
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(webhook_req(
            "installation",
            &payload,
            Some("sha256=deadbeef"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Signature over a DIFFERENT body (tampering).
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(webhook_req(
            "installation",
            &payload,
            Some(&sign(SECRET, b"{\"action\":\"created\"}")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // No signature at all.
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(webhook_req("installation", &payload, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Nothing was invalidated.
    let again = provider.token_scoped(&["openab".into()]).await.unwrap();
    assert_eq!(mints(&mint), 1, "rejected webhooks must not drop the cache");
    assert_eq!(first.token, again.token);
    assert!(state.mcp_sessions.get("sess-app").await.is_some());
}

/// installation_repositories.removed drops only the cached tokens whose
/// repo scope intersects the removed repositories (sessions are untouched:
/// their token stays valid for whatever it still covers).
#[tokio::test]
async fn test_repos_removed_drops_intersecting_tokens_only() {
    let (api, mint) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let provider = state.app_tokens.as_ref().unwrap();

    let openab = provider.token_scoped(&["openab".into()]).await.unwrap();
    let chi = provider.token_scoped(&["chi".into()]).await.unwrap();
    assert_eq!(mints(&mint), 2);
    state
        .mcp_sessions
        .insert("sess-app".into(), pin_app(&openab.token))
        .await;

    let payload = json!({
        "action": "removed",
        "installation": {"id": 42, "account": {"login": "openabdev"}},
        "repositories_removed": [{"name": "openab", "full_name": "openabdev/openab"}],
        "repositories_added": []
    });
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(signed_req("installation_repositories", &payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Intersecting envelope re-mints; untouched envelope still hits cache.
    let openab2 = provider.token_scoped(&["openab".into()]).await.unwrap();
    let chi2 = provider.token_scoped(&["chi".into()]).await.unwrap();
    assert_eq!(mints(&mint), 3);
    assert_ne!(openab.token, openab2.token);
    assert_eq!(chi.token, chi2.token);

    // Per spec, repo deselection does NOT kill pinned sessions.
    assert!(state.mcp_sessions.get("sess-app").await.is_some());
}

/// github_app_authorization.revoked carries no installation id: it drops
/// every configured App's cache and kills every App-pinned session
/// (multi mode shown here; the PAT pin survives).
#[tokio::test]
async fn test_authorization_revoked_drops_all_app_credentials() {
    let (api, mint) = spawn_mint_api().await;
    let state = multi_state(Some(SECRET), &api);
    let multi = state.multi_app_tokens.as_ref().unwrap();

    multi
        .get("openabdev")
        .unwrap()
        .token_scoped(&["openab".into()])
        .await
        .unwrap();
    multi
        .get("oablab")
        .unwrap()
        .token_scoped(&["chi".into()])
        .await
        .unwrap();
    assert_eq!(mints(&mint), 2);

    state
        .mcp_sessions
        .insert("sess-multi".into(), pin_multi(&["oablab", "openabdev"]))
        .await;
    state
        .mcp_sessions
        .insert("sess-pat".into(), pin_pat("alice"))
        .await;

    let payload = json!({
        "action": "revoked",
        "sender": {"login": "some-user"}
    });
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(signed_req("github_app_authorization", &payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Every provider's cache was dropped.
    multi
        .get("openabdev")
        .unwrap()
        .token_scoped(&["openab".into()])
        .await
        .unwrap();
    multi
        .get("oablab")
        .unwrap()
        .token_scoped(&["chi".into()])
        .await
        .unwrap();
    assert_eq!(mints(&mint), 4);

    assert!(state.mcp_sessions.get("sess-multi").await.is_none());
    assert!(state.mcp_sessions.get("sess-pat").await.is_some());
}

/// Multi mode, installation-scoped event: only the named installation's
/// provider is invalidated; the sibling keeps its cache and its sessions.
#[tokio::test]
async fn test_multi_mode_scopes_invalidation_to_named_installation() {
    let (api, mint) = spawn_mint_api().await;
    let state = multi_state(Some(SECRET), &api);
    let multi = state.multi_app_tokens.as_ref().unwrap();

    multi
        .get("openabdev")
        .unwrap()
        .token_scoped(&["openab".into()])
        .await
        .unwrap();
    let chi = multi
        .get("oablab")
        .unwrap()
        .token_scoped(&["chi".into()])
        .await
        .unwrap();
    state
        .mcp_sessions
        .insert("sess-both".into(), pin_multi(&["oablab", "openabdev"]))
        .await;
    state
        .mcp_sessions
        .insert("sess-oablab".into(), pin_multi(&["oablab"]))
        .await;

    let payload = json!({
        "action": "suspend",
        "installation": {"id": 41, "account": {"login": "openabdev"}}
    });
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(signed_req("installation", &payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // openabdev's cache dropped, oablab's untouched.
    multi
        .get("openabdev")
        .unwrap()
        .token_scoped(&["openab".into()])
        .await
        .unwrap();
    let chi2 = multi
        .get("oablab")
        .unwrap()
        .token_scoped(&["chi".into()])
        .await
        .unwrap();
    assert_eq!(mints(&mint), 3);
    assert_eq!(chi.token, chi2.token);

    // Sessions spanning the suspended installation die; a session bound
    // only to the surviving installation stays.
    assert!(state.mcp_sessions.get("sess-both").await.is_none());
    assert!(state.mcp_sessions.get("sess-oablab").await.is_some());
}

/// Events we do not handle are acknowledged (200) and invalidate nothing —
/// including real GitHub `ping` and non-destructive actions like
/// `installation.created`.
#[tokio::test]
async fn test_unhandled_events_are_ignored() {
    let (api, mint) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let provider = state.app_tokens.as_ref().unwrap();
    provider.token_scoped(&["openab".into()]).await.unwrap();

    for (event, payload) in [
        ("ping", json!({"zen": "Keep it real.", "hook": {"id": 1}})),
        (
            "installation",
            json!({"action": "created", "installation": {"id": 42, "account": {"login": "openabdev"}}}),
        ),
        ("issues", json!({"action": "opened"})),
    ] {
        let resp = base_router()
            .with_state(state.clone())
            .oneshot(signed_req(event, &payload))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "event {}", event);
    }
    assert_eq!(mints(&mint), 1, "ignored events must not drop the cache");
}

/// An installation event for an installation we do not serve is a no-op:
/// a suspend aimed at a different App's installation must not flush our cache.
#[tokio::test]
async fn test_event_for_other_installation_does_not_invalidate() {
    let (api, mint) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let provider = state.app_tokens.as_ref().unwrap();
    let first = provider.token_scoped(&["openab".into()]).await.unwrap();
    state
        .mcp_sessions
        .insert("sess-app".into(), pin_app(&first.token))
        .await;

    let payload = json!({
        "action": "suspend",
        "installation": {"id": 999, "account": {"login": "other-org"}}
    });
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(signed_req("installation", &payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let again = provider.token_scoped(&["openab".into()]).await.unwrap();
    assert_eq!(mints(&mint), 1);
    assert_eq!(first.token, again.token);
    assert!(state.mcp_sessions.get("sess-app").await.is_some());
}

/// An installation-wide token's scope covered every repo the installation
/// could see — including a just-removed one — so deselecting any repo
/// evicts it too (fail-closed over-invalidation).
#[tokio::test]
async fn test_repos_removed_evicts_installation_wide_tokens() {
    let (api, mint) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let provider = state.app_tokens.as_ref().unwrap();

    let wide = provider.token_scoped(&[]).await.unwrap();
    assert_eq!(mints(&mint), 1);

    let payload = json!({
        "action": "removed",
        "installation": {"id": 42, "account": {"login": "openabdev"}},
        "repositories_removed": [{"name": "anything", "full_name": "openabdev/anything"}]
    });
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(signed_req("installation_repositories", &payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let wide2 = provider.token_scoped(&[]).await.unwrap();
    assert_eq!(mints(&mint), 2);
    assert_ne!(wide.token, wide2.token);
}

/// github_app_authorization.revoked in SINGLE-app mode: cache + App pins
/// dropped, PAT pins survive.
#[tokio::test]
async fn test_authorization_revoked_single_app_mode() {
    let (api, mint) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let provider = state.app_tokens.as_ref().unwrap();
    provider.token_scoped(&["openab".into()]).await.unwrap();
    state
        .mcp_sessions
        .insert("sess-app".into(), pin_app("ghs_x"))
        .await;
    state
        .mcp_sessions
        .insert("sess-pat".into(), pin_pat("alice"))
        .await;

    let payload = json!({"action": "revoked", "sender": {"login": "someone"}});
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(signed_req("github_app_authorization", &payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    provider.token_scoped(&["openab".into()]).await.unwrap();
    assert_eq!(mints(&mint), 2, "cache must have been dropped");
    assert!(state.mcp_sessions.get("sess-app").await.is_none());
    assert!(state.mcp_sessions.get("sess-pat").await.is_some());
}

/// A mint that was in-flight when invalidation ran must not repopulate the
/// killed cache (generation-guarded insert).
#[tokio::test]
async fn test_mint_in_flight_does_not_repopulate_after_invalidation() {
    use axum::{extract::State as AxumState, routing::post, Json, Router};

    // Slow mint so invalidation lands mid-flight.
    async fn mint(AxumState(n): AxumState<MintCount>) -> Json<Value> {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let n = n.fetch_add(1, Ordering::SeqCst) + 1;
        Json(json!({"token": format!("ghs_slow_{}", n), "expires_at": rfc3339_in(3600)}))
    }
    let count: MintCount = Arc::new(AtomicU64::new(0));
    let app = Router::new()
        .route("/app/installations/{id}/access_tokens", post(mint))
        .with_state(count.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let api = format!("http://{}", addr);

    let provider = Arc::new(
        AppTokenProvider::new("123".into(), PEM, Some(42), Some("openabdev".into()), api).unwrap(),
    );

    let inflight = {
        let p = provider.clone();
        tokio::spawn(async move { p.token_scoped(&["openab".into()]).await })
    };
    // Let the mint get under way, then invalidate — mimicking a suspend
    // landing between the mint request and its response.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    provider.invalidate_all();
    // The caller still gets its token (GitHub answered), ...
    let t = inflight.await.unwrap().unwrap();
    assert_eq!(t.token, "ghs_slow_1");
    // ...but it must NOT be served from the cache afterwards.
    let t2 = provider.token_scoped(&["openab".into()]).await.unwrap();
    assert_eq!(mints(&count), 2, "killed cache must re-mint");
    assert_ne!(t.token, t2.token);
}

/// Fail-closed request validation: no event header, and non-JSON bodies,
/// get 400 after signature verification.
#[tokio::test]
async fn test_malformed_requests_get_400() {
    let (api, _) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);

    // Signed, but no X-GitHub-Event header.
    let body = b"{}".to_vec();
    let resp = base_router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/github")
                .header("x-hub-signature-256", sign(SECRET, &body))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Signed, has event header, body is not JSON.
    let body = b"not json{".to_vec();
    let resp = base_router()
        .with_state(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/github")
                .header("x-github-event", "installation")
                .header("x-hub-signature-256", sign(SECRET, &body))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// The webhook route is POST-only; GET falls through to 405 rather than
/// reaching the GitHub proxy catch-all.
#[tokio::test]
async fn test_get_webhook_is_405() {
    let (api, _) = spawn_mint_api().await;
    let state = single_state(Some(SECRET), &api);
    let resp = base_router()
        .with_state(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/webhooks/github")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// No webhook secret configured = listener disabled: the route still wins
/// over the catch-all but answers fail-closed 404, even for a correctly
/// signed payload. An EMPTY secret is not a secret at all — it must not
/// enable a trivially forgeable endpoint.
#[tokio::test]
async fn test_disabled_webhook_is_404() {
    let (api, _) = spawn_mint_api().await;
    let payload = json!({
        "action": "suspend",
        "installation": {"id": 42, "account": {"login": "openabdev"}}
    });
    for secret in [None, Some(""), Some("   ")] {
        let state = single_state(secret, &api);
        let resp = base_router()
            .with_state(state)
            .oneshot(signed_req("installation", &payload))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "secret {:?} must leave the listener disabled",
            secret
        );
    }
}
