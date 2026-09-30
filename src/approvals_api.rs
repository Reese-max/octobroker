//! Human-approval management API (`/approvals`) — issue #51.
//!
//! Operators list and decide pending approvals created by the
//! `tools_approval` policy tier. Authentication uses a dedicated operator
//! credential (`X-Octobroker-Operator-Key` → `[mcp.approvals]
//! operator_key`), deliberately separate from agent keys — approving a
//! high-risk write is a different trust decision than holding an agent's
//! bounded allowlist.
//!
//!   GET  /approvals[?status=pending|approved|denied|consumed|expired]
//!   GET  /approvals/{id}
//!   POST /approvals/{id}/approve
//!   POST /approvals/{id}/deny
//!
//! Requests:
//!   GET /approvals                                    → pending records
//!   GET /approvals?status=all                         → every record
//!   POST /approvals/apv_…/approve  (operator key)     → 200 + record
//!
//! Decisions are single-shot (409 on re-decision/expired/unknown-consume
//! states) and durable — a decision that cannot be fsync'd to the audit
//! JSONL fails 503 without changing state.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::approvals::{Approval, DecideError};
use crate::mcp::rpc_error;
use crate::AppState;

/// Dedicated operator credential — never an agent key. Startup validation
/// also rejects an operator_key that duplicates any agent key, and a
/// missing/wrong key gets 401 before any state is touched.
fn authenticate_operator(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let Some(cfg) = &state.config.mcp.approvals else {
        return Err(Box::new(rpc_error(
            StatusCode::NOT_FOUND,
            "approvals are not enabled",
        )));
    };
    let Some(presented) = headers
        .get("x-octobroker-operator-key")
        .and_then(|v| v.to_str().ok())
    else {
        tracing::warn!("approvals request rejected: missing X-Octobroker-Operator-Key");
        return Err(Box::new(rpc_error(
            StatusCode::UNAUTHORIZED,
            "X-Octobroker-Operator-Key header required",
        )));
    };
    if !crate::mcp::keys_match(&cfg.operator_key, presented) {
        tracing::warn!("approvals request rejected: invalid operator key");
        return Err(Box::new(rpc_error(
            StatusCode::UNAUTHORIZED,
            "invalid X-Octobroker-Operator-Key",
        )));
    }
    Ok(())
}

fn store(state: &AppState) -> Result<&crate::approvals::ApprovalStore, Box<Response>> {
    state.approvals.as_ref().ok_or_else(|| {
        Box::new(rpc_error(
            StatusCode::NOT_FOUND,
            "approvals are not enabled",
        ))
    })
}

fn approval_json(a: &Approval) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    serde_json::json!({
        "id": a.id,
        "agent": a.agent,
        "tool": a.tool,
        "repo": a.repo,
        "arg_keys": a.arg_keys,
        "args_hash": a.args_hash,
        "status": a.effective_status(now),
        "created_ts": a.created_ts,
        "expires_at": a.expires_at,
        "decided_ts": a.decided_ts,
        "consumed_ts": a.consumed_ts,
    })
}

pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let store = match store(&state) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = authenticate_operator(&state, &headers) {
        return *resp;
    }
    // Default shows only what needs a human decision.
    let status = params
        .get("status")
        .map(|s| s.as_str())
        .unwrap_or("pending");
    let records = store.list(if status == "all" { None } else { Some(status) });
    let body = serde_json::json!({
        "approvals": records.iter().map(approval_json).collect::<Vec<_>>()
    });
    json_response(StatusCode::OK, body)
}

pub async fn get_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let store = match store(&state) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = authenticate_operator(&state, &headers) {
        return *resp;
    }
    match store.get(&id) {
        Some(a) => json_response(StatusCode::OK, approval_json(&a)),
        None => rpc_error(StatusCode::NOT_FOUND, "unknown approval"),
    }
}

pub async fn approve_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    decide(&state, &id, true, &headers)
}

pub async fn deny_approval(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    decide(&state, &id, false, &headers)
}

fn decide(state: &AppState, id: &str, approved: bool, headers: &HeaderMap) -> Response {
    let store = match store(state) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = authenticate_operator(state, headers) {
        return *resp;
    }
    match store.decide(id, approved) {
        Ok(a) => {
            tracing::info!(
                "approval {} {} [agent={} tool={}]",
                id,
                if approved { "APPROVED" } else { "DENIED" },
                a.agent,
                a.tool
            );
            json_response(StatusCode::OK, approval_json(&a))
        }
        Err(DecideError::NotFound) => rpc_error(StatusCode::NOT_FOUND, "unknown approval"),
        Err(DecideError::NotPending) => {
            rpc_error(StatusCode::CONFLICT, "approval already decided or expired")
        }
        Err(DecideError::Persist(e)) => {
            tracing::error!("approval decision not durable (fail-closed): {}", e);
            rpc_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit backend unavailable — decision rejected",
            )
        }
    }
}

fn json_response(status: StatusCode, body: Value) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap_or_else(|_| rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cache, config, pool};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn approvals_tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "octobroker-apiv1-{}-{}.jsonl",
                name,
                std::process::id()
            ))
            .to_str()
            .unwrap()
            .to_string()
    }

    /// AppState with the approvals endpoint configured (operator key +
    /// store on a tmp JSONL) plus one agent whose key must NOT work as an
    /// operator credential. `enabled = false` models a deployment without
    /// [mcp.approvals]: no store, no config — every request is a local 404.
    fn test_state(store_path: &str, operator_key: &str, enabled: bool) -> Arc<AppState> {
        let identities = vec![config::IdentityConfig {
            id: "alice".into(),
            token: "t".into(),
        }];
        let agent = config::McpAgentConfig {
            id: "bot-a".into(),
            key: None,
            keys: vec!["agent-key".into()],
            tools: vec![],
            tools_approval: vec!["merge_pull_request".into()],
            repos: vec![],
            git_credentials_read_only: None,
        };
        Arc::new(AppState {
            pool: pool::PatPool::new(&identities),
            cache: cache::Cache::new(&config::CacheConfig::default()),
            config: config::Config {
                port: 8080,
                identities,
                allowed_owners: vec![],
                cache: config::CacheConfig::default(),
                mcp: config::McpConfig {
                    enabled: true,
                    enable_writes: true,
                    enable_git_credentials: false,
                    git_credentials_read_only: false,
                    upstream: None,
                    toolsets: vec![],
                    session_ttl_secs: 3600,
                    max_inflight_writes: 4,
                    agents: vec![agent],
                    github_app: None,
                    github_apps: vec![],
                    audit: Some(config::AuditConfig {
                        path: store_path.into(),
                        max_result_bytes: 1024,
                    }),
                    approvals: enabled.then(|| config::ApprovalsConfig {
                        operator_key: operator_key.into(),
                        ttl_secs: 900,
                    }),
                },
            },
            token_users: moka::future::Cache::builder().max_capacity(10).build(),
            http: reqwest::Client::new(),
            mcp_sessions: moka::future::Cache::builder().max_capacity(10).build(),
            app_tokens: None,
            multi_app_tokens: None,
            audit: None,
            write_inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            approvals: enabled
                .then(|| crate::approvals::ApprovalStore::open(store_path, 900).unwrap()),
        })
    }

    fn app(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/approvals", axum::routing::get(list_approvals))
            .route("/approvals/{id}", axum::routing::get(get_approval))
            .route(
                "/approvals/{id}/approve",
                axum::routing::post(approve_approval),
            )
            .route("/approvals/{id}/deny", axum::routing::post(deny_approval))
            .with_state(state)
    }

    fn req(method: &str, uri: &str, key: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(k) = key {
            b = b.header("x-octobroker-operator-key", k);
        }
        b.body(Body::empty()).unwrap()
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn make_pending(state: &AppState, args_hash: &str) -> String {
        match state
            .approvals
            .as_ref()
            .unwrap()
            .gate("bot-a", "merge_pull_request", args_hash, &[], Some("o/r"))
            .unwrap()
        {
            crate::approvals::GateDecision::Pending { id, .. } => id,
            _ => panic!("expected pending"),
        }
    }

    #[tokio::test]
    async fn test_disabled_is_404() {
        let state = test_state(&approvals_tmp("disabled"), "op-key", false);
        let resp = app(state)
            .oneshot(req("GET", "/approvals", Some("op-key")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_operator_auth_is_separate_from_agent_keys() {
        let path = approvals_tmp("auth");
        let state = test_state(&path, "op-key", true);
        for key in [None, Some("agent-key"), Some("wrong")] {
            let resp = app(state.clone())
                .oneshot(req("GET", "/approvals", key))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "key {:?}", key);
        }
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_list_decide_and_get_roundtrip() {
        let path = approvals_tmp("roundtrip");
        let state = test_state(&path, "op-key", true);
        let id = make_pending(&state, "deadbeef");

        // Default list shows the pending record (arg keys only — no values).
        let resp = app(state.clone())
            .oneshot(req("GET", "/approvals", Some("op-key")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["approvals"].as_array().unwrap().len(), 1);
        assert_eq!(v["approvals"][0]["id"], id.as_str());
        assert_eq!(v["approvals"][0]["status"], "pending");

        // Approve → durable status, then single-shot semantics.
        let resp = app(state.clone())
            .oneshot(req(
                "POST",
                &format!("/approvals/{}/approve", id),
                Some("op-key"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["status"], "approved");
        let resp = app(state.clone())
            .oneshot(req(
                "POST",
                &format!("/approvals/{}/approve", id),
                Some("op-key"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // Approved record shows in status-filtered and single GET.
        let resp = app(state.clone())
            .oneshot(req("GET", "/approvals?status=approved", Some("op-key")))
            .await
            .unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["approvals"].as_array().unwrap().len(), 1);
        let resp = app(state.clone())
            .oneshot(req("GET", &format!("/approvals/{}", id), Some("op-key")))
            .await
            .unwrap();
        assert_eq!(body_json(resp).await["status"], "approved");
        let resp = app(state.clone())
            .oneshot(req("GET", "/approvals/apv_ghost", Some("op-key")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Deny path on a fresh pending (distinct args hash — the first
        // triple's record is already consumed by the approval above).
        let id2 = make_pending(&state, "cafebabe");
        let resp = app(state.clone())
            .oneshot(req(
                "POST",
                &format!("/approvals/{}/deny", id2),
                Some("op-key"),
            ))
            .await
            .unwrap();
        assert_eq!(body_json(resp).await["status"], "denied");

        // Durable: the JSONL carries request + both decisions.
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[1]["phase"], "approval_decision");
        assert_eq!(lines[1]["decision"], "approved");
        assert_eq!(lines[3]["decision"], "denied");
        std::fs::remove_file(&path).ok();
    }
}
