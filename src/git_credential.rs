//! Git-over-HTTPS credential issuance (`/git-credential`).
//!
//! Repository-scoped agents exchange their `X-Octobroker-Key` for a short-lived
//! GitHub App installation token scoped to EXACTLY ONE repository, usable as
//! a git HTTPS credential (`x-access-token:<token>`). This closes the last
//! long-lived-credential gap for agents: pushes authenticate as the App
//! (`<app>[bot]`), expire within the hour, and every issuance is fail-closed
//! audited.
//!
//! Request:  GET /git-credential?repo=<owner>/<name>   (X-Octobroker-Key header)
//! Response: {"username":"x-access-token","password":"…","expires_at":…}
//!
//! Policy stack (all fail-closed):
//! key auth → repo-scoped agent → repo allowlist → installation coverage →
//! audited issuance → single-repo token mint (GitHub enforces the repository
//! boundary) → ref-level default-branch check for push-capable credentials
//! (GitHub's branch protection enforces the ref boundary).

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::mcp::{authenticate, rpc_error};
use crate::AppState;

pub async fn git_credential(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if !state.config.mcp.enable_git_credentials {
        return rpc_error(StatusCode::NOT_FOUND, "git credentials are not enabled");
    }
    // Authenticated agents only. Startup validation guarantees agents exist
    // when the endpoint is enabled, so network-trust mode (None) is denied.
    let agent = match authenticate(&state, &headers) {
        Ok(Some(a)) => a,
        Ok(None) => return rpc_error(StatusCode::UNAUTHORIZED, "agent authentication required"),
        Err(resp) => return *resp,
    };

    // Exactly one repository per credential: owner/name, strict shape AND
    // strict charset (GitHub logins: alphanumeric + hyphen; repo names:
    // alphanumeric + `-_.`). Percent-encoded or exotic input is rejected
    // here — before the allowlist, audit preflight, or any mint attempt.
    // Dot-only names are rejected too: they are not valid GitHub
    // repositories and would resolve to the *owner*'s own URL when the
    // ref-policy reads are built.
    let Some((owner, name)) =
        params
            .get("repo")
            .and_then(|r| r.split_once('/'))
            .filter(|(o, n)| {
                !o.is_empty()
                    && !n.is_empty()
                    && !matches!(*n, "." | "..")
                    && o.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
    else {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            "repo=<owner>/<name> query required",
        );
    };

    // Repository-scoped agents only — a repo-less agent has no installation
    // envelope, and git credentials are never PAT-backed.
    if agent.repos.is_empty() {
        tracing::warn!(
            "git-credential DENIED (repo-less agent) [agent={}]",
            agent.id
        );
        return rpc_error(
            StatusCode::FORBIDDEN,
            "git credentials require a repository-scoped agent",
        );
    }
    if !crate::policy::repo_allowed(&agent.repos, owner, name) {
        tracing::warn!(
            "git-credential DENIED (repo {}/{} not allowlisted) [agent={}]",
            owner,
            name,
            agent.id
        );
        return rpc_error(
            StatusCode::FORBIDDEN,
            "repository not permitted by agent policy",
        );
    }

    // Resolve the installation: multi-app routes by owner; single-app must
    // match the configured owner when one is set.
    let owner_key = owner.to_lowercase();
    let provider = if let Some(multi) = &state.multi_app_tokens {
        match multi.get(&owner_key) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    "git-credential DENIED (no installation for owner {}) [agent={}]",
                    owner,
                    agent.id
                );
                return rpc_error(
                    StatusCode::FORBIDDEN,
                    "no GitHub App installation configured for repository owner",
                );
            }
        }
    } else if let Some(single) = &state.app_tokens {
        let Some(configured) = state
            .config
            .mcp
            .github_app
            .as_ref()
            .and_then(|a| a.owner.as_deref())
            .filter(|o| !o.trim().is_empty())
        else {
            // Startup validation rejects this; defense-in-depth for manually
            // constructed state/tests.
            return rpc_error(
                StatusCode::FORBIDDEN,
                "single-App git credentials require a configured owner",
            );
        };
        if !configured.eq_ignore_ascii_case(owner) {
            return rpc_error(
                StatusCode::FORBIDDEN,
                "no GitHub App installation configured for repository owner",
            );
        }
        single
    } else {
        // Unreachable: validation requires an App backend.
        return rpc_error(StatusCode::BAD_GATEWAY, "no GitHub App backend configured");
    };

    // Durable preflight BEFORE any owner verification, mint, or cache lookup.
    // This ensures even a token minted but never returned has an audit trail.
    let Some(sink) = &state.audit else {
        return rpc_error(StatusCode::SERVICE_UNAVAILABLE, "audit backend unavailable");
    };
    let cred_label = format!("github-app:{}", owner_key);
    let repo_label = format!("{}/{}", owner, name);
    if let Err(e) = sink.record_git_credential_request(&agent.id, &cred_label, &repo_label) {
        tracing::error!(
            "audit unavailable — rejecting git-credential before mint (fail-closed): {}",
            e
        );
        return rpc_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit backend unavailable — credential rejected",
        );
    }

    // Effective credential mode, resolved from operator config only (never
    // request input): the per-agent override wins over the global default in
    // either direction; None inherits. Resolved before any result record so
    // failure audits also carry the mode the agent was configured for.
    let read_only = agent
        .git_credentials_read_only
        .unwrap_or(state.config.mcp.git_credentials_read_only);
    let mode = if read_only { "read" } else { "write" };

    // Bind the configured route label / explicit installation ID to the
    // actual installation account returned by GitHub. Never trust config
    // labels alone: same-named repos can exist under another owner.
    if let Err(e) = provider.verify_owner(owner).await {
        tracing::error!(
            "git-credential owner verification failed for {}/{}: {}",
            owner,
            name,
            e
        );
        if let Err(audit_err) = sink.record_git_credential_result(
            &agent.id,
            &cred_label,
            &repo_label,
            mode,
            Some("owner_verification_failed"),
            None,
        ) {
            tracing::error!("git-credential failure result audit failed: {}", audit_err);
        }
        return rpc_error(
            StatusCode::FORBIDDEN,
            "installation owner verification failed",
        );
    }

    // Git-specific token: exactly one repository, with a cache namespace
    // separate from MCP tokens (and read/write git tokens namespaced apart
    // from each other).
    let token = match provider.token_git(name, read_only).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("git-credential mint failed for {}/{}: {}", owner, name, e);
            if let Err(audit_err) = sink.record_git_credential_result(
                &agent.id,
                &cred_label,
                &repo_label,
                mode,
                Some("mint_failed"),
                None,
            ) {
                tracing::error!("git-credential failure result audit failed: {}", audit_err);
            }
            return rpc_error(StatusCode::BAD_GATEWAY, "credential mint failed");
        }
    };

    // Ref-level push policy (#49): a repository-scoped token can push to
    // ANY ref in the repo, including the default branch, and octobroker
    // does not proxy git to narrow that — GitHub's own branch protection /
    // ruleset is the ref-level boundary. When the operator requires it,
    // prove the default branch is protected before handing out a
    // push-capable credential. Read-only (contents:read) credentials are
    // exempt: they cannot push, so there is no ref to police. Runs after
    // the mint because the reads are authenticated by the repo-scoped token
    // itself — so a live push-capable token exists in-process for the
    // duration of this check, and is dropped again on any refusal (policy
    // denial below, or a failed audit result record further down) so a
    // refused request leaves octobroker holding no credential for it.
    if state.config.mcp.require_protected_default_branch && !read_only {
        let denial = match provider
            .default_branch_protected(owner, name, &token.token)
            .await
        {
            Ok(crate::ref_policy::Protection::Protected) => None,
            // Two denials, deliberately distinct: a repository that needs
            // hardening (403 — add the ruleset) versus an answer we could not
            // obtain at all (503 — GitHub unreachable, rate limited, timed
            // out; retry). The cause is echoed because it names the failing
            // read, never the credential.
            Ok(crate::ref_policy::Protection::Unprotected) => Some((
                StatusCode::FORBIDDEN,
                "unprotected_default_branch",
                "the repository's default branch is not protected — see the ref-level push policy in the README"
                    .to_string(),
                None,
            )),
            // The cause (a GitHub status, an unreachable API base) goes to
            // the broker log, not to the caller: the response must not echo
            // internal endpoints back to the agent.
            Err(e) => Some((
                StatusCode::SERVICE_UNAVAILABLE,
                "unverifiable_default_branch",
                "the repository's default branch protection could not be verified — retry later"
                    .to_string(),
                Some(e),
            )),
        };
        if let Some((status, reason, message, detail)) = denial {
            tracing::warn!(
                "git-credential DENIED [agent={}, repo={}, reason={}, detail={:?}]",
                agent.id,
                repo_label,
                reason,
                detail
            );
            provider.evict_git_tokens(name);
            if let Err(audit_err) = sink.record_git_credential_result(
                &agent.id,
                &cred_label,
                &repo_label,
                mode,
                Some(reason),
                None,
            ) {
                tracing::error!("git-credential failure result audit failed: {}", audit_err);
            }
            return rpc_error(status, &message);
        }
    }

    // Result record: if this cannot be persisted, do not return the token.
    if let Err(e) = sink.record_git_credential_result(
        &agent.id,
        &cred_label,
        &repo_label,
        mode,
        None,
        Some(token.expires_at),
    ) {
        tracing::error!(
            "audit result unavailable — rejecting git-credential response: {}",
            e
        );
        // Same invariant as a policy denial: a credential that will not be
        // handed out is not kept around.
        provider.evict_git_tokens(name);
        return rpc_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit backend unavailable — credential rejected",
        );
    }

    tracing::info!(
        "git-credential issued for {}/{} [agent={} via {}] (contents={}, expires_at={})",
        owner,
        name,
        agent.id,
        cred_label,
        mode,
        token.expires_at
    );
    let body = serde_json::json!({
        "username": "x-access-token",
        "password": token.token,
        "expires_at": token.expires_at,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
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

    type MintLog = Arc<std::sync::Mutex<Vec<(u64, serde_json::Value)>>>;

    /// Default branch the mock GitHub reports for `repo` (see
    /// `spawn_mock_github`'s ref-policy surface).
    fn default_branch_of(repo: &str) -> &'static str {
        if repo.ends_with("-slash") {
            "release/v1"
        } else {
            "main"
        }
    }

    async fn spawn_mock_github() -> (String, MintLog) {
        use axum::extract::Path;

        async fn mint(
            State(log): State<MintLog>,
            Path(id): Path<u64>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::response::Response {
            // `<repo>-mintfail` cannot be minted (GitHub answers 422/5xx for
            // an unknown repository) so the failure path is reachable.
            if body["repositories"][0]
                .as_str()
                .is_some_and(|r| r.starts_with("mintfail"))
            {
                return axum::response::Response::builder()
                    .status(axum::http::StatusCode::UNPROCESSABLE_ENTITY)
                    .body(axum::body::Body::from("{\"message\":\"not found\"}"))
                    .unwrap();
            }
            log.lock().unwrap().push((id, body));
            let exp = time::OffsetDateTime::from_unix_timestamp(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600) as i64,
            )
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
            axum::response::Response::builder()
                .status(axum::http::StatusCode::CREATED)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "token": if id == 41 { "ghs_git_openabdev" } else { "ghs_git_oablab" },
                        "expires_at": exp
                    })
                    .to_string(),
                ))
                .unwrap()
        }
        async fn installation(Path(id): Path<u64>) -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({
                "id": id,
                "account": {"login": if id == 41 { "openabdev" } else { "oablab" }}
            }))
        }

        // Ref-level push policy surface (#49): the two reads the broker makes
        // before handing out a PUSH-CAPABLE credential. Answers are derived
        // from the repository name so one stateless mock serves every case:
        //   <repo>-unprotected → default branch reports protected:false
        //   <repo>-ghfail      → the branch read fails (500)
        //   <repo>-metafail    → the repository read fails (500)
        //   <repo>-nodefault   → the repository reports no default branch
        //   <repo>-flip        → protected on the first branch read; every
        //                       later branch read for it fails
        //   <repo>-mintfail    → the mint endpoint answers 500
        //   <repo>-slash       → default branch is "release/v1" (a branch
        //                       name containing a slash)
        //   anything else       → default branch "main", protected:true
        async fn repo_meta(
            Path((_owner, repo)): Path<(String, String)>,
        ) -> axum::response::Response {
            let json = |value: serde_json::Value| {
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(value.to_string()))
                    .unwrap()
            };
            if repo.ends_with("-metafail") {
                return axum::response::Response::builder()
                    .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(axum::body::Body::from("boom"))
                    .unwrap();
            }
            if repo.ends_with("-nodefault") {
                return json(serde_json::json!({"default_branch": null}));
            }
            json(serde_json::json!({
                "default_branch": default_branch_of(&repo),
            }))
        }
        // Per-repository branch-read counter, so `<repo>-flip` can answer
        // once and fail afterwards (see below).
        let branch_reads = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
            String,
            usize,
        >::new()));
        let counter = branch_reads.clone();
        let repo_branch = move |Path((_owner, repo, branch)): Path<(String, String, String)>| {
            let counter = counter.clone();
            async move {
                let reply = |status: axum::http::StatusCode, body: String| {
                    axum::response::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body))
                        .unwrap()
                };
                let server_error = || {
                    reply(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "boom".to_string(),
                    )
                };
                if repo.ends_with("-ghfail") {
                    return server_error();
                }
                if repo.ends_with("-flip") {
                    // Protected on the first read, unreachable afterwards: a
                    // later request that still succeeds can only have used a
                    // cached verdict.
                    let mut reads = counter.lock().unwrap();
                    let seen = reads.entry(repo.clone()).or_insert(0);
                    *seen += 1;
                    if *seen > 1 {
                        return server_error();
                    }
                }
                // Only the repo's real default branch exists: asking for any
                // other name 404s, exactly as GitHub would.
                if branch != default_branch_of(&repo) {
                    return reply(
                        axum::http::StatusCode::NOT_FOUND,
                        "{\"message\":\"Branch not found\"}".to_string(),
                    );
                }
                reply(
                    axum::http::StatusCode::OK,
                    serde_json::json!({
                        "name": branch,
                        "protected": !repo.ends_with("-unprotected"),
                    })
                    .to_string(),
                )
            }
        };

        let log: MintLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route(
                "/app/installations/{id}/access_tokens",
                axum::routing::post(mint),
            )
            .route("/app/installations/{id}", axum::routing::get(installation))
            .route("/repos/{owner}/{repo}", axum::routing::get(repo_meta))
            .route(
                "/repos/{owner}/{repo}/branches/{*branch}",
                axum::routing::get(repo_branch),
            )
            .with_state(log.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{}", addr), log)
    }

    fn agent(id: &str, key: &str, repos: &[&str]) -> config::McpAgentConfig {
        config::McpAgentConfig {
            id: id.into(),
            key: None,
            keys: vec![key.into()],
            tools: vec![],
            repos: repos.iter().map(|s| s.to_string()).collect(),
            git_credentials_read_only: None,
        }
    }

    /// Agent with an explicit per-agent read-only override (`Some(true)` /
    /// `Some(false)`), as opposed to inheriting the global flag (`None`).
    fn agent_override(
        id: &str,
        key: &str,
        repos: &[&str],
        read_only: bool,
    ) -> config::McpAgentConfig {
        let mut a = agent(id, key, repos);
        a.git_credentials_read_only = Some(read_only);
        a
    }

    async fn test_state(
        enabled: bool,
        read_only: bool,
        sink: Option<crate::audit::AuditSink>,
    ) -> (Arc<AppState>, MintLog) {
        test_state_with_ref_policy(enabled, read_only, false, sink).await
    }

    /// Same state, with the #49 ref-level push policy gate
    /// (`require_protected_default_branch`) set explicitly.
    async fn test_state_with_ref_policy(
        enabled: bool,
        read_only: bool,
        require_protected_default_branch: bool,
        sink: Option<crate::audit::AuditSink>,
    ) -> (Arc<AppState>, MintLog) {
        let (gh, mint_log) = spawn_mock_github().await;
        let entries = vec![
            config::GithubAppsEntry {
                app_id: "111".into(),
                private_key: crate::app_token::tests::TEST_RSA_PEM.into(),
                installation_id: Some(41),
                owner: "openabdev".into(),
            },
            config::GithubAppsEntry {
                app_id: "222".into(),
                private_key: crate::app_token::tests::TEST_RSA_PEM.into(),
                installation_id: Some(42),
                owner: "oablab".into(),
            },
            // Mislabeled on purpose: installation 43 actually belongs to
            // "oablab" per the mock — owner verification must catch this.
            config::GithubAppsEntry {
                app_id: "333".into(),
                private_key: crate::app_token::tests::TEST_RSA_PEM.into(),
                installation_id: Some(43),
                owner: "mislabeled".into(),
            },
        ];
        let multi = crate::app_token::MultiAppTokenProvider::new(&entries, gh).unwrap();
        let cache_config = config::CacheConfig::default();
        (
            Arc::new(AppState {
                pool: pool::PatPool::new(&[]),
                cache: cache::Cache::new(&cache_config),
                config: config::Config {
                    port: 8080,
                    identities: vec![],
                    allowed_owners: vec![],
                    cache: cache_config,
                    mcp: config::McpConfig {
                        enabled: true,
                        enable_writes: false,
                        enable_git_credentials: enabled,
                        git_credentials_read_only: read_only,
                        require_protected_default_branch,
                        upstream: None,
                        toolsets: vec![],
                        session_ttl_secs: 3600,
                        max_inflight_writes: 4,
                        agents: vec![
                            agent(
                                "b0",
                                "key-b0",
                                &[
                                    "openabdev/openab",
                                    // ref-policy fixtures (see spawn_mock_github)
                                    "openabdev/openab-unprotected",
                                    "openabdev/openab-ghfail",
                                    "openabdev/openab-metafail",
                                    "openabdev/openab-nodefault",
                                    "openabdev/openab-flip",
                                    "openabdev/mintfail",
                                    "openabdev/openab-slash",
                                    "oablab/chi",
                                    "mislabeled/repo",
                                ],
                            ),
                            agent("norepo", "key-norepo", &[]),
                            agent("other", "key-other", &["otherorg/thing"]),
                            // Per-agent overrides: pinned read-only / pinned
                            // push-capable regardless of the global flag.
                            agent_override(
                                "pinned-ro",
                                "key-ro",
                                &["openabdev/openab", "openabdev/openab-unprotected"],
                                true,
                            ),
                            agent_override(
                                "pinned-rw",
                                "key-rw",
                                &["openabdev/openab", "openabdev/openab-unprotected"],
                                false,
                            ),
                        ],
                        github_app: None,
                        github_apps: entries,
                        audit: None,
                    },
                },
                token_users: moka::future::Cache::builder().max_capacity(10).build(),
                http: reqwest::Client::new(),
                mcp_sessions: moka::future::Cache::builder().max_capacity(10).build(),
                app_tokens: None,
                multi_app_tokens: Some(multi),
                audit: sink,
                write_inflight: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            }),
            mint_log,
        )
    }

    fn app(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/git-credential", axum::routing::get(git_credential))
            .with_state(state)
    }

    fn req(repo: &str, key: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method("GET")
            .uri(format!("/git-credential?repo={}", repo));
        if let Some(k) = key {
            b = b.header("x-octobroker-key", k);
        }
        b.body(Body::empty()).unwrap()
    }

    fn audit_tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "octobroker-gitcred-{}-{}.jsonl",
                name,
                std::process::id()
            ))
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn test_disabled_is_404() {
        let (state, _) = test_state(false, false, None).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_missing_or_bad_key_is_401() {
        let path = audit_tmp("auth");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state(true, false, Some(sink)).await;
        for key in [None, Some("wrong")] {
            let resp = app(state.clone())
                .oneshot(req("openabdev/openab", key))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        assert!(mint_log.lock().unwrap().is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_issues_single_repo_token_and_audits() {
        let path = audit_tmp("ok");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state(true, false, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["username"], "x-access-token");
        assert_eq!(v["password"], "ghs_git_openabdev");
        assert!(v["expires_at"].as_u64().unwrap() > 0);

        // Mint envelope: routed to the openabdev installation, EXACTLY one
        // repository, contents:write only — never the App's full permissions.
        {
            let minted = mint_log.lock().unwrap();
            assert_eq!(minted.len(), 1);
            assert_eq!(minted[0].0, 41);
            assert_eq!(minted[0].1["repositories"], serde_json::json!(["openab"]));
            assert_eq!(
                minted[0].1["permissions"],
                serde_json::json!({"contents": "write"})
            );
        }

        // Two-phase audit: durable preflight, then a success result.
        let records: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["phase"], "git_credential_request");
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[1]["phase"], "git_credential_result");
        assert_eq!(records[1]["mode"], "write");
        assert_eq!(records[1]["success"], true);
        assert!(records[1]["expires_at"].as_u64().unwrap() > 0);
        for r in &records {
            assert_eq!(r["agent"], "b0");
            assert_eq!(r["cred"], "github-app:openabdev");
            assert_eq!(r["repo"], "openabdev/openab");
            // the token value itself is never audited
            assert!(!r.to_string().contains("ghs_git_openabdev"));
        }
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_read_only_mode_mints_contents_read() {
        let path = audit_tmp("readonly");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // git_credentials_read_only = true
        let (state, mint_log) = test_state(true, true, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["username"], "x-access-token");
        assert!(v["expires_at"].as_u64().unwrap() > 0);

        // The mint envelope must request contents:READ — clone/fetch only,
        // no push — never write when read-only is configured.
        let minted = mint_log.lock().unwrap();
        assert_eq!(minted.len(), 1);
        assert_eq!(minted[0].1["repositories"], serde_json::json!(["openab"]));
        assert_eq!(
            minted[0].1["permissions"],
            serde_json::json!({"contents": "read"})
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_per_agent_read_only_overrides_global_write() {
        let path = audit_tmp("agent-ro");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // Global default: push-capable (read_only = false). The pinned-ro
        // agent must still get contents:read.
        let (state, mint_log) = test_state(true, false, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab", Some("key-ro")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let minted = mint_log.lock().unwrap();
        assert_eq!(minted.len(), 1);
        assert_eq!(
            minted[0].1["permissions"],
            serde_json::json!({"contents": "read"})
        );
        // The durable audit result must record the effective mode.
        let last: serde_json::Value = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .last()
            .map(|l| serde_json::from_str(l).unwrap())
            .unwrap();
        assert_eq!(last["phase"], "git_credential_result");
        assert_eq!(last["mode"], "read");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_per_agent_write_overrides_global_read_only() {
        let path = audit_tmp("agent-rw");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // Global default: read-only fleet. The pinned-rw agent is the one
        // explicitly push-capable exception — it must get contents:write.
        let (state, mint_log) = test_state(true, true, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab", Some("key-rw")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let minted = mint_log.lock().unwrap();
        assert_eq!(minted.len(), 1);
        assert_eq!(
            minted[0].1["permissions"],
            serde_json::json!({"contents": "write"})
        );
        // The durable audit result must record the effective mode.
        let last: serde_json::Value = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .last()
            .map(|l| serde_json::from_str(l).unwrap())
            .unwrap();
        assert_eq!(last["phase"], "git_credential_result");
        assert_eq!(last["mode"], "write");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_routes_by_owner() {
        let path = audit_tmp("route");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state(true, false, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("oablab/chi", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["password"], "ghs_git_oablab");
        let minted = mint_log.lock().unwrap();
        assert_eq!(minted.len(), 1);
        assert_eq!(minted[0].0, 42, "must route to the oablab installation");
        assert_eq!(minted[0].1["repositories"], serde_json::json!(["chi"]));
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_policy_denials() {
        let path = audit_tmp("deny");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state(true, false, Some(sink)).await;
        // off-allowlist repo
        let resp = app(state.clone())
            .oneshot(req("openabdev/secret-repo", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // repo-less agent
        let resp = app(state.clone())
            .oneshot(req("openabdev/openab", Some("key-norepo")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // malformed repo params, including encoded and exotic-charset forms
        // (%2F decodes back to '/'; charset validation rejects the rest)
        for bad in [
            "justanowner",
            "openabdev%2Fopenab%2Fx",
            "openabdev/",
            "/openab",
            "openabdev/open%20ab", // decodes to a space
            "openabdev/open+ab",   // '+' decodes to a space
            "open~abdev/openab",   // invalid owner charset
            "openabdev/.",         // dot-only name resolves to the owner's URL
            "openabdev/..",
        ] {
            let resp = app(state.clone())
                .oneshot(req(bad, Some("key-b0")))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "repo={}", bad);
        }
        // allowlisted repo whose owner has no App installation
        let resp = app(state.clone())
            .oneshot(req("otherorg/thing", Some("key-other")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // denials never mint, never audit
        assert!(mint_log.lock().unwrap().is_empty());
        assert!(std::fs::read_to_string(&path).unwrap().is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_owner_mismatch_fails_closed() {
        let path = audit_tmp("mismatch");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state(true, false, Some(sink)).await;
        // Config labels installation 43 as "mislabeled" but GitHub says the
        // installation account is "oablab" — the label must not be trusted.
        let resp = app(state)
            .oneshot(req("mislabeled/repo", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // verification failure must never reach the mint endpoint
        assert!(mint_log.lock().unwrap().is_empty());
        // audited: preflight + failed result
        let records: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["phase"], "git_credential_request");
        assert_eq!(records[1]["phase"], "git_credential_result");
        assert_eq!(records[1]["success"], false);
        assert!(records[1]["expires_at"].is_null());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_audit_fail_closed() {
        let sink = crate::audit::AuditSink::failing_for_tests();
        let (state, mint_log) = test_state(true, false, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // a failed audit preflight must never reach the mint endpoint
        assert!(mint_log.lock().unwrap().is_empty());
    }

    // ---- #49 ref-level push policy ----

    /// Audit trail of one /git-credential request as parsed JSONL records.
    fn audit_records(path: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn test_protected_default_branch_still_issues_push_credential() {
        let path = audit_tmp("refpolicy-ok");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state_with_ref_policy(true, false, true, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["password"], "ghs_git_openabdev");
        assert_eq!(mint_log.lock().unwrap().len(), 1);
        let records = audit_records(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["success"], true);
        // A successful issuance names no denial.
        assert!(records[1]["denial"].is_null());
        assert!(records[1]["expires_at"].as_u64().unwrap() > 0);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_unprotected_default_branch_denies_push_credential() {
        let path = audit_tmp("refpolicy-unprotected");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state_with_ref_policy(true, false, true, Some(sink)).await;
        let resp = app(state.clone())
            .oneshot(req("openabdev/openab-unprotected", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // The credential must never leave the broker, in any form.
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("ghs_git_openabdev"),
            "token leaked: {}",
            text
        );
        assert!(text.contains("not protected"), "got: {}", text);
        // Audited as a failed issuance with the policy named (preflight +
        // result, no expiry) — the operator can tell "needs hardening" from
        // an unreadable answer.
        let records = audit_records(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["phase"], "git_credential_request");
        assert_eq!(records[1]["phase"], "git_credential_result");
        assert_eq!(records[1]["success"], false);
        assert_eq!(records[1]["mode"], "write");
        assert_eq!(records[1]["denial"], "unprotected_default_branch");
        assert!(records[1]["expires_at"].is_null());
        assert!(!records[1].to_string().contains("ghs_git_openabdev"));
        // A denied issuance leaves no live push-capable credential cached:
        // the second attempt mints again rather than reusing the first.
        assert_eq!(mint_log.lock().unwrap().len(), 1);
        let resp = app(state)
            .oneshot(req("openabdev/openab-unprotected", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            mint_log.lock().unwrap().len(),
            2,
            "denied credential must be evicted from the token cache"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_protection_check_fails_closed_when_github_errors() {
        let path = audit_tmp("refpolicy-ghfail");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state_with_ref_policy(true, false, true, Some(sink)).await;
        let resp = app(state.clone())
            .oneshot(req("openabdev/openab-ghfail", Some("key-b0")))
            .await
            .unwrap();
        // An unreadable answer is never a pass, and it is NOT reported as a
        // policy denial: 503 (retry) with its own audit reason, so a GitHub
        // outage does not read as "this repo needs hardening".
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&body).contains("ghs_git_openabdev"),
            "token leaked: {}",
            String::from_utf8_lossy(&body)
        );
        let records = audit_records(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["success"], false);
        assert_eq!(records[1]["denial"], "unverifiable_default_branch");
        // Same invariant as the 403 arm: the credential minted before the
        // check must not stay cached for a later request.
        assert_eq!(mint_log.lock().unwrap().len(), 1, "issued, then denied");
        let resp = app(state)
            .oneshot(req("openabdev/openab-ghfail", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            mint_log.lock().unwrap().len(),
            2,
            "denied credential must be evicted from the token cache"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_protection_check_fails_closed_on_metadata_failures() {
        let path = audit_tmp("refpolicy-meta");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, _) = test_state_with_ref_policy(true, false, true, Some(sink)).await;
        // The repository read itself failing, and a repository that reports
        // no default branch, are both "protection not proven".
        for repo in ["openabdev/openab-metafail", "openabdev/openab-nodefault"] {
            let resp = app(state.clone())
                .oneshot(req(repo, Some("key-b0")))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{}", repo);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                !String::from_utf8_lossy(&body).contains("ghs_git_openabdev"),
                "token leaked: {}",
                String::from_utf8_lossy(&body)
            );
        }
        let records = audit_records(&path);
        assert_eq!(records.len(), 4, "preflight + result per request");
        for record in records
            .iter()
            .filter(|r| r["phase"] == "git_credential_result")
        {
            assert_eq!(record["success"], false);
            assert_eq!(record["denial"], "unverifiable_default_branch");
        }
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_mint_failure_is_audited_as_a_failure() {
        let path = audit_tmp("refpolicy-mintfail");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, mint_log) = test_state_with_ref_policy(true, false, true, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/mintfail", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        // `success` is derived from `denial`, so a failed issuance can never
        // be recorded without the reason it failed.
        let records = audit_records(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["phase"], "git_credential_result");
        assert_eq!(records[1]["success"], false);
        assert_eq!(records[1]["denial"], "mint_failed");
        assert!(records[1]["expires_at"].is_null());
        assert!(mint_log.lock().unwrap().is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_pinned_write_agent_is_still_checked_for_protection() {
        let path = audit_tmp("refpolicy-pinned-rw");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // Read-only fleet default, but this agent pins itself push-capable.
        // The policy check must follow the EFFECTIVE mode: skipping it here
        // would hand a `contents: write` credential for an unprotected
        // repository — exactly the bypass the per-agent override creates.
        let (state, mint_log) = test_state_with_ref_policy(true, true, true, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab-unprotected", Some("key-rw")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(mint_log.lock().unwrap().len(), 1, "issued, then denied");
        let last = audit_records(&path).pop().unwrap();
        assert_eq!(last["denial"], "unprotected_default_branch");
        assert_eq!(last["mode"], "write");
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_pinned_read_only_agent_is_exempt_from_the_check() {
        let path = audit_tmp("refpolicy-pinned-ro");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // Mirror image: the fleet is push-capable, this agent pins itself
        // read-only, so there is no ref to police.
        let (state, mint_log) = test_state_with_ref_policy(true, false, true, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab-unprotected", Some("key-ro")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            mint_log.lock().unwrap()[0].1["permissions"],
            serde_json::json!({"contents": "read"})
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_protection_check_is_opt_in() {
        let path = audit_tmp("refpolicy-off");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // Flag off: the repository is unprotected and the credential is
        // issued anyway — existing deployments are unaffected by default.
        let (state, mint_log) = test_state_with_ref_policy(true, false, false, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab-unprotected", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(mint_log.lock().unwrap().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_read_only_credential_skips_protection_check() {
        let path = audit_tmp("refpolicy-readonly");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        // Flag on, but the issued credential is contents:read — it cannot
        // push at all, so there is no ref to police and no reason to deny.
        let (state, mint_log) = test_state_with_ref_policy(true, true, true, Some(sink)).await;
        let resp = app(state)
            .oneshot(req("openabdev/openab-unprotected", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let minted = mint_log.lock().unwrap();
        assert_eq!(minted.len(), 1);
        assert_eq!(
            minted[0].1["permissions"],
            serde_json::json!({"contents": "read"})
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_failed_result_audit_discards_the_minted_credential() {
        let path = audit_tmp("refpolicy-resultfail");
        // The preflight record persists; the result record does not. That is
        // the only window where a valid push-capable token exists for a
        // request whose issuance never completes — it must be dropped, not
        // left cached for the next caller to collect.
        let sink =
            crate::audit::AuditSink::failing_on_phase_for_tests(&path, "git_credential_result");
        let (state, mint_log) = test_state(true, false, Some(sink)).await;
        let resp = app(state.clone())
            .oneshot(req("openabdev/openab", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mint_log.lock().unwrap().len(), 1, "issued, then discarded");
        // No second request can collect that token: it was minted again.
        let resp = app(state)
            .oneshot(req("openabdev/openab", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            mint_log.lock().unwrap().len(),
            2,
            "a credential that was never audited must not stay cached"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_protection_verdict_is_reused_within_its_ttl() {
        let path = audit_tmp("refpolicy-cached");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, _) = test_state_with_ref_policy(true, false, true, Some(sink)).await;
        // `<repo>-flip` reports a protected default branch once and then fails
        // every read, so a second request that still succeeds can only have
        // used the cached verdict. The window is deliberate and bounded by
        // PROTECT_TTL (a protection removed a moment ago can still pass for
        // at most that long); denials are never cached, so fixing a
        // repository takes effect at once.
        for attempt in 1..=2 {
            let resp = app(state.clone())
                .oneshot(req("openabdev/openab-flip", Some("key-b0")))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "attempt {} should reuse the cached verdict",
                attempt
            );
        }
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_default_branch_with_slash_is_checked() {
        let path = audit_tmp("refpolicy-slash");
        let sink = crate::audit::AuditSink::open(&path).unwrap();
        let (state, _) = test_state_with_ref_policy(true, false, true, Some(sink)).await;
        // Default branch is "release/v1": the branch that gets checked is
        // the one GitHub reports, not a hardcoded "main" — asking for any
        // other name 404s in the mock, exactly as GitHub would. (That the
        // name travels percent-encoded is pinned by
        // app_token::tests::test_branch_url_carries_the_branch_as_one_segment;
        // axum percent-decodes the path parameter, so this mock cannot
        // distinguish the two wire forms.)
        let resp = app(state)
            .oneshot(req("openabdev/openab-slash", Some("key-b0")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        std::fs::remove_file(&path).ok();
    }
}
