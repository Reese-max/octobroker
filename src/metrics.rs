//! MCP operational metrics (Phase 3, #18) — dashboards + alerting input.
//!
//! Exposed two ways:
//! - `GET /metrics` — Prometheus text exposition (scrape → Grafana/alerts).
//! - `GET /stats` JSON — same counters embedded under the `mcp` key.
//!
//! Cardinality is deliberately bounded: `agent` is a configured id (or
//! `anonymous` for network-trust mode), `kind`/`reason`/`result` are fixed
//! enums below — JSON-RPC method strings are bucketed, never emitted raw.

use std::collections::HashMap;
use std::sync::Mutex;

/// Request kind buckets for `octobroker_mcp_requests_total`.
pub fn request_kind(method: Option<&str>, http_method: &str) -> &'static str {
    if http_method == "GET" {
        return "stream_get";
    }
    if http_method == "DELETE" {
        return "session_delete";
    }
    match method.unwrap_or("") {
        "initialize" => "initialize",
        "tools/call" => "tools_call",
        "tools/list" => "tools_list",
        m if m.starts_with("notifications/") => "notification",
        _ => "other",
    }
}

/// Denial reasons for `octobroker_mcp_denied_total`.
pub mod deny {
    pub const POLICY: &str = "policy"; // tool/repo/write gate
    pub const AUTH: &str = "auth"; // bad/missing key or IAM token
    pub const QUOTA: &str = "quota"; // per-agent rate bucket
    pub const SESSION: &str = "session"; // unknown/expired/foreign session
    pub const BREAKER: &str = "breaker"; // upstream circuit open
    pub const AUDIT: &str = "audit"; // fail-closed audit loss
    pub const INFLIGHT: &str = "inflight"; // write concurrency cap
}

/// Upstream latency histogram buckets (ms, cumulative `le=`).
const LATENCY_BUCKETS_MS: [u64; 8] = [50, 100, 250, 500, 1000, 2500, 5000, 120_000];

#[derive(Default)]
struct Inner {
    /// (agent, kind) → count
    requests: HashMap<(String, &'static str), u64>,
    /// (agent, reason) → count
    denied: HashMap<(String, &'static str), u64>,
    upstream_requests: u64,
    /// Transport errors, 429s and 5xx — what the breaker counts.
    upstream_failures: u64,
    /// Errors while streaming an already-committed response body.
    upstream_stream_errors: u64,
    upstream_latency_ms_total: u64,
    upstream_latency_buckets: [u64; LATENCY_BUCKETS_MS.len()],
    iam_auth_success: u64,
    iam_auth_failure: u64,
}

pub struct McpMetrics {
    inner: Mutex<Inner>,
}

impl McpMetrics {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn record_request(&self, agent: &str, kind: &'static str) {
        let mut i = self.inner.lock().unwrap();
        *i.requests.entry((agent.to_string(), kind)).or_insert(0) += 1;
    }

    pub fn record_denied(&self, agent: &str, reason: &'static str) {
        let mut i = self.inner.lock().unwrap();
        *i.denied.entry((agent.to_string(), reason)).or_insert(0) += 1;
    }

    /// Every upstream forward (request resolved to headers or failed).
    /// `failure` = transport error / 429 / 5xx — matches the breaker's rule.
    pub fn record_upstream(&self, latency_ms: u64, failure: bool) {
        let mut i = self.inner.lock().unwrap();
        i.upstream_requests += 1;
        if failure {
            i.upstream_failures += 1;
        }
        i.upstream_latency_ms_total += latency_ms;
        for (idx, le) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if latency_ms <= *le {
                i.upstream_latency_buckets[idx] += 1;
            }
        }
    }

    /// Response body stream errored mid-body (headers were already
    /// committed — a truncated/aborted upstream body).
    pub fn record_stream_error(&self) {
        self.inner.lock().unwrap().upstream_stream_errors += 1;
    }

    pub fn record_iam_auth(&self, success: bool) {
        let mut i = self.inner.lock().unwrap();
        if success {
            i.iam_auth_success += 1;
        } else {
            i.iam_auth_failure += 1;
        }
    }

    /// JSON snapshot for `/stats` (under the `mcp` key).
    pub fn snapshot(
        &self,
        sessions_pinned: u64,
        circuit_open: bool,
        circuit_opens: u64,
    ) -> serde_json::Value {
        let i = self.inner.lock().unwrap();
        let requests: serde_json::Map<String, serde_json::Value> = i
            .requests
            .iter()
            .map(|((a, k), v)| (format!("{}:{}", a, k), serde_json::json!(v)))
            .collect();
        let denied: serde_json::Map<String, serde_json::Value> = i
            .denied
            .iter()
            .map(|((a, r), v)| (format!("{}:{}", a, r), serde_json::json!(v)))
            .collect();
        serde_json::json!({
            "requests": requests,
            "denied": denied,
            "upstream": {
                "requests": i.upstream_requests,
                "failures": i.upstream_failures,
                "stream_errors": i.upstream_stream_errors,
                "latency_ms_total": i.upstream_latency_ms_total,
                "latency_ms_avg": i
                    .upstream_latency_ms_total
                    .checked_div(i.upstream_requests)
                    .unwrap_or(0),
            },
            "circuit": { "open": circuit_open, "opens": circuit_opens },
            "sessions_pinned": sessions_pinned,
            "iam_auth": { "success": i.iam_auth_success, "failure": i.iam_auth_failure },
        })
    }

    /// Prometheus text exposition.
    pub fn prometheus(
        &self,
        sessions_pinned: u64,
        circuit_open: bool,
        circuit_opens: u64,
    ) -> String {
        let i = self.inner.lock().unwrap();
        let mut out = String::with_capacity(4096);

        out.push_str("# HELP octobroker_mcp_requests_total MCP requests by agent and frame kind\n");
        out.push_str("# TYPE octobroker_mcp_requests_total counter\n");
        let mut entries: Vec<_> = i.requests.iter().collect();
        entries.sort_by_key(|((a, k), _)| (a.clone(), *k));
        for ((agent, kind), v) in entries {
            out.push_str(&format!(
                "octobroker_mcp_requests_total{{agent=\"{}\",kind=\"{}\"}} {}\n",
                esc(agent),
                kind,
                v
            ));
        }

        out.push_str("# HELP octobroker_mcp_denied_total MCP denials by agent and reason\n");
        out.push_str("# TYPE octobroker_mcp_denied_total counter\n");
        let mut denied: Vec<_> = i.denied.iter().collect();
        denied.sort_by_key(|((a, r), _)| (a.clone(), *r));
        for ((agent, reason), v) in denied {
            out.push_str(&format!(
                "octobroker_mcp_denied_total{{agent=\"{}\",reason=\"{}\"}} {}\n",
                esc(agent),
                reason,
                v
            ));
        }

        out.push_str("# HELP octobroker_mcp_upstream_requests_total Upstream MCP forwards\n");
        out.push_str("# TYPE octobroker_mcp_upstream_requests_total counter\n");
        out.push_str(&format!(
            "octobroker_mcp_upstream_requests_total {}\n",
            i.upstream_requests
        ));
        out.push_str(
            "# HELP octobroker_mcp_upstream_failures_total Upstream failures (transport/429/5xx)\n",
        );
        out.push_str("# TYPE octobroker_mcp_upstream_failures_total counter\n");
        out.push_str(&format!(
            "octobroker_mcp_upstream_failures_total {}\n",
            i.upstream_failures
        ));
        out.push_str(
            "# HELP octobroker_mcp_upstream_stream_errors_total Mid-body upstream stream aborts\n",
        );
        out.push_str("# TYPE octobroker_mcp_upstream_stream_errors_total counter\n");
        out.push_str(&format!(
            "octobroker_mcp_upstream_stream_errors_total {}\n",
            i.upstream_stream_errors
        ));

        out.push_str("# HELP octobroker_mcp_upstream_latency_ms Upstream latency histogram (ms)\n");
        out.push_str("# TYPE octobroker_mcp_upstream_latency_ms histogram\n");
        for (idx, le) in LATENCY_BUCKETS_MS.iter().enumerate() {
            out.push_str(&format!(
                "octobroker_mcp_upstream_latency_ms_bucket{{le=\"{}\"}} {}\n",
                le, i.upstream_latency_buckets[idx]
            ));
        }
        out.push_str(&format!(
            "octobroker_mcp_upstream_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            i.upstream_requests
        ));
        out.push_str(&format!(
            "octobroker_mcp_upstream_latency_ms_sum {}\n",
            i.upstream_latency_ms_total
        ));
        out.push_str(&format!(
            "octobroker_mcp_upstream_latency_ms_count {}\n",
            i.upstream_requests
        ));

        out.push_str(
            "# HELP octobroker_mcp_circuit_open Upstream circuit breaker open (1) or closed (0)\n",
        );
        out.push_str("# TYPE octobroker_mcp_circuit_open gauge\n");
        out.push_str(&format!(
            "octobroker_mcp_circuit_open {}\n",
            circuit_open as u8
        ));
        out.push_str("# HELP octobroker_mcp_circuit_opens_total Breaker open events\n");
        out.push_str("# TYPE octobroker_mcp_circuit_opens_total counter\n");
        out.push_str(&format!(
            "octobroker_mcp_circuit_opens_total {}\n",
            circuit_opens
        ));

        out.push_str("# HELP octobroker_mcp_sessions_pinned Pinned MCP sessions (this replica)\n");
        out.push_str("# TYPE octobroker_mcp_sessions_pinned gauge\n");
        out.push_str(&format!(
            "octobroker_mcp_sessions_pinned {}\n",
            sessions_pinned
        ));

        out.push_str("# HELP octobroker_mcp_iam_auth_total SigV4 IAM proof exchanges by result\n");
        out.push_str("# TYPE octobroker_mcp_iam_auth_total counter\n");
        out.push_str(&format!(
            "octobroker_mcp_iam_auth_total{{result=\"success\"}} {}\n",
            i.iam_auth_success
        ));
        out.push_str(&format!(
            "octobroker_mcp_iam_auth_total{{result=\"failure\"}} {}\n",
            i.iam_auth_failure
        ));
        out
    }
}

/// Escape a Prometheus label value (agent ids are operator-configured).
fn esc(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
