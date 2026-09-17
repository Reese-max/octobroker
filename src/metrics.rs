//! Operational metrics for the MCP proxy (Phase 3, #18).
//!
//! Prometheus text exposition on `GET /metrics`:
//! - `octobroker_mcp_requests_total{agent,method,tool,result}` — every /mcp
//!   request, labeled by the frame method (and tool for tools/call) and the
//!   terminal result class.
//! - `octobroker_mcp_denied_total{agent,reason}` — per-agent deny rates,
//!   split by the policy layer that rejected the call.
//! - `octobroker_mcp_upstream_requests_total{result}` — upstream call
//!   outcomes by status class / transport result.
//! - `octobroker_mcp_upstream_duration_seconds` — upstream latency histogram.
//! - `octobroker_mcp_sessions` — live session pins (gauge, read at render).
//! - `octobroker_mcp_circuit_open` — upstream circuit breaker state.
//!
//! Cardinality is bounded: `agent` ids come from operator allowlists,
//! `result`/`reason` are fixed vocabularies, and client-supplied
//! `method`/`tool` labels are length-capped with a fixed-size map plus a
//! "~" overflow bucket.

use std::collections::HashMap;
use std::sync::Mutex;

/// Upstream latency histogram bounds (seconds). The last implied bucket is
/// +Inf; 120s matches the upstream POST timeout bound.
const LATENCY_BOUNDS: [f64; 6] = [0.1, 0.5, 1.0, 5.0, 30.0, 120.0];

#[derive(Default)]
struct Histogram {
    buckets: [u64; LATENCY_BOUNDS.len() + 1],
    sum: f64,
    count: u64,
}

impl Histogram {
    fn observe(&mut self, secs: f64) {
        let idx = LATENCY_BOUNDS
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(LATENCY_BOUNDS.len());
        self.buckets[idx] += 1;
        self.sum += secs;
        self.count += 1;
    }
}

/// Defense against unbounded label cardinality from client-controlled
/// method/tool strings: cap stored label length and total distinct keys.
const MAX_LABEL_LEN: usize = 64;
const MAX_KEYS: usize = 4096;

fn cap_label(s: &str) -> String {
    s.chars().take(MAX_LABEL_LEN).collect()
}

#[derive(Default)]
pub struct Metrics {
    /// (agent, method, tool, result)
    requests: Mutex<HashMap<(String, String, String, String), u64>>,
    /// (agent, reason)
    denied: Mutex<HashMap<(String, String), u64>>,
    /// result class: "2xx" | "4xx" | "5xx" | "transport_error"
    upstream: Mutex<HashMap<String, u64>>,
    upstream_latency: Mutex<Histogram>,
}

/// Request outcome labels for `requests_total`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RequestResult {
    /// Forwarded upstream (any upstream status).
    Forwarded,
    /// Completed locally (octobroker-owned tool, session ops).
    Local,
    /// Rejected by a policy layer before any upstream contact.
    Denied,
    /// Rejected by the quota or circuit breaker.
    Rejected,
    /// Proxy/upstream failure.
    Error,
}

impl RequestResult {
    fn label(self) -> &'static str {
        match self {
            RequestResult::Forwarded => "forwarded",
            RequestResult::Local => "local",
            RequestResult::Denied => "denied",
            RequestResult::Rejected => "rejected",
            RequestResult::Error => "error",
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one /mcp request at its terminal result.
    /// `method` is the JSON-RPC method ("initialize", "tools/call", …) or the
    /// HTTP verb for unparseable/control-plane traffic. `tool` may be empty.
    ///
    /// `method`/`tool` come from request bodies, so cardinality is defended
    /// twice: label values are truncated to MAX_LABEL_LEN, and once the map
    /// holds MAX_KEYS entries unseen keys fold into the "~" overflow bucket.
    pub fn request(&self, agent: &str, method: &str, tool: &str, result: RequestResult) {
        let key = (
            cap_label(agent),
            cap_label(method),
            cap_label(tool),
            result.label().to_string(),
        );
        let mut map = self.requests.lock().unwrap();
        if let Some(n) = map.get_mut(&key) {
            *n += 1;
        } else if map.len() >= MAX_KEYS {
            *map
                .entry(("~".into(), "~".into(), "~".into(), result.label().into()))
                .or_insert(0) += 1;
        } else {
            map.insert(key, 1);
        }
    }

    /// Count one policy rejection; `reason` is a fixed vocabulary:
    /// authn_missing | authn_invalid | iam_invalid | tool_not_allowed |
    /// write_disabled | write_needs_repo_scope | repo_unresolvable |
    /// repo_denied | session_binding | session_unknown | quota |
    /// circuit_open | inflight_cap | audit_unavailable | local_gate
    pub fn denied(&self, agent: &str, reason: &str) {
        let key = (cap_label(agent), cap_label(reason));
        let mut map = self.denied.lock().unwrap();
        if let Some(n) = map.get_mut(&key) {
            *n += 1;
        } else if map.len() >= MAX_KEYS {
            *map.entry(("~".into(), "~".into())).or_insert(0) += 1;
        } else {
            map.insert(key, 1);
        }
    }

    /// Count one upstream call and observe its latency.
    /// `result_class`: "2xx" | "4xx" | "5xx" | "timeout" | "transport_error".
    pub fn upstream(&self, result_class: &str, secs: f64) {
        *self
            .upstream
            .lock()
            .unwrap()
            .entry(result_class.to_string())
            .or_insert(0) += 1;
        self.upstream_latency.lock().unwrap().observe(secs);
    }

    /// Prometheus text exposition. Live gauges are rendered from caller-
    /// supplied snapshots so this registry stays lock-light.
    pub fn render(&self, sessions: u64, circuit_open: bool) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str(
            "# HELP octobroker_mcp_requests_total MCP requests by agent, method, tool, result\n\
             # TYPE octobroker_mcp_requests_total counter\n",
        );
        for ((agent, method, tool, result), count) in sorted(&self.requests.lock().unwrap()) {
            out.push_str(&format!(
                "octobroker_mcp_requests_total{{agent={},method={},tool={},result={}}} {}\n",
                esc(&agent),
                esc(&method),
                esc(&tool),
                esc(&result),
                count
            ));
        }
        out.push_str(
            "# HELP octobroker_mcp_denied_total MCP policy rejections by agent and reason\n\
             # TYPE octobroker_mcp_denied_total counter\n",
        );
        for ((agent, reason), count) in sorted(&self.denied.lock().unwrap()) {
            out.push_str(&format!(
                "octobroker_mcp_denied_total{{agent={},reason={}}} {}\n",
                esc(&agent),
                esc(&reason),
                count
            ));
        }
        out.push_str(
            "# HELP octobroker_mcp_upstream_requests_total Upstream MCP calls by result class\n\
             # TYPE octobroker_mcp_upstream_requests_total counter\n",
        );
        for (class, count) in sorted(&self.upstream.lock().unwrap()) {
            out.push_str(&format!(
                "octobroker_mcp_upstream_requests_total{{result={}}} {}\n",
                esc(&class),
                count
            ));
        }
        let hist = self.upstream_latency.lock().unwrap();
        out.push_str(
            "# HELP octobroker_mcp_upstream_duration_seconds Upstream MCP call latency\n\
             # TYPE octobroker_mcp_upstream_duration_seconds histogram\n",
        );
        let mut cumulative = 0u64;
        for (i, bound) in LATENCY_BOUNDS.iter().enumerate() {
            cumulative += hist.buckets[i];
            out.push_str(&format!(
                "octobroker_mcp_upstream_duration_seconds_bucket{{le=\"{}\"}} {}\n",
                bound, cumulative
            ));
        }
        cumulative += hist.buckets[LATENCY_BOUNDS.len()];
        out.push_str(&format!(
            "octobroker_mcp_upstream_duration_seconds_bucket{{le=\"+Inf\"}} {}\n\
             octobroker_mcp_upstream_duration_seconds_sum {}\n\
             octobroker_mcp_upstream_duration_seconds_count {}\n",
            cumulative, hist.sum, hist.count
        ));
        out.push_str(&format!(
            "# HELP octobroker_mcp_sessions Live pinned MCP sessions\n\
             # TYPE octobroker_mcp_sessions gauge\n\
             octobroker_mcp_sessions {}\n\
             # HELP octobroker_mcp_circuit_open Upstream circuit breaker open\n\
             # TYPE octobroker_mcp_circuit_open gauge\n\
             octobroker_mcp_circuit_open {}\n",
            sessions, circuit_open as u64
        ));
        out
    }
}

fn sorted<K: Ord + Clone, V: Clone>(map: &HashMap<K, V>) -> Vec<(K, V)> {
    let mut v: Vec<(K, V)> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// Quote a label value (Prometheus format): backslash, quote, newline.
fn esc(v: &str) -> String {
    let escaped: String = v
        .chars()
        .flat_map(|c| match c {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' => "\\n".chars().collect(),
            c => vec![c],
        })
        .collect();
    format!("\"{}\"", escaped)
}

/// Map an upstream HTTP status to its result class.
pub fn status_class(status: reqwest::StatusCode) -> &'static str {
    if status.is_success() {
        "2xx"
    } else if status.is_server_error() {
        "5xx"
    } else {
        "4xx"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counters_and_render() {
        let m = Metrics::new();
        m.request("b0", "tools/call", "issue_read", RequestResult::Forwarded);
        m.request("b0", "tools/call", "issue_read", RequestResult::Forwarded);
        m.request("-", "initialize", "", RequestResult::Forwarded);
        m.denied("b0", "tool_not_allowed");
        m.upstream("2xx", 0.04);
        m.upstream("5xx", 1.5);

        let text = m.render(3, false);
        assert!(text.contains(
            "octobroker_mcp_requests_total{agent=\"b0\",method=\"tools/call\",tool=\"issue_read\",result=\"forwarded\"} 2"
        ));
        assert!(text
            .contains("octobroker_mcp_denied_total{agent=\"b0\",reason=\"tool_not_allowed\"} 1"));
        assert!(text.contains("octobroker_mcp_upstream_requests_total{result=\"2xx\"} 1"));
        assert!(text.contains("octobroker_mcp_upstream_requests_total{result=\"5xx\"} 1"));
        assert!(text.contains("octobroker_mcp_sessions 3"));
        assert!(text.contains("octobroker_mcp_circuit_open 0"));
        assert!(text.contains("le=\"0.1\"} 1")); // 0.04 in first bucket
        assert!(text.contains("le=\"+Inf\"} 2")); // cumulative = all
        assert!(text.contains("_count 2"));
        assert!(text.contains("_sum 1.54"));
    }

    #[test]
    fn test_label_escaping() {
        assert_eq!(esc("a\"b"), "\"a\\\"b\"");
        assert_eq!(esc("a\\b"), "\"a\\\\b\"");
        assert_eq!(esc("a\nb"), "\"a\\nb\"");
    }

    #[test]
    fn test_status_class() {
        assert_eq!(status_class(reqwest::StatusCode::OK), "2xx");
        assert_eq!(status_class(reqwest::StatusCode::TOO_MANY_REQUESTS), "4xx");
        assert_eq!(status_class(reqwest::StatusCode::BAD_GATEWAY), "5xx");
    }
}
