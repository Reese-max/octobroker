//! MCP request metrics, per-agent deny rates and upstream latency histograms
//! (Phase 3, #18).
//!
//! Dashboards and alerting need three things the tracing logs do not give a
//! scraper: counters keyed by agent, a latency distribution, and gauges that
//! survive a scrape interval. This module keeps them as lock-free atomics
//! (plus one small mutex for the per-agent breakdown) so instrumenting the
//! proxy hot path costs no `await`.
//!
//! Exposure:
//! - `GET /metrics` — Prometheus text exposition (`render_prometheus`).
//! - `GET /stats` — the same numbers as JSON (`snapshot_json`), alongside the
//!   pool/cache/quota snapshots operators already read.
//!
//! Series come in two shapes so a dashboard can aggregate without parsing
//! labels: `..._by_agent_{requests,denied}` is pre-rolled up per agent (usable
//! directly with `sum by (agent)`), and `..._by_agent_tool_...` keeps the
//! per-tool breakdown. Tool names only reach a metric after the agent
//! allowlist has already accepted them, so the label space stays bounded by
//! configuration; labels are escaped for exposition regardless.
//!
//! Free of `crate::` references so `tests/phase3_operational.rs` can include
//! it directly.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Upper bounds (milliseconds) of the upstream latency histogram buckets.
/// The final `+Inf` bucket is implicit.
pub const LATENCY_BUCKETS_MS: [u64; 9] = [5, 10, 25, 50, 100, 250, 500, 1_000, 2_500];

/// Label used when a request has no authenticated agent (Phase 1
/// network-trust mode) so those requests are counted rather than dropped.
pub const ANONYMOUS_AGENT: &str = "<anonymous>";

/// How the proxy handled one MCP request. Every early return in the handler
/// maps to exactly one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Forwarded upstream (including locally-handled octobroker tools).
    Allowed,
    /// Rejected by policy: tool allowlist, write gate, repo allowlist, session
    /// binding, agent authentication.
    Denied,
    /// Rejected by the per-agent rate limiter or an upstream `Retry-After`.
    QuotaRejected,
    /// Rejected because the agent's upstream circuit is open.
    CircuitOpen,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
            Outcome::QuotaRejected => "quota_rejected",
            Outcome::CircuitOpen => "circuit_open",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AgentCounters {
    pub requests: u64,
    pub allowed: u64,
    pub denied: u64,
    pub quota_rejected: u64,
    pub circuit_open: u64,
    pub upstream_requests: u64,
    pub upstream_errors: u64,
    pub upstream_latency_ms_sum: u64,
}

impl AgentCounters {
    fn merge(&mut self, other: &AgentCounters) {
        self.requests += other.requests;
        self.allowed += other.allowed;
        self.denied += other.denied;
        self.quota_rejected += other.quota_rejected;
        self.circuit_open += other.circuit_open;
        self.upstream_requests += other.upstream_requests;
        self.upstream_errors += other.upstream_errors;
        self.upstream_latency_ms_sum += other.upstream_latency_ms_sum;
    }

    fn to_json(self) -> Value {
        json!({
            "requests": self.requests,
            "allowed": self.allowed,
            "denied": self.denied,
            "quota_rejected": self.quota_rejected,
            "circuit_open": self.circuit_open,
            "upstream_requests": self.upstream_requests,
            "upstream_errors": self.upstream_errors,
            "upstream_latency_ms_sum": self.upstream_latency_ms_sum,
        })
    }
}

type SeriesKey = (String, String);

/// Process-wide MCP observability counters.
pub struct Metrics {
    requests: AtomicU64,
    allowed: AtomicU64,
    denied: AtomicU64,
    quota_rejected: AtomicU64,
    circuit_open: AtomicU64,
    upstream_requests: AtomicU64,
    upstream_errors: AtomicU64,
    upstream_latency_ms_sum: AtomicU64,
    upstream_latency_ms_count: AtomicU64,
    latency_buckets: [AtomicU64; LATENCY_BUCKETS_MS.len()],
    series: Mutex<HashMap<SeriesKey, AgentCounters>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            quota_rejected: AtomicU64::new(0),
            circuit_open: AtomicU64::new(0),
            upstream_requests: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            upstream_latency_ms_sum: AtomicU64::new(0),
            upstream_latency_ms_count: AtomicU64::new(0),
            latency_buckets: Default::default(),
            series: Mutex::new(HashMap::new()),
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one MCP request by how it was handled.
    pub fn observe_mcp(&self, agent: Option<&str>, tool: Option<&str>, outcome: Outcome) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        match outcome {
            Outcome::Allowed => {
                self.allowed.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Denied => {
                self.denied.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::QuotaRejected => {
                self.quota_rejected.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::CircuitOpen => {
                self.circuit_open.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut series = self.lock();
        let counters = series
            .entry(series_key(agent, tool))
            .or_default();
        counters.requests += 1;
        match outcome {
            Outcome::Allowed => counters.allowed += 1,
            Outcome::Denied => counters.denied += 1,
            Outcome::QuotaRejected => counters.quota_rejected += 1,
            Outcome::CircuitOpen => counters.circuit_open += 1,
        }
    }

    /// Count one upstream exchange. `status` is the HTTP status actually
    /// observed (0 when the request never produced one).
    pub fn observe_upstream(&self, agent: Option<&str>, latency_ms: u64, status: u16) {
        self.upstream_requests.fetch_add(1, Ordering::Relaxed);
        self.upstream_latency_ms_sum
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.upstream_latency_ms_count
            .fetch_add(1, Ordering::Relaxed);
        let failed = !(200..400).contains(&status);
        if failed {
            self.upstream_errors.fetch_add(1, Ordering::Relaxed);
        }
        for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if latency_ms <= *bound {
                self.latency_buckets[index].fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut series = self.lock();
        let counters = series.entry(series_key(agent, None)).or_default();
        counters.upstream_requests += 1;
        counters.upstream_latency_ms_sum += latency_ms;
        if failed {
            counters.upstream_errors += 1;
        }
    }

    /// Cumulative bucket counters (cumulative, as Prometheus expects).
    pub fn latency_bucket_counts(&self) -> Vec<u64> {
        self.latency_buckets
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect()
    }

    /// Per-agent roll-up across tools, plus the raw per-tool series.
    pub fn by_agent(&self) -> Vec<(String, AgentCounters)> {
        let series = self.lock();
        let mut rolled: HashMap<String, AgentCounters> = HashMap::new();
        for ((agent, _), counters) in series.iter() {
            rolled.entry(agent.clone()).or_default().merge(counters);
        }
        let mut out: Vec<(String, AgentCounters)> = rolled.into_iter().collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// JSON view, embedded in `/stats`.
    pub fn snapshot_json(&self) -> Value {
        // Two separate acquisitions of the same lock: `by_agent` locks too, and
        // std::sync::Mutex is not reentrant.
        let by_agent_tool = {
            let series = self.lock();
            let mut map = serde_json::Map::new();
            let mut keys: Vec<&SeriesKey> = series.keys().collect();
            keys.sort();
            for key in keys {
                map.insert(format!("{}/{}", key.0, key.1), series[key].to_json());
            }
            map
        };
        let by_agent = self.by_agent();
        let by_agent: serde_json::Map<String, Value> = by_agent
            .into_iter()
            .map(|(agent, counters)| (agent, counters.to_json()))
            .collect();
        json!({
            "mcp": {
                "requests": self.requests.load(Ordering::Relaxed),
                "allowed": self.allowed.load(Ordering::Relaxed),
                "denied": self.denied.load(Ordering::Relaxed),
                "quota_rejected": self.quota_rejected.load(Ordering::Relaxed),
                "circuit_open": self.circuit_open.load(Ordering::Relaxed),
                "upstream": {
                    "requests": self.upstream_requests.load(Ordering::Relaxed),
                    "errors": self.upstream_errors.load(Ordering::Relaxed),
                    "latency_ms": {
                        "count": self.upstream_latency_ms_count.load(Ordering::Relaxed),
                        "sum": self.upstream_latency_ms_sum.load(Ordering::Relaxed),
                        "buckets": bucket_view(&self.latency_bucket_counts()),
                    },
                },
                "by_agent": Value::Object(by_agent),
                "by_agent_tool": Value::Object(by_agent_tool),
            }
        })
    }

    /// Prometheus text exposition for `GET /metrics`.
    pub fn render_prometheus(&self) -> String {
        let counts = self.latency_bucket_counts();
        let mut out = String::with_capacity(4096);

        counter(
            &mut out,
            "octobroker_mcp_requests_total",
            "MCP requests handled, all outcomes.",
            self.requests.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "octobroker_mcp_allowed_total",
            "MCP requests forwarded upstream.",
            self.allowed.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "octobroker_mcp_denied_total",
            "MCP requests rejected by agent policy.",
            self.denied.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "octobroker_mcp_quota_rejected_total",
            "MCP requests rejected by the per-agent rate limiter.",
            self.quota_rejected.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "octobroker_mcp_circuit_open_total",
            "MCP requests rejected because the agent's upstream circuit was open.",
            self.circuit_open.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "octobroker_mcp_upstream_requests_total",
            "Upstream MCP exchanges attempted.",
            self.upstream_requests.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "octobroker_mcp_upstream_errors_total",
            "Upstream MCP exchanges that returned a non-2xx/3xx status or none at all.",
            self.upstream_errors.load(Ordering::Relaxed),
        );

        out.push_str("# HELP octobroker_mcp_upstream_latency_ms_bucket Upstream MCP exchange latency in milliseconds (cumulative).\n# TYPE octobroker_mcp_upstream_latency_ms_bucket histogram\n");
        for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            out.push_str(&format!(
                "octobroker_mcp_upstream_latency_ms_bucket{{le=\"{}\"}} {}\n",
                bound, counts[index]
            ));
        }
        out.push_str(&format!(
            "octobroker_mcp_upstream_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            self.upstream_latency_ms_count.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP octobroker_mcp_upstream_latency_ms_sum Cumulative upstream MCP exchange latency in milliseconds.\n# TYPE octobroker_mcp_upstream_latency_ms_sum counter\n");
        out.push_str(&format!(
            "octobroker_mcp_upstream_latency_ms_sum {}\n",
            self.upstream_latency_ms_sum.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP octobroker_mcp_upstream_latency_ms_count Upstream MCP exchanges observed.\n# TYPE octobroker_mcp_upstream_latency_ms_count counter\n");
        out.push_str(&format!(
            "octobroker_mcp_upstream_latency_ms_count {}\n",
            self.upstream_latency_ms_count.load(Ordering::Relaxed)
        ));

        for (name, help) in [
            (
                "octobroker_mcp_by_agent_requests_total",
                "MCP requests handled, rolled up by agent id.",
            ),
            (
                "octobroker_mcp_by_agent_denied_total",
                "MCP requests rejected by policy, rolled up by agent id.",
            ),
            (
                "octobroker_mcp_by_agent_quota_rejected_total",
                "MCP requests rejected by the rate limiter, rolled up by agent id.",
            ),
            (
                "octobroker_mcp_by_agent_circuit_open_total",
                "MCP requests rejected by an open circuit, rolled up by agent id.",
            ),
            (
                "octobroker_mcp_by_agent_upstream_requests_total",
                "Upstream MCP exchanges attempted, rolled up by agent id.",
            ),
            (
                "octobroker_mcp_by_agent_upstream_errors_total",
                "Upstream MCP exchanges that failed, rolled up by agent id.",
            ),
            (
                "octobroker_mcp_by_agent_upstream_latency_ms_sum",
                "Cumulative upstream latency in milliseconds, rolled up by agent id.",
            ),
        ] {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
        }
        for (agent, counters) in self.by_agent() {
            let agent = escape_label(&agent);
            let fields: [(&str, &str, u64); 7] = [
                ("requests", "requests_total", counters.requests),
                ("denied", "denied_total", counters.denied),
                (
                    "quota_rejected",
                    "quota_rejected_total",
                    counters.quota_rejected,
                ),
                ("circuit_open", "circuit_open_total", counters.circuit_open),
                (
                    "upstream_requests",
                    "upstream_requests_total",
                    counters.upstream_requests,
                ),
                (
                    "upstream_errors",
                    "upstream_errors_total",
                    counters.upstream_errors,
                ),
                (
                    "upstream_latency_ms_sum",
                    "upstream_latency_ms_sum",
                    counters.upstream_latency_ms_sum,
                ),
            ];
            for (_, suffix, value) in fields {
                out.push_str(&format!(
                    "octobroker_mcp_by_agent_{suffix}{{agent=\"{agent}\"}} {value}\n"
                ));
            }
        }

        out.push_str("# HELP octobroker_mcp_by_agent_tool_requests_total MCP requests handled, by agent id and tool name.\n# TYPE octobroker_mcp_by_agent_tool_requests_total counter\n");
        out.push_str("# HELP octobroker_mcp_by_agent_tool_denied_total MCP requests rejected by policy, by agent id and tool name.\n# TYPE octobroker_mcp_by_agent_tool_denied_total counter\n");
        let series = self.lock();
        let mut entries: Vec<(&SeriesKey, &AgentCounters)> = series.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for ((agent, tool), counters) in entries {
            if counters.requests == 0 {
                continue;
            }
            out.push_str(&format!(
                "octobroker_mcp_by_agent_tool_requests_total{{agent=\"{}\",tool=\"{}\"}} {}\n",
                escape_label(agent),
                escape_label(tool),
                counters.requests
            ));
            out.push_str(&format!(
                "octobroker_mcp_by_agent_tool_denied_total{{agent=\"{}\",tool=\"{}\"}} {}\n",
                escape_label(agent),
                escape_label(tool),
                counters.denied
            ));
        }
        out
    }

    /// Zero every counter (test support).
    pub fn reset(&self) {
        for counter in [
            &self.requests,
            &self.allowed,
            &self.denied,
            &self.quota_rejected,
            &self.circuit_open,
            &self.upstream_requests,
            &self.upstream_errors,
            &self.upstream_latency_ms_sum,
            &self.upstream_latency_ms_count,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        for bucket in &self.latency_buckets {
            bucket.store(0, Ordering::Relaxed);
        }
        self.lock().clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SeriesKey, AgentCounters>> {
        self.series
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
    out.push_str(&format!("{name} {value}\n"));
}

/// Series key: agent label plus tool label (empty when the request named none).
fn series_key(agent: Option<&str>, tool: Option<&str>) -> SeriesKey {
    (
        agent.unwrap_or(ANONYMOUS_AGENT).to_string(),
        tool.unwrap_or("").to_string(),
    )
}

fn bucket_view(counts: &[u64]) -> Value {
    let mut map = serde_json::Map::new();
    for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
        map.insert(bound.to_string(), json!(counts[index]));
    }
    Value::Object(map)
}

/// Neutralise `\\` and `\"` in an exposition line so a label's real quote
/// count can be checked.
fn unescape_prometheus_labels(series: &str) -> String {
    let mut out = String::with_capacity(series.len());
    let mut chars = series.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                chars.next();
                out.push('\u{0}');
            }
            other => out.push(other),
        }
    }
    out
}

/// Escape a Prometheus label value: backslash, double quote and newline.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_buckets_are_cumulative() {
        let m = Metrics::new();
        m.observe_upstream(Some("a"), 7, 200);
        m.observe_upstream(Some("a"), 2_600, 200);
        let counts = m.latency_bucket_counts();
        // 7ms lands in every bucket >= 7; 2600ms only in the 2500ms one.
        assert_eq!(counts[0], 0);
        assert_eq!(counts[1], 1);
        assert_eq!(counts[8], 1);
        assert_eq!(m.snapshot_json()["mcp"]["upstream"]["latency_ms"]["count"], 2);
    }

    #[test]
    fn test_tool_name_is_a_separate_label_from_the_agent_rollup() {
        let m = Metrics::new();
        m.observe_mcp(Some("bot-a"), Some("get_me"), Outcome::Allowed);
        m.observe_mcp(Some("bot-a"), Some("create_issue"), Outcome::Denied);
        let snap = m.snapshot_json();
        assert_eq!(snap["mcp"]["by_agent"]["bot-a"]["requests"], 2);
        assert_eq!(snap["mcp"]["by_agent"]["bot-a"]["denied"], 1);
        assert_eq!(snap["mcp"]["by_agent_tool"]["bot-a/get_me"]["requests"], 1);
        assert_eq!(snap["mcp"]["by_agent_tool"]["bot-a/create_issue"]["denied"], 1);
    }

    #[test]
    fn test_render_prometheus_uses_two_label_shapes() {
        let m = Metrics::new();
        m.observe_mcp(Some("bot-a"), Some("get_me"), Outcome::Allowed);
        m.observe_mcp(Some("bot-a"), Some("delete_file"), Outcome::Denied);
        let text = m.render_prometheus();
        assert!(text
            .contains("octobroker_mcp_by_agent_denied_total{agent=\"bot-a\"} 1"));
        assert!(text.contains(
            "octobroker_mcp_by_agent_tool_denied_total{agent=\"bot-a\",tool=\"delete_file\"} 1"
        ));
    }

    #[test]
    fn test_label_escaping_cannot_break_exposition() {
        let m = Metrics::new();
        m.observe_mcp(Some("we\"ird\\agent"), None, Outcome::Denied);
        let text = m.render_prometheus();
        assert!(text.contains("octobroker_mcp_by_agent_denied_total{agent=\"we\\\"ird\\\\agent\"} 1"));
        for line in text.lines() {
            if line.starts_with('#') {
                continue;
            }
            let (series, value) = line
                .rsplit_once(' ')
                .unwrap_or_else(|| panic!("sample without a value: {line}"));
            assert!(
                value.parse::<f64>().is_ok(),
                "sample value is not numeric: {line}"
            );
            // Label escaping: neutralise escape sequences, then the remaining
            // quotes must be balanced (two per label value).
            let unescaped = unescape_prometheus_labels(series);
            assert_eq!(
                unescaped.matches('"').count() % 2,
                0,
                "unbalanced label quotes: {line}"
            );
        }
    }

    #[test]
    fn test_upstream_errors_exclude_2xx_and_3xx() {
        let m = Metrics::new();
        m.observe_upstream(Some("a"), 1, 200);
        m.observe_upstream(Some("a"), 1, 302);
        m.observe_upstream(Some("a"), 1, 503);
        m.observe_upstream(Some("a"), 1, 0);
        assert_eq!(m.snapshot_json()["mcp"]["upstream"]["errors"], 2);
        assert_eq!(m.by_agent()[0].1.upstream_requests, 4);
    }

    #[test]
    fn test_outcome_names_are_stable() {
        assert_eq!(Outcome::Allowed.as_str(), "allowed");
        assert_eq!(Outcome::Denied.as_str(), "denied");
        assert_eq!(Outcome::QuotaRejected.as_str(), "quota_rejected");
        assert_eq!(Outcome::CircuitOpen.as_str(), "circuit_open");
    }
}