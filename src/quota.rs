//! Per-agent rate quotas, upstream circuit breaking and retry policy for the
//! MCP proxy (Phase 3, #18).
//!
//! Noisy-neighbour protection has three independent layers:
//!
//! 1. **Token bucket** — a sustained per-minute rate with a burst allowance,
//!    so one agent cannot monopolise the shared proxy.
//! 2. **Circuit breaker** — after a run of upstream failures, an agent's
//!    traffic stops hitting the upstream entirely until a half-open probe
//!    succeeds. This bounds both latency and load during an upstream incident.
//! 3. **`Retry-After` cooldown** — when the upstream throttles, the agent's
//!    bucket is suppressed for the advertised interval (clamped to a cap so a
//!    hostile or mistaken upstream cannot park an agent for a day).
//!
//! Retries are deliberately *not* implemented here as a blind loop: the proxy
//! only retries frames it has classified as idempotent reads, and
//! [`backoff_ms`] is the shared, capped, deterministic exponential schedule
//! they use. Non-idempotent (write-classified) calls are never retried — that
//! invariant is enforced at the call site in `mcp.rs` and covered by tests.
//!
//! Free of `crate::` references so `tests/phase3_operational.rs` can include
//! it directly.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Ceiling applied to an upstream `Retry-After` before it is used to suppress
/// an agent.
pub const DEFAULT_RETRY_AFTER_CAP_SECS: u64 = 120;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct QuotaConfig {
    /// Master switch: when false every `check` allows (but failures, circuit
    /// state and metrics are still recorded so enabling is observable).
    pub enabled: bool,
    /// Sustained allowance per agent, requests per minute.
    pub per_agent_per_min: f64,
    /// Bucket capacity: the largest instantaneous burst an agent may spend.
    pub per_agent_burst: f64,
    /// Ceiling for an upstream-advertised `Retry-After`.
    pub retry_after_cap_secs: u64,
    /// Consecutive upstream failures that open the circuit.
    pub circuit_failure_threshold: u32,
    /// How long the circuit stays open before admitting one half-open probe.
    pub circuit_cooldown_secs: u64,
    /// Consecutive half-open successes needed to close the circuit again.
    pub circuit_half_open_successes: u32,
    /// Max attempts for an idempotent read (1 = no retry).
    pub retry_max_attempts: u32,
    /// First retry delay; doubles per attempt.
    pub retry_base_backoff_ms: u64,
    /// Ceiling for the retry delay.
    pub retry_max_backoff_ms: u64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_agent_per_min: 240.0,
            per_agent_burst: 60.0,
            retry_after_cap_secs: DEFAULT_RETRY_AFTER_CAP_SECS,
            circuit_failure_threshold: 5,
            circuit_cooldown_secs: 30,
            circuit_half_open_successes: 1,
            retry_max_attempts: 3,
            retry_base_backoff_ms: 100,
            retry_max_backoff_ms: 2_000,
        }
    }
}

impl QuotaConfig {
    /// Reject configurations that would make the limiter meaningless or
    /// unbounded. Checked at startup; a failure aborts boot.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if !(self.per_agent_per_min.is_finite() && self.per_agent_per_min > 0.0) {
            return Err("mcp.quota.per_agent_per_min must be a positive number".into());
        }
        if !(self.per_agent_burst.is_finite() && self.per_agent_burst >= 1.0) {
            return Err("mcp.quota.per_agent_burst must be at least 1 request".into());
        }
        if self.retry_after_cap_secs == 0 {
            return Err("mcp.quota.retry_after_cap_secs must be positive".into());
        }
        if self.circuit_failure_threshold == 0 {
            return Err("mcp.quota.circuit_failure_threshold must be at least 1".into());
        }
        if self.circuit_half_open_successes == 0 {
            return Err("mcp.quota.circuit_half_open_successes must be at least 1".into());
        }
        if self.retry_max_attempts == 0 {
            return Err("mcp.quota.retry_max_attempts must be at least 1".into());
        }
        if self.retry_base_backoff_ms == 0 {
            return Err("mcp.quota.retry_base_backoff_ms must be positive".into());
        }
        if self.retry_base_backoff_ms > self.retry_max_backoff_ms {
            return Err("mcp.quota.retry_base_backoff_ms must not exceed retry_max_backoff_ms".into());
        }
        Ok(())
    }

    /// Token refill per millisecond for one agent.
    fn refill_per_ms(&self) -> f64 {
        self.per_agent_per_min / 60_000.0
    }
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// Outcome of a pre-dispatch admission check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Local rate limit exceeded.
    Throttled { retry_after_secs: u64 },
    /// Upstream circuit is open; no request will be attempted.
    CircuitOpen { retry_after_secs: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Circuit {
    Closed,
    Open { until_ms: u64 },
    /// Cooldown elapsed: one probe is admitted, further traffic is refused
    /// until that probe reports back.
    HalfOpen { probe_in_flight: bool, successes: u32 },
}

struct AgentState {
    tokens: f64,
    last_refill_ms: u64,
    consecutive_failures: u32,
    circuit: Circuit,
    cooldown_until_ms: u64,
    allowed: u64,
    rejected: u64,
}

impl AgentState {
    fn new(burst: f64, now_ms: u64) -> Self {
        Self {
            tokens: burst,
            last_refill_ms: now_ms,
            consecutive_failures: 0,
            circuit: Circuit::Closed,
            cooldown_until_ms: 0,
            allowed: 0,
            rejected: 0,
        }
    }
}

/// Per-agent quota and circuit state for the whole process.
pub struct QuotaRegistry {
    config: QuotaConfig,
    agents: Mutex<HashMap<String, AgentState>>,
}

impl QuotaRegistry {
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config,
            agents: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &QuotaConfig {
        &self.config
    }

    /// Admission decision for one request from `agent`. Consumes a token when
    /// the request is admitted, so the caller must call this exactly once per
    /// upstream attempt.
    pub fn check(&self, agent: &str, now_ms: u64) -> Decision {
        if !self.config.enabled {
            return Decision::Allow;
        }
        let mut agents = self.lock();
        let burst = self.config.per_agent_burst;
        let state = agents
            .entry(agent.to_string())
            .or_insert_with(|| AgentState::new(burst, now_ms));
        refill(state, &self.config, now_ms);

        match state.circuit {
            Circuit::Open { until_ms } if now_ms < until_ms => {
                state.rejected += 1;
                Decision::CircuitOpen {
                    retry_after_secs: ceil_secs(until_ms.saturating_sub(now_ms)),
                }
            }
            Circuit::Open { .. } => {
                // Cooldown elapsed: transition to half-open and let exactly one
                // probe through. The probe is claimed here, not in the
                // `HalfOpen` arm below, so the first post-cooldown request is
                // the one that holds the slot.
                state.circuit = Circuit::HalfOpen {
                    probe_in_flight: true,
                    successes: 0,
                };
                spend_token(state, &self.config)
            }
            Circuit::HalfOpen { probe_in_flight, .. } if probe_in_flight => {
                state.rejected += 1;
                Decision::CircuitOpen {
                    retry_after_secs: self.config.circuit_cooldown_secs,
                }
            }
            Circuit::HalfOpen { .. } => {
                if let Circuit::HalfOpen { probe_in_flight, .. } = &mut state.circuit {
                    *probe_in_flight = true;
                }
                spend_token(state, &self.config)
            }
            Circuit::Closed => spend_token(state, &self.config),
        }
    }

    /// Report a successful upstream exchange: refills nothing, but clears the
    /// failure run and closes a half-open circuit.
    pub fn record_success(&self, agent: &str, now_ms: u64) {
        let mut agents = self.lock();
        let burst = self.config.per_agent_burst;
        let state = agents
            .entry(agent.to_string())
            .or_insert_with(|| AgentState::new(burst, now_ms));
        state.consecutive_failures = 0;
        if let Circuit::HalfOpen {
            probe_in_flight,
            successes,
        } = &mut state.circuit
        {
            *probe_in_flight = false;
            *successes += 1;
            if *successes >= self.config.circuit_half_open_successes {
                state.circuit = Circuit::Closed;
            }
        }
    }

    /// Report an upstream failure (transport error or 5xx). Opens the circuit
    /// once the threshold is reached; a failed half-open probe re-opens it
    /// immediately with a fresh cooldown.
    pub fn record_upstream_failure(&self, agent: &str, now_ms: u64) {
        let mut agents = self.lock();
        let burst = self.config.per_agent_burst;
        let state = agents
            .entry(agent.to_string())
            .or_insert_with(|| AgentState::new(burst, now_ms));
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let was_half_open = matches!(state.circuit, Circuit::HalfOpen { .. });
        if was_half_open || state.consecutive_failures >= self.config.circuit_failure_threshold {
            state.circuit = Circuit::Open {
                until_ms: now_ms + self.config.circuit_cooldown_secs * 1000,
            };
            state.cooldown_until_ms = now_ms + self.config.circuit_cooldown_secs * 1000;
        }
    }

    /// Report an upstream 429. Suppresses the agent for the advertised
    /// interval (or `retry_after_cap_secs` when the upstream gives no usable
    /// value). Returns the effective cooldown actually applied.
    ///
    /// A cooldown only ever *extends*: a later response advertising a shorter
    /// `Retry-After` must not release an agent that an earlier, longer
    /// cooldown is still holding.
    pub fn record_upstream_throttle(
        &self,
        agent: &str,
        retry_after_secs: Option<u64>,
        now_ms: u64,
    ) -> u64 {
        let cap = self.config.retry_after_cap_secs;
        let applied = retry_after_secs.unwrap_or(cap).min(cap).max(1);
        let mut agents = self.lock();
        let burst = self.config.per_agent_burst;
        let state = agents
            .entry(agent.to_string())
            .or_insert_with(|| AgentState::new(burst, now_ms));
        state.tokens = 0.0;
        state.cooldown_until_ms = state.cooldown_until_ms.max(now_ms + applied * 1000);
        applied
    }

    /// Observable per-agent state for `/stats` and the dashboards.
    pub fn snapshot(&self) -> Vec<AgentQuotaSnapshot> {
        let agents = self.lock();
        let mut out: Vec<AgentQuotaSnapshot> = agents
            .iter()
            .map(|(agent, state)| AgentQuotaSnapshot {
                agent: agent.clone(),
                tokens: state.tokens,
                consecutive_failures: state.consecutive_failures,
                circuit_open: !matches!(state.circuit, Circuit::Closed),
                cooldown_until_ms: state.cooldown_until_ms,
                allowed: state.allowed,
                rejected: state.rejected,
            })
            .collect();
        out.sort_by(|a, b| a.agent.cmp(&b.agent));
        out
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, AgentState>> {
        self.agents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn spend_token(state: &mut AgentState, config: &QuotaConfig) -> Decision {
    // An upstream-advertised cooldown wins over the token bucket.
    if state.cooldown_until_ms > state.last_refill_ms {
        state.rejected += 1;
        return Decision::Throttled {
            retry_after_secs: ceil_secs(state.cooldown_until_ms.saturating_sub(state.last_refill_ms)),
        };
    }
    if state.tokens < 1.0 {
        state.rejected += 1;
        return Decision::Throttled {
            retry_after_secs: ceil_secs(((1.0 - state.tokens) / config.refill_per_ms().max(f64::MIN_POSITIVE)) as u64),
        };
    }
    state.tokens -= 1.0;
    state.allowed += 1;
    Decision::Allow
}

fn refill(state: &mut AgentState, config: &QuotaConfig, now_ms: u64) {
    if now_ms <= state.last_refill_ms {
        // Monotonic clock expected; a backwards step must not mint tokens.
        state.last_refill_ms = state.last_refill_ms.min(now_ms);
        return;
    }
    let elapsed = now_ms - state.last_refill_ms;
    state.tokens =
        (state.tokens + elapsed as f64 * config.refill_per_ms()).min(config.per_agent_burst);
    state.last_refill_ms = now_ms;
}

fn ceil_secs(ms: u64) -> u64 {
    if ms == 0 {
        1
    } else {
        ms.div_ceil(1000)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentQuotaSnapshot {
    pub agent: String,
    pub tokens: f64,
    pub consecutive_failures: u32,
    pub circuit_open: bool,
    pub cooldown_until_ms: u64,
    pub allowed: u64,
    pub rejected: u64,
}

// ---------------------------------------------------------------------------
// Retry-After + backoff
// ---------------------------------------------------------------------------

/// Parse a `Retry-After` header value (RFC 9110 §10.2.3): either a
/// non-negative delta in seconds or an HTTP-date. Returns the number of
/// seconds to wait from `now_epoch_secs`, or None when the value is unusable.
/// A date already in the past yields 0 ("retry now").
pub fn parse_retry_after(value: &str, now_epoch_secs: u64) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(seconds) = trimmed.parse::<u64>() {
        return Some(seconds);
    }
    // HTTP-date uses the obsolete `GMT` zone, which RFC 2822's numeric-offset
    // parser does not accept; normalize it before parsing.
    let normalized = if let Some(head) = trimmed.strip_suffix(" GMT") {
        format!("{head} +0000")
    } else {
        trimmed.to_string()
    };
    let when = time::OffsetDateTime::parse(
        &normalized,
        &time::format_description::well_known::Rfc2822,
    )
    .ok()?;
    let when = u64::try_from(when.unix_timestamp()).ok()?;
    Some(when.saturating_sub(now_epoch_secs))
}

/// Capped exponential backoff for an idempotent retry. Deterministic (no RNG)
/// so the schedule is auditable and testable.
pub fn backoff_ms(attempt: u32, base_ms: u64, max_ms: u64) -> u64 {
    let shift = attempt.saturating_sub(1).min(32);
    let delay = base_ms.saturating_mul(1u64 << shift);
    delay.min(max_ms).max(1)
}

/// Sleep for `backoff_ms(attempt, ..)`.
pub async fn sleep_backoff(attempt: u32, base_ms: u64, max_ms: u64) {
    tokio::time::sleep(Duration::from_millis(backoff_ms(attempt, base_ms, max_ms))).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> QuotaConfig {
        QuotaConfig {
            enabled: true,
            per_agent_per_min: 60.0,
            per_agent_burst: 3.0,
            retry_after_cap_secs: 120,
            circuit_failure_threshold: 2,
            circuit_cooldown_secs: 30,
            circuit_half_open_successes: 1,
            retry_max_attempts: 3,
            retry_base_backoff_ms: 100,
            retry_max_backoff_ms: 1_000,
        }
    }

    #[test]
    fn test_half_open_requires_more_than_one_success_when_configured() {
        let mut c = cfg();
        c.circuit_half_open_successes = 2;
        let q = QuotaRegistry::new(c);
        q.record_upstream_failure("a", 0);
        q.record_upstream_failure("a", 0);
        assert!(matches!(q.check("a", 0), Decision::CircuitOpen { .. }));
        assert_eq!(q.check("a", 30_000), Decision::Allow);
        q.record_success("a", 30_100);
        // First success is not enough: the next call re-enters half-open.
        assert!(matches!(q.check("a", 30_200), Decision::Allow));
        q.record_success("a", 30_300);
        assert_eq!(q.check("a", 30_400), Decision::Allow);
        assert!(!q.snapshot()[0].circuit_open);
    }

    #[test]
    fn test_throttle_without_retry_after_uses_the_cap() {
        let q = QuotaRegistry::new(cfg());
        assert_eq!(q.record_upstream_throttle("a", None, 0), 120);
        assert!(matches!(q.check("a", 0), Decision::Throttled { .. }));
    }

    #[test]
    fn test_backwards_clock_does_not_mint_tokens() {
        let q = QuotaRegistry::new(cfg());
        for _ in 0..3 {
            assert_eq!(q.check("a", 10_000), Decision::Allow);
        }
        // A clock that steps backwards must not refill the bucket.
        assert!(matches!(q.check("a", 5_000), Decision::Throttled { .. }));
    }

    #[test]
    fn test_snapshot_is_sorted() {
        let q = QuotaRegistry::new(cfg());
        q.check("zeta", 0);
        q.check("alpha", 0);
        let snap = q.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].agent, "alpha");
        assert_eq!(snap[1].agent, "zeta");
    }

    #[test]
    fn test_disabled_config_skips_validation_of_numbers() {
        let mut c = cfg();
        c.enabled = false;
        c.per_agent_per_min = 0.0;
        c.per_agent_burst = 0.0;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_ceil_secs_never_returns_zero() {
        assert_eq!(ceil_secs(0), 1);
        assert_eq!(ceil_secs(1), 1);
        assert_eq!(ceil_secs(1000), 1);
        assert_eq!(ceil_secs(1001), 2);
    }
}