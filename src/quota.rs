//! Phase 3 (#18): per-agent request quotas + upstream circuit breaker.
//!
//! - [`RateLimiter`]: token bucket per agent id over *all* `/mcp` verbs —
//!   noisy neighbors get `429` + `Retry-After` instead of saturating the
//!   upstream or this process.
//! - [`CircuitBreaker`]: after `threshold` consecutive upstream failures
//!   (transport error, 429, or 5xx — never a 4xx, which is a caller problem)
//!   calls fail fast with `503` + `Retry-After` until the cooldown elapses,
//!   then exactly ONE half-open probe is admitted (see `Admission::Probe`).
//!   A stale in-flight request finishing while the breaker is open can never
//!   close it — only the designated probe's outcome decides.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Bucket id for unauthenticated (network-trust mode) traffic.
pub const ANONYMOUS: &str = "anonymous";

/// Per-agent token buckets. `0` configured rate = unlimited.
pub struct RateLimiter {
    /// agent_id -> (tokens, last refill). Bucket capacity = rate (burst of
    /// one minute's allotment); refill is continuous at rate/60 tokens/s.
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Consume one token for `agent` under `rate_per_min`.
    /// Returns `Err(retry_after_secs)` when the bucket is empty.
    pub fn check(&self, agent: &str, rate_per_min: u32) -> Result<(), u64> {
        if rate_per_min == 0 {
            return Ok(());
        }
        let rate = rate_per_min as f64 / 60.0;
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        let (tokens, at) = buckets
            .entry(agent.to_string())
            .or_insert((rate_per_min as f64, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * rate).min(rate_per_min as f64);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            // seconds until the next token exists (at least 1 — Retry-After
            // of 0 is meaningless)
            Err(((1.0 - *tokens) / rate).ceil().max(1.0) as u64)
        }
    }
}

/// What the breaker decided for a caller: `Open` carries the
/// `Retry-After` hint; `Admitted`/`Probe` ride the caller through
/// `record_success`/`record_failure` so only the designated probe can
/// change open-state direction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Admission {
    Admitted,
    /// The single half-open probe allowed through after cooldown.
    Probe,
    /// Rejected — the u64 is the suggested Retry-After (seconds).
    Open(u64),
}

/// Upstream circuit breaker (OPEN after `threshold` consecutive failures,
/// HALF-OPEN probe after `cooldown`).
pub struct CircuitBreaker {
    threshold: u32,
    cooldown: Duration,
    state: Mutex<State>,
}

struct State {
    consecutive_failures: u32,
    /// Instant the OPEN window ends; 0 when closed.
    open_until_ms: u64,
    /// A half-open probe is currently in flight — further callers are
    /// rejected instead of stampeding a recovering upstream.
    probe_in_flight: bool,
    /// Times the breaker has transitioned CLOSED→OPEN (observability).
    opens: u64,
}

fn now_ms() -> u64 {
    // Process-lifetime epoch is fine — only durations matter.
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            threshold,
            cooldown: Duration::from_secs(cooldown_secs),
            state: Mutex::new(State {
                consecutive_failures: 0,
                open_until_ms: 0,
                probe_in_flight: false,
                opens: 0,
            }),
        }
    }

    /// Gate an upstream request.
    pub fn check(&self) -> Admission {
        if self.threshold == 0 {
            return Admission::Admitted; // breaker disabled
        }
        let mut s = self.state.lock().unwrap();
        if s.open_until_ms == 0 {
            return Admission::Admitted;
        }
        let remaining = s.open_until_ms.saturating_sub(now_ms());
        if remaining > 0 {
            return Admission::Open((remaining / 1000).max(1));
        }
        // Cooldown elapsed → admit ONE probe; reject the herd behind it.
        if s.probe_in_flight {
            return Admission::Open(1);
        }
        s.probe_in_flight = true;
        Admission::Probe
    }

    /// Upstream success (or 4xx — a caller problem, not upstream health).
    /// `probe` marks the call as the admitted half-open probe.
    pub fn record_success(&self, admission: Admission) {
        let mut s = self.state.lock().unwrap();
        match admission {
            Admission::Probe => {
                // The probe succeeded → CLOSE the breaker.
                s.probe_in_flight = false;
                s.open_until_ms = 0;
                s.consecutive_failures = 0;
            }
            Admission::Admitted => {
                // A request admitted before the breaker opened: its success
                // doesn't overturn the open decision — the probe decides.
                if s.open_until_ms == 0 {
                    s.consecutive_failures = 0;
                }
            }
            Admission::Open(_) => {}
        }
    }

    /// Upstream failure: transport error, 429, or 5xx.
    pub fn record_failure(&self, admission: Admission) {
        if self.threshold == 0 {
            return;
        }
        let mut s = self.state.lock().unwrap();
        match admission {
            Admission::Probe => {
                // Probe failed → re-OPEN for a fresh cooldown.
                s.probe_in_flight = false;
                s.opens += 1;
                s.open_until_ms = now_ms() + self.cooldown.as_millis() as u64;
                s.consecutive_failures = s.consecutive_failures.max(self.threshold);
            }
            Admission::Admitted => {
                s.consecutive_failures += 1;
                if s.open_until_ms == 0 && s.consecutive_failures >= self.threshold {
                    s.opens += 1;
                    s.open_until_ms = now_ms() + self.cooldown.as_millis() as u64;
                }
            }
            Admission::Open(_) => {}
        }
    }

    /// For observability.
    pub fn opens(&self) -> u64 {
        self.state.lock().unwrap().opens
    }

    pub fn is_open(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.open_until_ms > 0 && now_ms() < s.open_until_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_429s() {
        let rl = RateLimiter::new();
        // 60/min = 1/s; first burst can take all 60.
        for _ in 0..60 {
            assert!(rl.check("a", 60).is_ok());
        }
        let e = rl.check("a", 60).unwrap_err();
        assert!(e >= 1);
        // Independent buckets.
        assert!(rl.check("b", 60).is_ok());
        // Unlimited rate.
        for _ in 0..1000 {
            assert!(rl.check("a", 0).is_ok());
        }
    }

    #[test]
    fn breaker_opens_after_threshold_and_fails_fast() {
        let cb = CircuitBreaker::new(3, 60);
        for _ in 0..3 {
            cb.record_failure(Admission::Admitted);
        }
        assert!(matches!(cb.check(), Admission::Open(_)));
        assert_eq!(cb.opens(), 1);
    }

    #[test]
    fn breaker_half_open_admits_one_probe_only() {
        let cb = CircuitBreaker::new(1, 1);
        cb.record_failure(Admission::Admitted);
        assert!(cb.is_open());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // cooldown elapsed → exactly one probe admitted
        assert_eq!(cb.check(), Admission::Probe);
        // concurrent callers behind the probe are rejected
        assert!(matches!(cb.check(), Admission::Open(_)));
        // probe succeeds → closed
        cb.record_success(Admission::Probe);
        assert_eq!(cb.check(), Admission::Admitted);
    }

    #[test]
    fn breaker_stale_success_cannot_close_open() {
        let cb = CircuitBreaker::new(1, 3600);
        // Request A admitted while closed, still in flight…
        let adm_a = cb.check();
        assert_eq!(adm_a, Admission::Admitted);
        // …breaker opens on a different request's failure
        cb.record_failure(Admission::Admitted);
        assert!(cb.is_open());
        // …then A completes successfully while open: must NOT close it.
        cb.record_success(adm_a);
        assert!(matches!(cb.check(), Admission::Open(_)));
    }

    #[test]
    fn breaker_probe_failure_reopens() {
        let cb = CircuitBreaker::new(1, 1);
        cb.record_failure(Admission::Admitted);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(cb.check(), Admission::Probe);
        cb.record_failure(Admission::Probe);
        assert!(cb.is_open());
        assert_eq!(cb.opens(), 2);
    }

    #[test]
    fn breaker_disabled_when_threshold_zero() {
        let cb = CircuitBreaker::new(0, 60);
        for _ in 0..100 {
            cb.record_failure(Admission::Admitted);
        }
        assert_eq!(cb.check(), Admission::Admitted);
        assert!(!cb.is_open());
    }
}
