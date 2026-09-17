//! Per-agent request quotas and upstream circuit breaking (Phase 3, #18).
//!
//! `RateLimiter` is a per-agent token bucket over all /mcp verbs — the
//! noisy-neighbor bound: one agent cannot starve the shared upstream
//! budget. `CircuitBreaker` fails fast while the hosted MCP endpoint is
//! erroring so a sick upstream cannot pile up sockets and timeouts inside
//! octobroker.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-key token bucket. `rpm` is the sustained requests/minute budget and
/// also the burst capacity. `try_acquire` returns the number of seconds the
/// caller should wait before retrying when the bucket is empty.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Consume one token for `key` at `rpm` requests/minute.
    /// `rpm == 0` means unlimited — always allowed.
    /// Err(secs) = empty bucket; retry after `secs` (≥1).
    pub fn try_acquire(&self, key: &str, rpm: u32) -> Result<(), u64> {
        if rpm == 0 {
            return Ok(());
        }
        let rate = f64::from(rpm) / 60.0;
        let capacity = f64::from(rpm);
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - bucket.tokens;
            Err((deficit / rate).ceil().max(1.0) as u64)
        }
    }
}

/// Fail-fast gate for a failing upstream. Opens after `threshold`
/// consecutive transport/5xx failures, stays open for `cooldown`, then lets
/// a probe through (a success closes it; a failure re-opens it).
pub struct CircuitBreaker {
    threshold: u32,
    cooldown: Duration,
    state: Mutex<State>,
}

#[derive(Debug, PartialEq)]
enum State {
    /// Consecutive upstream failures so far.
    Closed {
        failures: u32,
    },
    Open {
        since: Instant,
        failures: u32,
    },
    /// Cooldown elapsed; traffic is probing. First success closes, first
    /// failure re-opens.
    HalfOpen {
        failures: u32,
    },
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            threshold,
            cooldown: Duration::from_secs(cooldown_secs),
            state: Mutex::new(State::Closed { failures: 0 }),
        }
    }

    /// Err(secs) = fail fast now; retry after `secs`. Ok = request may
    /// proceed (in HalfOpen every caller may probe; upstream protects
    /// itself by failing fast again on the first error).
    pub fn check(&self) -> Result<(), u64> {
        if self.threshold == 0 {
            return Ok(());
        }
        let mut state = self.state.lock().unwrap();
        if let State::Open { since, failures } = *state {
            let elapsed = since.elapsed();
            if elapsed < self.cooldown {
                return Err((self.cooldown - elapsed).as_secs().max(1));
            }
            *state = State::HalfOpen { failures };
        }
        Ok(())
    }

    pub fn record_success(&self) {
        if self.threshold == 0 {
            return;
        }
        *self.state.lock().unwrap() = State::Closed { failures: 0 };
    }

    /// Counts a failure; opens the circuit at `threshold` consecutive.
    /// In HalfOpen/Open a failure (re)starts the cooldown window.
    pub fn record_failure(&self) {
        if self.threshold == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let failures = match *state {
            State::Closed { failures }
            | State::Open { failures, .. }
            | State::HalfOpen { failures } => failures + 1,
        };
        *state = if failures >= self.threshold {
            State::Open {
                since: Instant::now(),
                failures,
            }
        } else {
            State::Closed { failures }
        };
    }

    /// For metrics: 1 while the breaker is not fully closed (traffic is
    /// being failed-fast or is only probing), 0 when closed.
    pub fn is_open(&self) -> bool {
        !matches!(*self.state.lock().unwrap(), State::Closed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlimited_when_rpm_zero() {
        let l = RateLimiter::new();
        for _ in 0..1000 {
            assert!(l.try_acquire("a", 0).is_ok());
        }
    }

    #[test]
    fn test_bucket_allows_burst_then_throttles() {
        let l = RateLimiter::new();
        // rpm=2 → capacity 2: two immediate tokens, then empty.
        assert!(l.try_acquire("a", 2).is_ok());
        assert!(l.try_acquire("a", 2).is_ok());
        let retry = l.try_acquire("a", 2).unwrap_err();
        assert!(retry >= 1, "retry-after must be positive");
        // Per-key isolation: another agent is unaffected.
        assert!(l.try_acquire("b", 2).is_ok());
    }

    #[test]
    fn test_bucket_refills() {
        let l = RateLimiter::new();
        // rpm=600 → capacity 600, refill 10/sec. Drain the bucket, then a
        // ~250ms wait restores ~2 tokens.
        for _ in 0..600 {
            assert!(l.try_acquire("a", 600).is_ok());
        }
        assert!(l.try_acquire("a", 600).is_err());
        std::thread::sleep(Duration::from_millis(250));
        assert!(
            l.try_acquire("a", 600).is_ok(),
            "bucket must refill over time"
        );
    }

    #[test]
    fn test_circuit_closed_until_threshold() {
        let c = CircuitBreaker::new(3, 60);
        assert!(c.check().is_ok());
        c.record_failure();
        c.record_failure();
        assert!(c.check().is_ok(), "below threshold stays closed");
        c.record_failure();
        assert!(c.is_open());
        let retry = c.check().unwrap_err();
        assert!((1..=60).contains(&retry));
    }

    #[test]
    fn test_circuit_success_resets() {
        let c = CircuitBreaker::new(2, 60);
        c.record_failure();
        c.record_success();
        c.record_failure();
        assert!(c.check().is_ok(), "success resets the failure count");
    }

    #[test]
    fn test_circuit_recovers_after_cooldown() {
        let c = CircuitBreaker::new(1, 1);
        c.record_failure();
        assert!(c.check().is_err());
        std::thread::sleep(Duration::from_millis(1100));
        assert!(c.check().is_ok(), "cooldown elapsed → half-open allow");
        // Still logically open until a success arrives: a failure re-opens.
        c.record_failure();
        assert!(c.is_open());
    }

    #[test]
    fn test_circuit_disabled_never_opens() {
        let c = CircuitBreaker::new(0, 30);
        for _ in 0..100 {
            c.record_failure();
        }
        assert!(c.check().is_ok());
        assert!(!c.is_open());
    }
}
