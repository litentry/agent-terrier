//! Circuit breaker — Phase C, US-033.
//!
//! Per plan §Phase C: when an EVM anchor returns errors faster than a
//! recovery window, the breaker opens and subsequent attempts fail fast
//! (no more network calls until the half-open probe says recovery).
//!
//! State machine:
//!
//! ```text
//!  ┌────────┐  K consecutive failures  ┌──────┐
//!  │ Closed ├─────────────────────────►│ Open │
//!  └────────┘                          └─┬────┘
//!       ▲                                │
//!       │ probe success                  │ M seconds elapsed
//!       │                                ▼
//!       │                          ┌─────────┐
//!       └──────────────────────────┤ HalfOpen│
//!                                  └────┬────┘
//!                                       │ probe failure
//!                                       ▼
//!                                  ┌──────┐
//!                                  │ Open │
//!                                  └──────┘
//! ```
//!
//! `failure_threshold` (K) and `recovery_seconds` (M) are configurable.
//! `Closed` is the happy path; `Open` short-circuits all subsequent
//! attempts; `HalfOpen` allows exactly one probe at a time.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    pub failure_threshold: u32,
    pub recovery_seconds: i64,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_seconds: 30,
        }
    }
}

#[derive(Debug)]
struct BreakerInner {
    state: BreakerState,
    consecutive_failures: u32,
    /// When the breaker entered `Open`. Used to decide when to flip to
    /// `HalfOpen`.
    opened_at: Option<i64>,
    /// True while a probe is in-flight in HalfOpen — guarantees only ONE
    /// caller at a time exits the breaker.
    probe_in_flight: bool,
}

/// Thread-safe circuit breaker. The `try_acquire` method returns a
/// `BreakerToken` which the caller MUST resolve via `complete_success`
/// or `complete_failure`. Dropping the token without resolving counts
/// as a failure (defensive — prevents stuck HalfOpen probes).
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    inner: Mutex<BreakerInner>,
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(BreakerInner {
                state: BreakerState::Closed,
                consecutive_failures: 0,
                opened_at: None,
                probe_in_flight: false,
            }),
        }
    }

    /// Try to acquire the right to make a network call. Returns:
    /// - `Ok(BreakerToken::Closed)` when the breaker is closed.
    /// - `Ok(BreakerToken::HalfOpenProbe)` when the breaker just
    ///   transitioned to HalfOpen and this call is the probe.
    /// - `Err(BreakerError::Open)` when the breaker is open and the
    ///   recovery window has not elapsed.
    /// - `Err(BreakerError::HalfOpenProbeBusy)` when another probe is
    ///   already in flight.
    pub fn try_acquire(&self) -> Result<BreakerToken<'_>, BreakerError> {
        let now = unix_now();
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| BreakerError::Internal(format!("breaker mutex poisoned: {}", e)))?;
        match inner.state {
            BreakerState::Closed => Ok(BreakerToken {
                breaker: self,
                kind: TokenKind::Closed,
                resolved: false,
            }),
            BreakerState::Open => {
                let opened_at = inner.opened_at.unwrap_or(now);
                if now - opened_at >= self.config.recovery_seconds {
                    if inner.probe_in_flight {
                        return Err(BreakerError::HalfOpenProbeBusy);
                    }
                    inner.state = BreakerState::HalfOpen;
                    inner.probe_in_flight = true;
                    Ok(BreakerToken {
                        breaker: self,
                        kind: TokenKind::HalfOpenProbe,
                        resolved: false,
                    })
                } else {
                    Err(BreakerError::Open)
                }
            }
            BreakerState::HalfOpen => {
                if inner.probe_in_flight {
                    Err(BreakerError::HalfOpenProbeBusy)
                } else {
                    inner.probe_in_flight = true;
                    Ok(BreakerToken {
                        breaker: self,
                        kind: TokenKind::HalfOpenProbe,
                        resolved: false,
                    })
                }
            }
        }
    }

    pub fn state(&self) -> BreakerState {
        self.inner
            .lock()
            .map(|i| i.state)
            .unwrap_or(BreakerState::Open)
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.inner
            .lock()
            .map(|i| i.consecutive_failures)
            .unwrap_or(0)
    }

    fn complete_success(&self, kind: TokenKind) {
        let now = unix_now();
        let _ = now;
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.consecutive_failures = 0;
        inner.state = BreakerState::Closed;
        inner.opened_at = None;
        if matches!(kind, TokenKind::HalfOpenProbe) {
            inner.probe_in_flight = false;
        }
    }

    fn complete_failure(&self, kind: TokenKind) {
        let now = unix_now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
        let should_open = inner.consecutive_failures >= self.config.failure_threshold
            || matches!(kind, TokenKind::HalfOpenProbe);
        if should_open {
            inner.state = BreakerState::Open;
            inner.opened_at = Some(now);
        }
        if matches!(kind, TokenKind::HalfOpenProbe) {
            inner.probe_in_flight = false;
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TokenKind {
    Closed,
    HalfOpenProbe,
}

#[derive(Debug)]
pub struct BreakerToken<'a> {
    breaker: &'a CircuitBreaker,
    kind: TokenKind,
    resolved: bool,
}

impl<'a> BreakerToken<'a> {
    pub fn complete_success(mut self) {
        self.breaker.complete_success(self.kind);
        self.resolved = true;
    }
    pub fn complete_failure(mut self) {
        self.breaker.complete_failure(self.kind);
        self.resolved = true;
    }
}

impl<'a> Drop for BreakerToken<'a> {
    fn drop(&mut self) {
        if !self.resolved {
            // Defensive: an unresolved token counts as a failure (the
            // caller dropped without telling us the outcome — assume
            // worst case so the breaker doesn't get stuck).
            self.breaker.complete_failure(self.kind);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BreakerError {
    #[error("circuit breaker is open (recovery in progress)")]
    Open,
    #[error("circuit breaker half-open probe already in flight")]
    HalfOpenProbeBusy,
    #[error("internal: {0}")]
    Internal(String),
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_breaker_acquires_freely() {
        let b = CircuitBreaker::new(BreakerConfig::default());
        for _ in 0..10 {
            let t = b.try_acquire().unwrap();
            t.complete_success();
        }
        assert_eq!(b.state(), BreakerState::Closed);
        assert_eq!(b.consecutive_failures(), 0);
    }

    #[test]
    fn k_consecutive_failures_open_the_breaker() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 3,
            recovery_seconds: 30,
        });
        for _ in 0..2 {
            let t = b.try_acquire().unwrap();
            t.complete_failure();
        }
        assert_eq!(b.state(), BreakerState::Closed);
        let t = b.try_acquire().unwrap();
        t.complete_failure();
        assert_eq!(b.state(), BreakerState::Open);
        // Subsequent acquires fail fast.
        let res = b.try_acquire();
        assert!(matches!(res, Err(BreakerError::Open)));
    }

    #[test]
    fn one_success_resets_failure_counter_in_closed() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 3,
            recovery_seconds: 30,
        });
        for _ in 0..2 {
            let t = b.try_acquire().unwrap();
            t.complete_failure();
        }
        let t = b.try_acquire().unwrap();
        t.complete_success();
        assert_eq!(b.consecutive_failures(), 0);
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn dropped_token_counts_as_failure() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            recovery_seconds: 30,
        });
        {
            let _t = b.try_acquire().unwrap();
            // Dropped without resolution.
        }
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn half_open_after_recovery_succeeds_to_closed() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            recovery_seconds: 0, // immediate transition for test
        });
        // Open the breaker.
        let t = b.try_acquire().unwrap();
        t.complete_failure();
        assert_eq!(b.state(), BreakerState::Open);
        // Acquire a probe (recovery_seconds=0 so eligible immediately).
        let probe = b.try_acquire().unwrap();
        probe.complete_success();
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn half_open_failure_re_opens() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            recovery_seconds: 0,
        });
        let t = b.try_acquire().unwrap();
        t.complete_failure();
        let probe = b.try_acquire().unwrap();
        probe.complete_failure();
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn half_open_probe_is_serialized() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            recovery_seconds: 0,
        });
        let t = b.try_acquire().unwrap();
        t.complete_failure();
        let _probe = b.try_acquire().unwrap();
        // Concurrent acquire — should fail with HalfOpenProbeBusy.
        let res = b.try_acquire();
        assert!(matches!(res, Err(BreakerError::HalfOpenProbeBusy)));
    }
}
