//! Prometheus-compatible counters (Phase D-rest, US-036).
//!
//! Per plan §Phase D: counters for mints, mints_failed, audit_writes,
//! audit_writes_failed, auth_attempts, auth_failed_by_reason. Histograms
//! (mint_latency, audit_write_latency) are deferred to V0.1-FOLLOWUPS
//! Phase E hardening (require either the `prometheus` crate or
//! per-bucket atomic arrays — both are large additions for v0).
//!
//! v0 emits a Prometheus-exposition-format text body via the
//! `/metrics` endpoint, gated by `BROKER_METRICS_ENABLED=true`. The
//! counters use `AtomicU64` so the increment surface is lock-free.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    pub mints: AtomicU64,
    pub mints_failed: AtomicU64,
    pub audit_writes: AtomicU64,
    pub audit_writes_failed: AtomicU64,
    pub auth_attempts: AtomicU64,
    pub auth_failed_unauthorized: AtomicU64,
    pub auth_failed_rate_limited: AtomicU64,
    pub auth_failed_other: AtomicU64,
    pub idempotency_hits: AtomicU64,
    pub idempotency_conflicts: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        let pairs: &[(&str, &AtomicU64, &str)] = &[
            (
                "agentkeys_broker_mints_total",
                &self.mints,
                "Total mint requests that returned 200.",
            ),
            (
                "agentkeys_broker_mints_failed_total",
                &self.mints_failed,
                "Total mint requests that returned non-2xx.",
            ),
            (
                "agentkeys_broker_audit_writes_total",
                &self.audit_writes,
                "Total successful audit-anchor writes.",
            ),
            (
                "agentkeys_broker_audit_writes_failed_total",
                &self.audit_writes_failed,
                "Total audit-anchor writes that errored.",
            ),
            (
                "agentkeys_broker_auth_attempts_total",
                &self.auth_attempts,
                "Total auth challenge or verify attempts.",
            ),
            (
                "agentkeys_broker_auth_failed_unauthorized_total",
                &self.auth_failed_unauthorized,
                "Auth attempts that failed with 401 Unauthorized.",
            ),
            (
                "agentkeys_broker_auth_failed_rate_limited_total",
                &self.auth_failed_rate_limited,
                "Auth attempts that failed with 429 Rate Limited.",
            ),
            (
                "agentkeys_broker_auth_failed_other_total",
                &self.auth_failed_other,
                "Auth attempts that failed with any other 4xx/5xx.",
            ),
            (
                "agentkeys_broker_idempotency_hits_total",
                &self.idempotency_hits,
                "Idempotency-Key replays served from cache.",
            ),
            (
                "agentkeys_broker_idempotency_conflicts_total",
                &self.idempotency_conflicts,
                "Idempotency-Key requests with mismatched body hash (422).",
            ),
        ];
        for (name, counter, help) in pairs {
            use std::fmt::Write as _;
            let _ = writeln!(out, "# HELP {} {}", name, help);
            let _ = writeln!(out, "# TYPE {} counter", name);
            let _ = writeln!(out, "{} {}", name, counter.load(Ordering::Relaxed));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_metrics_render_zeros() {
        let m = Metrics::new();
        let s = m.render_prometheus();
        assert!(s.contains("agentkeys_broker_mints_total 0"));
        assert!(s.contains("agentkeys_broker_audit_writes_total 0"));
    }

    #[test]
    fn incremented_counters_render_correctly() {
        let m = Metrics::new();
        m.mints.fetch_add(7, Ordering::Relaxed);
        m.audit_writes.fetch_add(3, Ordering::Relaxed);
        let s = m.render_prometheus();
        assert!(s.contains("agentkeys_broker_mints_total 7"));
        assert!(s.contains("agentkeys_broker_audit_writes_total 3"));
    }

    #[test]
    fn render_includes_help_and_type_per_counter() {
        let m = Metrics::new();
        let s = m.render_prometheus();
        let help_count = s.matches("# HELP").count();
        let type_count = s.matches("# TYPE").count();
        assert_eq!(help_count, 10);
        assert_eq!(type_count, 10);
    }

    #[test]
    fn counters_are_independent() {
        let m = Metrics::new();
        m.mints.fetch_add(5, Ordering::Relaxed);
        m.mints_failed.fetch_add(2, Ordering::Relaxed);
        let s = m.render_prometheus();
        assert!(s.contains("agentkeys_broker_mints_total 5"));
        assert!(s.contains("agentkeys_broker_mints_failed_total 2"));
    }
}
