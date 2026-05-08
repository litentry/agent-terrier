//! Per-OmniAccount mint rate limit + per-identity daily EVM-tx budget
//! (Phase C, US-034).
//!
//! Per plan §Phase C gas-drain mitigations:
//! 1. Per-OmniAccount sliding-window rate limit on mints (default 30/hour).
//! 2. Per-identity daily EVM-tx budget (default 100/day) — separately
//!    enforced because EVM tx submission is the costly resource, not
//!    the STS call.
//!
//! Both buckets reuse the existing `EmailRateLimitStore` schema
//! (bucket-id-generic). Phase E renames `EmailRateLimitStore` →
//! `RateLimitStore` to drop the historical "email" prefix.
//!
//! This module is a thin convenience layer over `EmailRateLimitStore`
//! with the bucket-id conventions pinned + helper constants.

use crate::plugins::auth::AuthError;
use crate::storage::{EmailRateLimitStore, RateLimitOutcome};

const HOUR_SECONDS: i64 = 3600;
const DAY_SECONDS: i64 = 86400;

/// Bucket-id prefix for per-OmniAccount mint rate limit.
const MINT_BUCKET_PREFIX: &str = "mints_per_omni_hourly:";

/// Bucket-id prefix for per-OmniAccount daily EVM-tx budget.
const EVM_TX_BUCKET_PREFIX: &str = "evm_tx_per_omni_daily:";

pub struct MintRateLimiter {
    store: std::sync::Arc<EmailRateLimitStore>,
    pub mints_per_hour: i64,
    pub evm_tx_per_day: i64,
}

impl MintRateLimiter {
    pub fn new(
        store: std::sync::Arc<EmailRateLimitStore>,
        mints_per_hour: i64,
        evm_tx_per_day: i64,
    ) -> Self {
        Self {
            store,
            mints_per_hour,
            evm_tx_per_day,
        }
    }

    /// Check + increment per-OmniAccount mint rate. Plan default 30/hour.
    /// Returns `Allowed` with remaining count or `Denied` with retry-after.
    pub fn check_mint(
        &self,
        omni_account: &str,
        now: i64,
    ) -> Result<RateLimitOutcome, AuthError> {
        let bucket = format!("{}{}", MINT_BUCKET_PREFIX, omni_account);
        self.store.check_and_increment(&bucket, now, HOUR_SECONDS, self.mints_per_hour)
    }

    /// Check + increment per-OmniAccount daily EVM-tx budget. Plan default
    /// 100/day. Defends the broker fee-payer wallet against amplification:
    /// even if an attacker drives the mint endpoint at the per-hour mint
    /// limit, EVM tx submission is independently capped at 100/day per
    /// identity.
    pub fn check_evm_tx(
        &self,
        omni_account: &str,
        now: i64,
    ) -> Result<RateLimitOutcome, AuthError> {
        let bucket = format!("{}{}", EVM_TX_BUCKET_PREFIX, omni_account);
        self.store.check_and_increment(&bucket, now, DAY_SECONDS, self.evm_tx_per_day)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn limiter(mints: i64, evm: i64) -> MintRateLimiter {
        MintRateLimiter::new(
            Arc::new(EmailRateLimitStore::open_in_memory().unwrap()),
            mints,
            evm,
        )
    }

    #[test]
    fn first_mint_allowed_returns_remaining() {
        let l = limiter(30, 100);
        let r = l.check_mint("0xom", 1000).unwrap();
        assert!(matches!(r, RateLimitOutcome::Allowed { remaining: 29 }));
    }

    #[test]
    fn mint_limit_enforced_per_hour() {
        let l = limiter(3, 100);
        for _ in 0..3 {
            l.check_mint("0xom", 1000).unwrap();
        }
        let r = l.check_mint("0xom", 1000).unwrap();
        assert!(matches!(r, RateLimitOutcome::Denied { .. }));
    }

    #[test]
    fn evm_tx_budget_enforced_per_day() {
        let l = limiter(1000, 2);
        for _ in 0..2 {
            l.check_evm_tx("0xom", 1000).unwrap();
        }
        let r = l.check_evm_tx("0xom", 1000).unwrap();
        assert!(matches!(r, RateLimitOutcome::Denied { .. }));
    }

    #[test]
    fn mint_and_evm_buckets_independent() {
        let l = limiter(2, 2);
        // Exhaust mint bucket — EVM bucket still fresh.
        for _ in 0..2 {
            l.check_mint("0xom", 1000).unwrap();
        }
        let mint_r = l.check_mint("0xom", 1000).unwrap();
        assert!(matches!(mint_r, RateLimitOutcome::Denied { .. }));
        let evm_r = l.check_evm_tx("0xom", 1000).unwrap();
        assert!(matches!(evm_r, RateLimitOutcome::Allowed { .. }));
    }

    #[test]
    fn rate_limit_resets_in_next_window() {
        let l = limiter(2, 100);
        for _ in 0..2 {
            l.check_mint("0xom", 1000).unwrap();
        }
        // Move into next hourly window.
        let r = l.check_mint("0xom", 1000 + HOUR_SECONDS + 10).unwrap();
        assert!(matches!(r, RateLimitOutcome::Allowed { .. }));
    }

    #[test]
    fn cross_omni_buckets_isolated() {
        let l = limiter(2, 100);
        l.check_mint("0xalice", 1000).unwrap();
        l.check_mint("0xalice", 1000).unwrap();
        // Bob's bucket is fresh.
        let r = l.check_mint("0xbob", 1000).unwrap();
        assert!(matches!(r, RateLimitOutcome::Allowed { remaining: 1 }));
    }
}
