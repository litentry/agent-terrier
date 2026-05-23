//! Pluggable trait surface for the three layers below the credential mint:
//! auth (who is the user?), wallet (what wallet do they own?), audit (where
//! does the immutable record go?).
//!
//! Per Stage 7 plan §3 and §3.5: every plug-in implements a Send+Sync trait,
//! is registered in `PluginRegistry` at boot, and reports its operational
//! state via `Readiness`. **No trait method may default to `Ready`** — every
//! plug-in must implement `ready()` against its own dependencies.

pub mod audit;
pub mod auth;
pub mod wallet;

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub use audit::{AnchorReceipt, AuditAnchor, AuditError, AuditRecord};
pub use auth::{
    AuthChallenge, AuthError, AuthResponse, ChallengeParams, UserAuthMethod, VerifiedIdentity,
};
pub use wallet::{WalletAddress, WalletBinding, WalletError, WalletProvisioner, WalletRole};

/// Operational state of a single plug-in or boot-time check.
///
/// `/readyz` aggregates all `Readiness` values from registered plug-ins:
/// any `Unready` produces 503, any `Degraded` produces 200 with a JSON body
/// listing degradations, and all-`Ready` produces 200 with empty body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum Readiness {
    /// The plug-in's dependencies are all reachable and operations are
    /// expected to succeed.
    Ready { detail: Option<String> },
    /// Operations are probably succeeding right now but a dependency is
    /// stale or partially impaired (e.g., circuit half-open, cache stale).
    Degraded { reason: String },
    /// Operations are failing or about to fail. `/readyz` returns 503.
    Unready { reason: String },
}

impl Readiness {
    /// Convenience constructor for the common "all good, no detail" case.
    pub fn ok() -> Self {
        Self::Ready { detail: None }
    }

    pub fn ready_with(detail: impl Into<String>) -> Self {
        Self::Ready {
            detail: Some(detail.into()),
        }
    }

    pub fn degraded(reason: impl Into<String>) -> Self {
        Self::Degraded {
            reason: reason.into(),
        }
    }

    pub fn unready(reason: impl Into<String>) -> Self {
        Self::Unready {
            reason: reason.into(),
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }

    pub fn is_unready(&self) -> bool {
        matches!(self, Self::Unready { .. })
    }
}

/// The set of plug-ins active in this broker process.
///
/// Constructed at boot from `BROKER_AUTH_METHODS`, `BROKER_WALLET_PROVISIONER`,
/// and `BROKER_AUDIT_ANCHORS` (env.rs). Stored on `AppState` and shared via
/// `Arc<PluginRegistry>` to every handler.
pub struct PluginRegistry {
    /// Auth methods keyed by their `name()`, e.g. `"wallet_sig"`, `"email_link"`,
    /// `"oauth2_google"`. Multiple may be enabled; the auth router dispatches
    /// by URL prefix.
    pub auth: HashMap<String, Arc<dyn UserAuthMethod>>,
    /// Single wallet provisioner — chosen at config time.
    pub wallet: Arc<dyn WalletProvisioner>,
    /// One or more audit anchors. When more than one is configured the
    /// `BROKER_AUDIT_POLICY` env var selects the multi-anchor strategy
    /// (`dual_strict`, `sqlite_primary`, `evm_primary`).
    pub audit: Vec<Arc<dyn AuditAnchor>>,
}

impl PluginRegistry {
    /// Aggregate readiness across every registered plug-in.
    ///
    /// Returns `(overall, per_check)` where `overall` is the worst state
    /// (Unready > Degraded > Ready) and `per_check` is the labeled list
    /// for the `/readyz` JSON body (Designer review #status-shape).
    pub fn aggregate_readiness(&self) -> (Readiness, Vec<(String, Readiness)>) {
        let mut checks: Vec<(String, Readiness)> = Vec::new();
        for (name, plugin) in &self.auth {
            checks.push((format!("auth/{}", name), plugin.ready()));
        }
        checks.push((
            format!("wallet/{}", self.wallet.name()),
            self.wallet.ready(),
        ));
        for anchor in &self.audit {
            checks.push((format!("audit/{}", anchor.name()), anchor.ready()));
        }

        let mut worst = Readiness::ok();
        for (_, r) in &checks {
            worst = match (&worst, r) {
                (_, Readiness::Unready { .. }) => r.clone(),
                (Readiness::Unready { .. }, _) => worst.clone(),
                (Readiness::Ready { .. }, Readiness::Degraded { .. }) => r.clone(),
                _ => worst.clone(),
            };
        }
        (worst, checks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_helpers_classify_correctly() {
        assert!(Readiness::ok().is_ready());
        assert!(!Readiness::ok().is_degraded());
        assert!(!Readiness::ok().is_unready());

        assert!(Readiness::degraded("stale cache").is_degraded());
        assert!(Readiness::unready("RPC down").is_unready());
    }

    #[test]
    fn readiness_serialize_round_trip() {
        let r = Readiness::degraded("circuit half-open");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("degraded"));
        assert!(s.contains("circuit half-open"));
        let back: Readiness = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }
}
