//! The in-memory usage meter (#384 attribution model): every turn accumulates
//! to ONE user (the owning omni — budgets are per-user), with per-device and
//! per-api-key breakdowns that roll up into the user-facing summary.
//!
//! Durability note: accumulators are process-local; the durable trail is the
//! per-turn `GateTurn` audit row. Rebuild-on-restart from the audit feed is the
//! tracked follow-up in #384.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use serde::Serialize;

use crate::openai::UsageCounters;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Counters {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cached_tokens: u64,
    pub reasoning_tokens: u64,
    pub turns: u64,
}

impl Counters {
    fn add(&mut self, u: &UsageCounters) {
        self.prompt_tokens += u.prompt_tokens;
        self.completion_tokens += u.completion_tokens;
        self.total_tokens += u.total_tokens;
        self.cached_tokens += u.cached_tokens;
        self.reasoning_tokens += u.reasoning_tokens;
        self.turns += 1;
    }
}

#[derive(Debug, Default)]
struct KeyBucket {
    label: String,
    device_id: String,
    counters: Counters,
}

#[derive(Debug, Default)]
struct UserUsage {
    totals: Counters,
    by_device: BTreeMap<String, Counters>,
    by_key: BTreeMap<String, KeyBucket>,
}

/// Per-device slice of a user's rollup.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceUsage {
    pub device_id: String,
    #[serde(flatten)]
    pub counters: Counters,
}

/// Per-api-key slice of a user's rollup.
#[derive(Debug, Clone, Serialize)]
pub struct KeyUsage {
    pub api_key_id: String,
    pub label: String,
    pub device_id: String,
    #[serde(flatten)]
    pub counters: Counters,
}

/// The user-facing summary `GET /v1/usage` serves: one user, total + budget +
/// the two breakdowns.
#[derive(Debug, Clone, Serialize)]
pub struct UsageSummary {
    pub user_omni: String,
    pub budget_tokens: Option<u64>,
    pub used_tokens: u64,
    pub remaining_tokens: Option<u64>,
    pub totals: Counters,
    pub by_device: Vec<DeviceUsage>,
    pub by_api_key: Vec<KeyUsage>,
}

#[derive(Default)]
pub struct Meter {
    users: RwLock<HashMap<String, UserUsage>>,
}

impl Meter {
    /// Record one turn's usage against (user, device, api-key). The user
    /// bucket is the accumulation root; device/key are attribution dimensions.
    pub fn record(
        &self,
        user_omni: &str,
        device_id: &str,
        api_key_id: &str,
        key_label: &str,
        usage: &UsageCounters,
    ) {
        let mut users = self.users.write().expect("meter lock poisoned");
        let user = users.entry(user_omni.to_string()).or_default();
        user.totals.add(usage);
        user.by_device
            .entry(device_id.to_string())
            .or_default()
            .add(usage);
        let bucket = user.by_key.entry(api_key_id.to_string()).or_default();
        bucket.label = key_label.to_string();
        bucket.device_id = device_id.to_string();
        bucket.counters.add(usage);
    }

    /// Tokens already accumulated to the user — the budget comparand.
    pub fn used_total(&self, user_omni: &str) -> u64 {
        self.users
            .read()
            .expect("meter lock poisoned")
            .get(user_omni)
            .map(|u| u.totals.total_tokens)
            .unwrap_or(0)
    }

    /// Roll one user's breakdowns up into the presentation summary.
    pub fn summary(&self, user_omni: &str, budget_tokens: Option<u64>) -> UsageSummary {
        let users = self.users.read().expect("meter lock poisoned");
        let user = users.get(user_omni);
        let totals = user.map(|u| u.totals.clone()).unwrap_or_default();
        let used = totals.total_tokens;
        UsageSummary {
            user_omni: user_omni.to_string(),
            budget_tokens,
            used_tokens: used,
            remaining_tokens: budget_tokens.map(|b| b.saturating_sub(used)),
            totals,
            by_device: user
                .map(|u| {
                    u.by_device
                        .iter()
                        .map(|(d, c)| DeviceUsage {
                            device_id: d.clone(),
                            counters: c.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            by_api_key: user
                .map(|u| {
                    u.by_key
                        .iter()
                        .map(|(k, b)| KeyUsage {
                            api_key_id: k.clone(),
                            label: b.label.clone(),
                            device_id: b.device_id.clone(),
                            counters: b.counters.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// All known users' summaries (operator view).
    pub fn summaries(&self, budget_for: impl Fn(&str) -> Option<u64>) -> Vec<UsageSummary> {
        let user_omnis: Vec<String> = {
            let users = self.users.read().expect("meter lock poisoned");
            users.keys().cloned().collect()
        };
        let mut out: Vec<UsageSummary> = user_omnis
            .into_iter()
            .map(|u| self.summary(&u, budget_for(&u)))
            .collect();
        out.sort_by(|a, b| a.user_omni.cmp(&b.user_omni));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(total: u64) -> UsageCounters {
        UsageCounters {
            prompt_tokens: total / 2,
            completion_tokens: total - total / 2,
            total_tokens: total,
            cached_tokens: 1,
            reasoning_tokens: 2,
        }
    }

    #[test]
    fn two_keys_two_devices_roll_up_to_one_user() {
        let meter = Meter::default();
        let user = "0xuser";
        meter.record(user, "esp32-01", "k1", "kid tablet", &usage(10));
        meter.record(user, "esp32-02", "k2", "living room", &usage(30));
        meter.record(user, "esp32-01", "k1", "kid tablet", &usage(5));

        assert_eq!(meter.used_total(user), 45);
        let s = meter.summary(user, Some(100));
        assert_eq!(s.used_tokens, 45);
        assert_eq!(s.remaining_tokens, Some(55));
        assert_eq!(s.totals.turns, 3);
        assert_eq!(s.totals.cached_tokens, 3);
        assert_eq!(s.totals.reasoning_tokens, 6);
        assert_eq!(s.by_device.len(), 2);
        assert_eq!(s.by_api_key.len(), 2);
        let d1 = s
            .by_device
            .iter()
            .find(|d| d.device_id == "esp32-01")
            .unwrap();
        assert_eq!(d1.counters.total_tokens, 15);
        assert_eq!(d1.counters.turns, 2);
        let k2 = s.by_api_key.iter().find(|k| k.api_key_id == "k2").unwrap();
        assert_eq!(k2.counters.total_tokens, 30);
        assert_eq!(k2.label, "living room");
    }

    #[test]
    fn remaining_saturates_and_unknown_user_is_empty() {
        let meter = Meter::default();
        meter.record("0xu", "d", "k", "", &usage(80));
        let s = meter.summary("0xu", Some(50));
        assert_eq!(s.remaining_tokens, Some(0));
        let empty = meter.summary("0xnobody", None);
        assert_eq!(empty.used_tokens, 0);
        assert!(empty.by_device.is_empty());
        assert_eq!(empty.remaining_tokens, None);
    }
}
