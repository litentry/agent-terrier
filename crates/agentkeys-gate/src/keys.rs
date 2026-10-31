//! #427 — the LIVE relay-key registry: the boot-time keys-file set plus
//! broker-minted per-delegate keys (spawn provisions, archive disables),
//! write-through-persisted to the SAME keys file so restarts re-hydrate.
//!
//! The file stays the durable source of truth; this store exists so the #425
//! spawn/archive ceremonies don't need an operator `sudoedit` + restart per
//! delegate. Mutations are admin-token-gated at the HTTP layer (`admin.rs`) —
//! the gate stays custody + metering; provisioning changes WHO is metered,
//! never what a caller may do (control stays hooks + caps, arch.md §22d).

use std::path::PathBuf;
use std::sync::RwLock;

use rand_core::RngCore;

use crate::config::{GateConfig, KeysFile, RelayKey, UserBudget};
use crate::error::{GateError, GateResult};

/// Canonicalize 32-byte hex identifiers; preserve named identifiers.
pub fn canonical_key_id(id: &str) -> String {
    let trimmed = id.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        format!("0x{}", hex.to_ascii_lowercase())
    } else {
        trimmed.to_string()
    }
}

/// Boot rows spelled the pre-canonical way fold onto one id. Their secrets
/// all still authenticate (a live sandbox keeps working through the upgrade);
/// the next provision or disable of the id collapses them.
fn canonicalize_boot_keys(keys: &[RelayKey]) -> Vec<RelayKey> {
    let keys: Vec<RelayKey> = keys
        .iter()
        .cloned()
        .map(|mut k| {
            k.key_id = canonical_key_id(&k.key_id);
            k.device_id = canonical_key_id(&k.device_id);
            k
        })
        .collect();
    let mut live: std::collections::BTreeMap<&str, usize> = Default::default();
    for k in keys.iter().filter(|k| !k.disabled) {
        *live.entry(k.key_id.as_str()).or_default() += 1;
    }
    for (key_id, live_rows) in live.into_iter().filter(|(_, n)| *n > 1) {
        tracing::warn!(
            key_id,
            live_rows,
            "relay key id holds more than one live secret (a 0x/bare spelling split from \
             before ids were canonical) — each still authenticates until the next provision \
             or disable of this id collapses them to one"
        );
    }
    keys
}

/// Constant-time byte comparison (same rationale as `auth::ct_eq`).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// What the write-through re-serializes besides the live keys (the keys file
/// also carries user budgets + the default — preserved verbatim from boot).
struct PersistCtx {
    path: PathBuf,
    default_budget_tokens: Option<u64>,
    users: Vec<UserBudget>,
}

pub struct KeyStore {
    keys: RwLock<Vec<RelayKey>>,
    persist: Option<PersistCtx>,
}

/// The provision result — the secret is returned ONCE (the caller injects it
/// into the sandbox env and drops it; the file keeps it for restarts, 0600).
#[derive(Debug, serde::Serialize)]
pub struct ProvisionedKey {
    pub key_id: String,
    pub secret: String,
}

impl KeyStore {
    /// Seed from the boot config: its keys-file key set + the write-through
    /// context. No keys file ⇒ in-memory only, loudly logged (a restart drops
    /// broker-minted keys; the systemd unit always sets the file).
    pub fn from_config(config: &GateConfig) -> Self {
        let persist = match &config.keys_file {
            Some(path) => Some(PersistCtx {
                path: path.clone(),
                default_budget_tokens: config.default_budget_tokens,
                users: config
                    .user_budgets
                    .iter()
                    .map(|(u, b)| UserBudget {
                        user_omni: u.clone(),
                        budget_tokens: *b,
                    })
                    .collect(),
            }),
            None => {
                tracing::warn!(
                    "no keys file configured — admin-provisioned relay keys are IN-MEMORY \
                     only and will NOT survive a restart (set AGENTKEYS_GATE_KEYS_FILE)"
                );
                None
            }
        };
        Self {
            keys: RwLock::new(canonicalize_boot_keys(&config.keys)),
            persist,
        }
    }

    /// Resolve a bearer token to its key record. A DISABLED key is refused
    /// with the same 401 as an unknown one (no oracle on which it was).
    pub fn authenticate(&self, token: &str) -> GateResult<RelayKey> {
        self.keys
            .read()
            .expect("key store lock poisoned")
            .iter()
            .find(|k| !k.disabled && ct_eq(k.key.as_bytes(), token.as_bytes()))
            .cloned()
            .ok_or_else(|| GateError::Unauthorized("unknown relay key".into()))
    }

    /// #427 spawn provisioning: mint (or re-mint) the key for `key_id` —
    /// upsert semantics, so a re-provision rotates the secret + re-enables a
    /// disabled key (the idempotent-retry posture the broker relies on). The
    /// id is canonical first, and every other row of it is superseded — ONE
    /// live secret per id, whichever spelling the caller sent.
    #[allow(clippy::too_many_arguments)]
    pub fn provision(
        &self,
        key_id: &str,
        user_omni: &str,
        delegate_omni: Option<String>,
        device_id: &str,
        label: &str,
        budget_tokens: Option<u64>,
    ) -> GateResult<ProvisionedKey> {
        if key_id.trim().is_empty() || user_omni.trim().is_empty() {
            return Err(GateError::BadRequest(
                "key_id and user_omni are required".into(),
            ));
        }
        let key_id = canonical_key_id(key_id);
        let mut secret_bytes = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut secret_bytes);
        let secret = format!("gk_{}", hex_encode(&secret_bytes));
        let superseded = {
            let mut keys = self.keys.write().expect("key store lock poisoned");
            let record = RelayKey {
                key: secret.clone(),
                key_id: key_id.clone(),
                user_omni: agentkeys_protocol::normalize_omni_0x(user_omni),
                device_id: canonical_key_id(device_id),
                label: label.to_string(),
                delegate_omni: delegate_omni.map(|d| agentkeys_protocol::normalize_omni_0x(&d)),
                budget_tokens,
                disabled: false,
            };
            let before = keys.len();
            let mut placed = false;
            keys.retain_mut(|k| {
                if k.key_id != key_id {
                    return true;
                }
                if placed {
                    return false;
                }
                *k = record.clone();
                placed = true;
                true
            });
            let superseded = before - keys.len();
            if !placed {
                keys.push(record);
            }
            superseded
        };
        if superseded > 0 {
            tracing::info!(
                key_id = %key_id,
                superseded,
                "relay key re-provisioned — its other rows (a 0x/bare spelling split) are removed"
            );
        }
        self.write_through()?;
        Ok(ProvisionedKey { key_id, secret })
    }

    /// #427 archive deprovisioning: disable EVERY live row of the (canonical)
    /// key_id. `Ok(true)` = a live key was disabled; `Ok(false)` = unknown or
    /// already disabled (idempotent — the archive retry posture).
    pub fn disable(&self, key_id: &str) -> GateResult<bool> {
        let key_id = canonical_key_id(key_id);
        let changed = {
            let mut keys = self.keys.write().expect("key store lock poisoned");
            let mut changed = false;
            for k in keys
                .iter_mut()
                .filter(|k| k.key_id == key_id && !k.disabled)
            {
                k.disabled = true;
                changed = true;
            }
            changed
        };
        if changed {
            self.write_through()?;
        }
        Ok(changed)
    }

    /// The caller's per-key budget, read live (the record may have been
    /// re-provisioned since authentication).
    pub fn budget_for_key(&self, key_id: &str) -> Option<u64> {
        let key_id = canonical_key_id(key_id);
        self.keys
            .read()
            .expect("key store lock poisoned")
            .iter()
            .find(|k| k.key_id == key_id)
            .and_then(|k| k.budget_tokens)
    }

    /// Atomic write-through of the full keys file (tmp + rename, 0600). A
    /// failure is a hard error to the admin caller — a mutation the file
    /// doesn't carry would silently vanish on restart.
    fn write_through(&self) -> GateResult<()> {
        let Some(ctx) = &self.persist else {
            return Ok(());
        };
        let doc = KeysFile {
            default_budget_tokens: ctx.default_budget_tokens,
            users: ctx.users.clone(),
            keys: self.keys.read().expect("key store lock poisoned").clone(),
        };
        let json = serde_json::to_string_pretty(&doc)
            .map_err(|e| GateError::Internal(format!("keys file serialize: {e}")))?;
        let tmp = ctx.path.with_extension("json.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| GateError::Internal(format!("keys file write {tmp:?}: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &ctx.path)
            .map_err(|e| GateError::Internal(format!("keys file rename → {:?}: {e}", ctx.path)))?;
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamConfig;

    fn cfg(keys: Vec<RelayKey>, keys_file: Option<PathBuf>) -> GateConfig {
        GateConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: UpstreamConfig {
                base_url: "http://127.0.0.1:1/v1".into(),
                api_key: "upstream".into(),
                model_override: None,
                default_model: None,
            },
            keys,
            user_budgets: Default::default(),
            default_budget_tokens: Some(1000),
            admin_token: Some("admintok".into()),
            keys_file,
            audit_url: None,
            require_audit: false,
            aws_region: "us-east-1".into(),
            speech_backend: None,
            search: None,
            decision: Default::default(),
        }
    }

    fn boot_key(secret: &str, key_id: &str) -> RelayKey {
        RelayKey {
            key: secret.into(),
            key_id: key_id.into(),
            user_omni: format!("0x{}", "aa".repeat(32)),
            device_id: "esp32-01".into(),
            label: String::new(),
            delegate_omni: None,
            budget_tokens: None,
            disabled: false,
        }
    }

    #[test]
    fn provision_mints_a_usable_key_and_disable_refuses_it() {
        let store = KeyStore::from_config(&cfg(vec![], None));
        let minted = store
            .provision(
                &format!("0x{}", "11".repeat(32)),
                &"bb".repeat(32),
                Some("cc".repeat(32)),
                "dkh",
                "watchdog",
                Some(500),
            )
            .unwrap();
        assert!(minted.secret.starts_with("gk_"));
        let caller = store.authenticate(&minted.secret).unwrap();
        assert_eq!(caller.user_omni, format!("0x{}", "bb".repeat(32)));
        assert_eq!(
            caller.delegate_omni.as_deref(),
            Some(format!("0x{}", "cc".repeat(32)).as_str())
        );
        assert_eq!(caller.budget_tokens, Some(500));

        // Disable → the very same secret is refused with a plain 401.
        assert!(store.disable(&minted.key_id).unwrap());
        assert!(matches!(
            store.authenticate(&minted.secret),
            Err(GateError::Unauthorized(_))
        ));
        // Idempotent second disable.
        assert!(!store.disable(&minted.key_id).unwrap());
    }

    #[test]
    fn reprovision_rotates_the_secret_and_reenables() {
        let store = KeyStore::from_config(&cfg(vec![], None));
        let kid = "delegate-1";
        let first = store
            .provision(kid, &"bb".repeat(32), None, "dkh", "", None)
            .unwrap();
        store.disable(kid).unwrap();
        let second = store
            .provision(kid, &"bb".repeat(32), None, "dkh", "", None)
            .unwrap();
        assert_ne!(first.secret, second.secret);
        assert!(store.authenticate(&second.secret).is_ok());
        assert!(store.authenticate(&first.secret).is_err());
    }

    #[test]
    fn write_through_persists_boot_keys_plus_minted_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gate-keys.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "default_budget_tokens": 1000,
                "users": [],
                "keys": [{
                    "key": "gk_boot", "key_id": "boot-1",
                    "user_omni": "aa".repeat(32), "device_id": "esp32-01"
                }]
            })
            .to_string(),
        )
        .unwrap();
        // Simulate boot: parse like from_cli_with does.
        let parsed: KeysFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut config = cfg(parsed.keys, Some(path.clone()));
        config.default_budget_tokens = parsed.default_budget_tokens;
        let store = KeyStore::from_config(&config);

        store
            .provision(
                "delegate-1",
                &"bb".repeat(32),
                None,
                "dkh",
                "spawned",
                Some(9),
            )
            .unwrap();
        let reread: KeysFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(reread.default_budget_tokens, Some(1000));
        assert_eq!(reread.keys.len(), 2);
        let minted = reread
            .keys
            .iter()
            .find(|k| k.key_id == "delegate-1")
            .unwrap();
        assert_eq!(minted.budget_tokens, Some(9));
        assert!(!minted.disabled);
        // The boot key round-trips untouched.
        assert!(reread.keys.iter().any(|k| k.key_id == "boot-1"));
    }

    #[test]
    fn boot_disabled_key_never_authenticates() {
        let mut k = boot_key("gk_dead", "dead-1");
        k.disabled = true;
        let store = KeyStore::from_config(&cfg(vec![k], None));
        assert!(store.authenticate("gk_dead").is_err());
    }

    const DKH: &str = "5eed00c0ffee5eed00c0ffee5eed00c0ffee5eed00c0ffee5eed00c0ffee5eed";

    #[test]
    fn a_hex_id_has_one_spelling_and_other_ids_are_kept() {
        let canonical = format!("0x{DKH}");
        assert_eq!(canonical_key_id(DKH), canonical);
        assert_eq!(canonical_key_id(&canonical), canonical);
        assert_eq!(
            canonical_key_id(&format!("0X{}", DKH.to_uppercase())),
            canonical
        );
        assert_eq!(canonical_key_id(&format!(" {DKH} ")), canonical);
        for kept in ["k1", "contact-gate-router", "esp32-01", "0xabc", ""] {
            assert_eq!(canonical_key_id(kept), kept);
        }
    }

    /// Synthetic legacy spelling collision for one delegate.
    fn split_rows() -> Vec<RelayKey> {
        let mut prefixed = boot_key("gk_from_resolve", &format!("0x{DKH}"));
        prefixed.device_id = format!("0x{DKH}");
        let mut bare = boot_key("gk_from_wake", DKH);
        bare.device_id = DKH.to_string();
        vec![prefixed, bare]
    }

    #[test]
    fn a_split_delegate_keeps_both_secrets_until_its_id_is_touched() {
        let store = KeyStore::from_config(&cfg(split_rows(), None));
        // An upgrade breaks no live sandbox: both secrets still authenticate,
        // and both now attribute to the one canonical id.
        for secret in ["gk_from_resolve", "gk_from_wake"] {
            let caller = store.authenticate(secret).unwrap();
            assert_eq!(caller.key_id, format!("0x{DKH}"));
            assert_eq!(caller.device_id, format!("0x{DKH}"));
        }
    }

    #[test]
    fn archive_under_either_spelling_disables_every_row() {
        let store = KeyStore::from_config(&cfg(split_rows(), None));
        assert!(store.disable(DKH).unwrap());
        assert!(store.authenticate("gk_from_resolve").is_err());
        assert!(store.authenticate("gk_from_wake").is_err());
        assert!(!store.disable(&format!("0x{DKH}")).unwrap());
    }

    #[test]
    fn a_reprovision_under_either_spelling_leaves_one_live_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gate-keys.json");
        let store = KeyStore::from_config(&cfg(split_rows(), Some(path.clone())));
        let minted = store
            .provision(DKH, &"bb".repeat(32), None, DKH, "app", None)
            .unwrap();
        assert_eq!(minted.key_id, format!("0x{DKH}"));
        assert!(store.authenticate(&minted.secret).is_ok());
        assert!(store.authenticate("gk_from_resolve").is_err());
        assert!(store.authenticate("gk_from_wake").is_err());
        let reread: KeysFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(reread.keys.len(), 1);
        assert_eq!(reread.keys[0].key_id, format!("0x{DKH}"));
        assert_eq!(reread.keys[0].device_id, format!("0x{DKH}"));
    }
}
