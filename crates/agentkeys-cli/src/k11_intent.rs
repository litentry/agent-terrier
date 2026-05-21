//! Typed K11 operation intent — replaces ad-hoc `--intent-field
//! "Label=Value"` strings across the harness with a single typed
//! contract per master-mutation operation.
//!
//! ## Why typed
//!
//! Before this module:
//!  - 7 bash scripts each built their own `--intent-field` string set.
//!  - Field names drifted across scripts ("Chain ID" vs "Chain").
//!  - Role bitfields were rendered as raw integers with a verbose
//!    `(bit0=CAP_MINT, bit1=RECOVERY, bit2=SCOPE_MGMT)` legend that
//!    repeated in every prompt the operator saw.
//!  - 0-means-unlimited amount semantics weren't decoded — operators
//!    saw `Max amount per call=0 (0 = unlimited)` instead of just
//!    `unlimited`.
//!  - Hashes (operator omni, device key hash, target hash) were
//!    rendered as full 66-char hex strings, blowing out the prompt
//!    width on smaller windows.
//!
//! After this module:
//!  - Scripts pass a single `--intent-op-json` flag (or POST body
//!    field) carrying a typed `K11OpIntent` variant.
//!  - `render()` produces the canonical `K11IntentContext` with all
//!    formatting concerns (role decoding, hash truncation, unlimited
//!    rendering, chain-id labeling) centralized HERE.
//!  - One change to a label / unit / decode rule updates every
//!    K11-emitting site simultaneously. No more cross-script drift.
//!
//! ## Wire format (JSON)
//!
//! Tagged enum via `serde(tag = "kind")`. Example for a scope grant:
//!
//! ```json
//! {
//!   "kind": "set_scope_grant",
//!   "agent_label": "demo-agent",
//!   "agent_omni": "0xb3224706…cc999E02",
//!   "services": ["openrouter", "brave-search"],
//!   "read_only": false,
//!   "max_per_call": "0",
//!   "max_per_period": "1000000000000000000",
//!   "period_seconds": 3600,
//!   "max_total": "0",
//!   "chain_id": 212013,
//!   "scope_nonce": 5,
//!   "asserting": { "kind": "primary", "device_key_hash": "0xde64…" }
//! }
//! ```
//!
//! All large numeric fields (`max_per_*`, `max_total`) are strings to
//! survive JSON's `u53` limit — they may exceed `2^53` when an
//! operator wants a value beyond the safe-integer range.

use serde::Deserialize;

use crate::k11_webauthn::K11IntentContext;

/// Which master is asserting in a multi-party ceremony. Renders as the
/// `Asserting role` row of the K11 confirmation page.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssertingRole {
    Primary {
        device_key_hash: String,
    },
    Companion {
        device_key_hash: String,
    },
}

impl AssertingRole {
    fn row(&self) -> (String, String) {
        match self {
            AssertingRole::Primary { device_key_hash } => (
                "Asserting role".into(),
                format!("PRIMARY (key hash {})", truncate_hash(device_key_hash)),
            ),
            AssertingRole::Companion { device_key_hash } => (
                "Asserting role".into(),
                format!("COMPANION (key hash {})", truncate_hash(device_key_hash)),
            ),
        }
    }
}

/// One variant per master-mutation operation. Scripts construct the
/// matching variant + pass it as JSON to `--intent-op-json` (CLI) or
/// `intent_op` (companion POST body).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum K11OpIntent {
    /// `AgentKeysScope.setScopeWithWebauthn(...)`
    SetScopeGrant {
        operator_omni: String,
        agent_label: String,
        agent_omni: String,
        services: Vec<String>,
        read_only: bool,
        max_per_call: String,
        max_per_period: String,
        period_seconds: u64,
        max_total: String,
        chain_id: u64,
        scope_nonce: u64,
        asserting: AssertingRole,
    },
    /// `AgentKeysScope.revokeScope(...)`
    SetScopeRevoke {
        operator_omni: String,
        agent_label: String,
        agent_omni: String,
        chain_id: u64,
        scope_nonce: u64,
        asserting: AssertingRole,
    },
    /// `SidecarRegistry.registerAdditionalMasterDevice(...)` — companion as the new 2nd master.
    RegisterCompanionAs2ndMaster {
        operator_omni: String,
        new_device_key_hash: String,
        companion_rp_id: String,
        roles: u8,
        chain_id: u64,
        operator_nonce: u64,
        asserting: AssertingRole,
    },
    /// `SidecarRegistry.registerAdditionalMasterDevice(...)` — synthetic 3rd master used in the demo's M-of-N revoke flow.
    RegisterSpareMaster {
        operator_omni: String,
        new_device_key_hash: String,
        roles: u8,
        chain_id: u64,
        operator_nonce: u64,
        asserting: AssertingRole,
    },
    /// `SidecarRegistry.setRecoveryThreshold(...)`
    SetRecoveryThreshold {
        operator_omni: String,
        new_threshold: u8,
        chain_id: u64,
        operator_nonce: u64,
        asserting: AssertingRole,
    },
    /// `SidecarRegistry.recoverViaQuorum(...)` — multi-party device revoke.
    /// Headline + per-op rows are identical for primary + companion;
    /// only `asserting` differs.
    RecoveryDeviceRevoke {
        operator_omni: String,
        target_device_key_hash: String,
        recovery_threshold: u8,
        chain_id: u64,
        operator_nonce: u64,
        asserting: AssertingRole,
    },
    /// `SidecarRegistry.revokeDevice(...)` — master target. Catastrophic;
    /// renders with the ⚠ warning prefix per the wiki convention.
    /// Some revoke paths are EOA-signed directly (not via K11Verifier
    /// chain payload), in which case `operator_nonce` doesn't apply
    /// and `recovery_threshold_remaining` may be unknown without an
    /// extra RPC — both fields are therefore optional; the renderer
    /// skips the row when None.
    RevokeMasterDevice {
        operator_omni: String,
        target_device_key_hash: String,
        #[serde(default)]
        recovery_threshold_remaining: Option<u8>,
        chain_id: u64,
        #[serde(default)]
        operator_nonce: Option<u64>,
        asserting: AssertingRole,
    },
    /// `SidecarRegistry.revokeDevice(...)` — agent target. Lower blast
    /// radius than master revoke; no warning prefix.
    RevokeAgentDevice {
        operator_omni: String,
        target_device_key_hash: String,
        #[serde(default)]
        agent_label: Option<String>,
        chain_id: u64,
        #[serde(default)]
        operator_nonce: Option<u64>,
        asserting: AssertingRole,
    },
}

impl K11OpIntent {
    /// Parse the JSON shape carried by `--intent-op-json` or the
    /// companion's POST body. Returns the typed variant ready for
    /// `render()`.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Render the typed intent to the on-page `K11IntentContext`.
    /// Centralizes every formatting concern (role decoding, hash
    /// truncation, "unlimited" rendering, chain-id labeling) so no
    /// per-operation script has to know how to format values.
    pub fn render(&self) -> K11IntentContext {
        let (text, fields) = match self {
            K11OpIntent::SetScopeGrant {
                operator_omni,
                agent_label,
                agent_omni,
                services,
                read_only,
                max_per_call,
                max_per_period,
                period_seconds,
                max_total,
                chain_id,
                scope_nonce,
                asserting,
            } => {
                let text = format!(
                    "Grant agent '{}' access to: {}",
                    agent_label,
                    services.join(", ")
                );
                let mut f = vec![
                    ("Operator omni".into(), truncate_hash(operator_omni)),
                    asserting.row(),
                    ("Agent label".into(), agent_label.clone()),
                    ("Agent omni".into(), truncate_hash(agent_omni)),
                    ("Services".into(), services.join(", ")),
                    (
                        "Access mode".into(),
                        if *read_only {
                            "read-only".into()
                        } else {
                            "read + write".into()
                        },
                    ),
                    ("Max per call".into(), format_amount(max_per_call)),
                    (
                        "Max per period".into(),
                        format!(
                            "{} over {}",
                            format_amount(max_per_period),
                            format_duration(*period_seconds)
                        ),
                    ),
                    ("Max total".into(), format_amount(max_total)),
                    ("Effect".into(),
                        "agent gains the listed access until the scope is revoked or its caps are exhausted".into()),
                    ("Chain".into(), format_chain_id(*chain_id)),
                    ("Scope nonce".into(), scope_nonce.to_string()),
                ];
                // Drop "Max per period" / "Max per call" / "Max total"
                // rows when all are zero (== fully unlimited) — keeps
                // the prompt concise. Operator sees only the rows that
                // carry information.
                if max_per_call == "0" && max_per_period == "0" && max_total == "0" {
                    f.retain(|(k, _)| {
                        k != "Max per call" && k != "Max per period" && k != "Max total"
                    });
                    f.insert(7, ("Spending limits".into(), "unlimited".into()));
                }
                (text, f)
            }
            K11OpIntent::SetScopeRevoke {
                operator_omni,
                agent_label,
                agent_omni,
                chain_id,
                scope_nonce,
                asserting,
            } => (
                format!("Revoke all scope grants for agent '{}'", agent_label),
                vec![
                    ("Operator omni".into(), truncate_hash(operator_omni)),
                    asserting.row(),
                    ("Agent label".into(), agent_label.clone()),
                    ("Agent omni".into(), truncate_hash(agent_omni)),
                    (
                        "Effect".into(),
                        "agent loses access to ALL services this scope previously granted".into(),
                    ),
                    ("Chain".into(), format_chain_id(*chain_id)),
                    ("Scope nonce".into(), scope_nonce.to_string()),
                ],
            ),
            K11OpIntent::RegisterCompanionAs2ndMaster {
                operator_omni,
                new_device_key_hash,
                companion_rp_id,
                roles,
                chain_id,
                operator_nonce,
                asserting,
            } => (
                "Register companion device as 2nd master".into(),
                vec![
                    ("Operator omni".into(), truncate_hash(operator_omni)),
                    asserting.row(),
                    ("New device".into(), truncate_hash(new_device_key_hash)),
                    ("Companion RP ID".into(), companion_rp_id.clone()),
                    ("Permissions".into(), format_roles(*roles)),
                    (
                        "Effect".into(),
                        "the companion can sign master-mutation ceremonies as a 2nd quorum vote".into(),
                    ),
                    ("Chain".into(), format_chain_id(*chain_id)),
                    ("Operator nonce".into(), operator_nonce.to_string()),
                ],
            ),
            K11OpIntent::RegisterSpareMaster {
                operator_omni,
                new_device_key_hash,
                roles,
                chain_id,
                operator_nonce,
                asserting,
            } => (
                "Register synthetic 3rd master (spare) device".into(),
                vec![
                    ("Operator omni".into(), truncate_hash(operator_omni)),
                    asserting.row(),
                    ("New spare device".into(), truncate_hash(new_device_key_hash)),
                    ("Permissions".into(), format_roles(*roles)),
                    (
                        "Effect".into(),
                        "adds a 3rd master to the operator's quorum (used by the M-of-N revoke demo)".into(),
                    ),
                    ("Chain".into(), format_chain_id(*chain_id)),
                    ("Operator nonce".into(), operator_nonce.to_string()),
                ],
            ),
            K11OpIntent::SetRecoveryThreshold {
                operator_omni,
                new_threshold,
                chain_id,
                operator_nonce,
                asserting,
            } => (
                format!("Set recovery threshold to {} (M-of-N master quorum)", new_threshold),
                vec![
                    ("Operator omni".into(), truncate_hash(operator_omni)),
                    asserting.row(),
                    ("New threshold".into(), new_threshold.to_string()),
                    (
                        "Effect".into(),
                        "future master-device revokes will require this many active master signatures".into(),
                    ),
                    ("Chain".into(), format_chain_id(*chain_id)),
                    ("Operator nonce".into(), operator_nonce.to_string()),
                ],
            ),
            K11OpIntent::RecoveryDeviceRevoke {
                operator_omni,
                target_device_key_hash,
                recovery_threshold,
                chain_id,
                operator_nonce,
                asserting,
            } => (
                "Revoke master device via M-of-N recovery quorum".into(),
                vec![
                    ("Operator omni".into(), truncate_hash(operator_omni)),
                    asserting.row(),
                    ("Target device".into(), truncate_hash(target_device_key_hash)),
                    ("Recovery threshold".into(), recovery_threshold.to_string()),
                    (
                        "Effect".into(),
                        "removes target from active master set; future cap-mint by this device is rejected on-chain".into(),
                    ),
                    ("Chain".into(), format_chain_id(*chain_id)),
                    ("Operator nonce".into(), operator_nonce.to_string()),
                ],
            ),
            K11OpIntent::RevokeMasterDevice {
                operator_omni,
                target_device_key_hash,
                recovery_threshold_remaining,
                chain_id,
                operator_nonce,
                asserting,
            } => {
                let mut f = vec![
                    ("Operator omni".into(), truncate_hash(operator_omni)),
                    asserting.row(),
                    ("Target device".into(), truncate_hash(target_device_key_hash)),
                ];
                if let Some(rem) = recovery_threshold_remaining {
                    f.push(("Recovery threshold remaining".into(), rem.to_string()));
                }
                f.push((
                    "Effect".into(),
                    "the operator loses this master device; recovery via remaining quorum or fresh init required to restore".into(),
                ));
                f.push(("Chain".into(), format_chain_id(*chain_id)));
                if let Some(n) = operator_nonce {
                    f.push(("Operator nonce".into(), n.to_string()));
                }
                (
                    // Catastrophic op → warning-prefix per wiki convention.
                    "⚠ REVOKE MASTER device — this disables the operator's master entirely".into(),
                    f,
                )
            }
            K11OpIntent::RevokeAgentDevice {
                operator_omni,
                target_device_key_hash,
                agent_label,
                chain_id,
                operator_nonce,
                asserting,
            } => {
                let headline = match agent_label.as_deref() {
                    Some(label) => format!("Revoke agent device for '{}'", label),
                    None => format!("Revoke agent device {}", truncate_hash(target_device_key_hash)),
                };
                let mut f = vec![
                    ("Operator omni".into(), truncate_hash(operator_omni)),
                    asserting.row(),
                ];
                if let Some(label) = agent_label {
                    f.push(("Agent label".into(), label.clone()));
                }
                f.push(("Target device".into(), truncate_hash(target_device_key_hash)));
                f.push((
                    "Effect".into(),
                    "agent device can no longer mint caps; previously-issued caps still work until expiry".into(),
                ));
                f.push(("Chain".into(), format_chain_id(*chain_id)));
                if let Some(n) = operator_nonce {
                    f.push(("Operator nonce".into(), n.to_string()));
                }
                (headline, f)
            }
        };
        K11IntentContext {
            text: Some(text),
            fields,
        }
    }
}

// ── Formatting helpers — single source of truth for every concern ─────────

/// Decode the role bitfield to a readable list of permission names.
/// Bits: `bit 0 = CAP_MINT`, `bit 1 = RECOVERY`, `bit 2 = SCOPE_MGMT`.
/// Higher bits surface as `bit<N>` so unknown future flags don't get
/// silently dropped.
fn format_roles(roles: u8) -> String {
    let mut names: Vec<String> = Vec::new();
    if roles & 0b001 != 0 {
        names.push("CAP_MINT".into());
    }
    if roles & 0b010 != 0 {
        names.push("RECOVERY".into());
    }
    if roles & 0b100 != 0 {
        names.push("SCOPE_MGMT".into());
    }
    // Surface any higher bits explicitly so a future role expansion
    // doesn't silently render as "the same 3 permissions" when the bit
    // is actually a new one we don't know yet.
    for bit in 3..8 {
        if roles & (1u8 << bit) != 0 {
            names.push(format!("bit{bit}(unknown)"));
        }
    }
    if names.is_empty() {
        format!("none (raw {roles})")
    } else {
        format!("{} (raw {})", names.join(" | "), roles)
    }
}

/// Truncate a 0x-prefixed hex string to `0x<first6>…<last5>` for
/// readability. Hashes shorter than 14 chars total are passed through.
fn truncate_hash(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() <= 14 {
        return trimmed.to_string();
    }
    let body = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if body.len() < 12 {
        return trimmed.to_string();
    }
    format!("0x{}…{}", &body[..6], &body[body.len() - 5..])
}

/// Render a "0 = unlimited" amount field. Non-zero raw strings pass
/// through unchanged so big U256 decimals stay accurate; zero becomes
/// the explicit "unlimited" word.
fn format_amount(raw: &str) -> String {
    let t = raw.trim();
    if t == "0" || t == "0x0" || t.is_empty() {
        "unlimited".into()
    } else {
        t.to_string()
    }
}

/// `3600` → `"1h"`; `86400` → `"1d"`; etc. Used for the period field
/// of scope grants.
fn format_duration(seconds: u64) -> String {
    if seconds == 0 {
        return "unlimited".into();
    }
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let mins = (seconds % 3_600) / 60;
    let secs = seconds % 60;
    let mut parts: Vec<String> = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if mins > 0 {
        parts.push(format!("{mins}m"));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!("{secs}s"));
    }
    parts.join(" ")
}

/// Render a chain ID with the known-network label when available.
fn format_chain_id(id: u64) -> String {
    match id {
        212013 => format!("Heima Mainnet ({id})"),
        // Heima Paseo (Frontier EVM testnet) — chain_id pinned in chain_profile.rs.
        420420421 => format!("Heima Paseo testnet ({id})"),
        31337 => format!("Anvil local ({id})"),
        1 => format!("Ethereum Mainnet ({id})"),
        8453 => format!("Base ({id})"),
        84532 => format!("Base Sepolia ({id})"),
        11155111 => format!("Ethereum Sepolia ({id})"),
        _ => format!("chain_id {id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_decode_canonical_combinations() {
        assert_eq!(format_roles(0), "none (raw 0)");
        assert_eq!(format_roles(0b001), "CAP_MINT (raw 1)");
        assert_eq!(format_roles(0b010), "RECOVERY (raw 2)");
        assert_eq!(format_roles(0b100), "SCOPE_MGMT (raw 4)");
        assert_eq!(format_roles(0b011), "CAP_MINT | RECOVERY (raw 3)");
        assert_eq!(format_roles(0b111), "CAP_MINT | RECOVERY | SCOPE_MGMT (raw 7)");
        // The user's specific complaint — `Role bitfield = 3` should
        // render as a readable permission list.
        let formatted = format_roles(3);
        assert!(formatted.contains("CAP_MINT"));
        assert!(formatted.contains("RECOVERY"));
        assert!(!formatted.contains("SCOPE_MGMT"));
    }

    #[test]
    fn roles_surface_unknown_future_bits() {
        assert_eq!(
            format_roles(0b1000),
            "bit3(unknown) (raw 8)"
        );
        // 0b1111 = CAP_MINT | RECOVERY | SCOPE_MGMT | bit3 unknown.
        let formatted = format_roles(0b1111);
        assert!(formatted.contains("CAP_MINT"));
        assert!(formatted.contains("bit3(unknown)"));
    }

    #[test]
    fn truncate_hash_keeps_short_values() {
        assert_eq!(truncate_hash("0xabcd"), "0xabcd");
        assert_eq!(truncate_hash("short"), "short");
    }

    #[test]
    fn truncate_hash_collapses_long_values() {
        let omni = "0x941cb1c3260518bbf40eac7d02663517fc7cff304d9b03e80d2cc54126c6bef2";
        // 64 hex chars in body → first 6 + last 5 → "0x941cb1…6bef2"
        assert_eq!(truncate_hash(omni), "0x941cb1…6bef2");
    }

    #[test]
    fn unlimited_amount_renders_as_word() {
        assert_eq!(format_amount("0"), "unlimited");
        assert_eq!(format_amount("0x0"), "unlimited");
        assert_eq!(format_amount(""), "unlimited");
        assert_eq!(format_amount("1000000000000000000"), "1000000000000000000");
    }

    #[test]
    fn duration_human_units() {
        assert_eq!(format_duration(0), "unlimited");
        assert_eq!(format_duration(1), "1s");
        assert_eq!(format_duration(60), "1m");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(86400), "1d");
        assert_eq!(format_duration(86400 + 3600 + 60 + 1), "1d 1h 1m 1s");
        assert_eq!(format_duration(7200), "2h");
    }

    #[test]
    fn chain_id_labels_known_networks() {
        assert!(format_chain_id(212013).contains("Heima Mainnet"));
        assert!(format_chain_id(31337).contains("Anvil"));
        assert!(format_chain_id(99999).starts_with("chain_id"));
    }

    /// Smoke test: round-trip JSON → typed → rendered. Confirms the
    /// scope-grant variant produces the expected concise prompt vs
    /// the old 11-row verbose dump.
    #[test]
    fn scope_grant_renders_concisely() {
        let json = r#"{
            "kind": "set_scope_grant",
            "operator_omni": "0x941cb1c3260518bbf40eac7d02663517fc7cff304d9b03e80d2cc54126c6bef2",
            "agent_label": "demo-agent",
            "agent_omni": "0xb3224706f0E33d6B36badb296B4F44BECc999E02b3224706f0E33d6B36bad000",
            "services": ["openrouter"],
            "read_only": false,
            "max_per_call": "0",
            "max_per_period": "0",
            "period_seconds": 3600,
            "max_total": "0",
            "chain_id": 212013,
            "scope_nonce": 5,
            "asserting": { "kind": "primary", "device_key_hash": "0xde644936d5b7d5d42032fd08bba42fbbfd6663bc" }
        }"#;
        let op = K11OpIntent::from_json(json).expect("valid JSON parses");
        let ctx = op.render();
        let text = ctx.text.as_deref().unwrap();
        assert_eq!(text, "Grant agent 'demo-agent' access to: openrouter");
        // When all amounts are 0, the prompt shows ONE "Spending limits"
        // row instead of three "Max per *" rows.
        let labels: Vec<&str> = ctx.fields.iter().map(|(l, _)| l.as_str()).collect();
        assert!(labels.contains(&"Spending limits"));
        assert!(!labels.contains(&"Max per call"));
        assert!(!labels.contains(&"Max per period"));
        assert!(!labels.contains(&"Max total"));
        // Operator omni is truncated, not full-length.
        let (_, omni_val) = ctx
            .fields
            .iter()
            .find(|(l, _)| l == "Operator omni")
            .unwrap();
        assert!(omni_val.contains('…'));
        // Chain rendered with label.
        let (_, chain_val) = ctx.fields.iter().find(|(l, _)| l == "Chain").unwrap();
        assert!(chain_val.contains("Heima Mainnet"));
    }

    /// Role bitfield decode end-to-end: a Register-companion intent
    /// with roles=3 must render the Permissions row as
    /// "CAP_MINT | RECOVERY (raw 3)" — answering the user's specific
    /// "Role bitfield = 3 should show a readable permission" feedback.
    #[test]
    fn register_companion_renders_decoded_roles() {
        let json = r#"{
            "kind": "register_companion_as2nd_master",
            "operator_omni": "0x941cb1c3260518bbf40eac7d02663517fc7cff304d9b03e80d2cc54126c6bef2",
            "new_device_key_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "companion_rp_id": "companion.localhost",
            "roles": 3,
            "chain_id": 212013,
            "operator_nonce": 7,
            "asserting": { "kind": "primary", "device_key_hash": "0xde644936d5b7d5d42032fd08bba42fbbfd6663bc" }
        }"#;
        let op = K11OpIntent::from_json(json).expect("valid JSON parses");
        let ctx = op.render();
        let (_, perms) = ctx
            .fields
            .iter()
            .find(|(l, _)| l == "Permissions")
            .unwrap();
        assert_eq!(perms, "CAP_MINT | RECOVERY (raw 3)");
    }

    /// Recovery ceremony — both PRIMARY and COMPANION roles produce
    /// identical headline + identical operation rows, differing ONLY
    /// in the Asserting role row. Verifies the multi-party uniformity
    /// rule from the wiki.
    #[test]
    fn recovery_uniform_across_primary_and_companion() {
        let make = |role_kind: &str, role_hash: &str| {
            format!(
                r#"{{
                    "kind": "recovery_device_revoke",
                    "operator_omni": "0x941cb1c3260518bbf40eac7d02663517fc7cff304d9b03e80d2cc54126c6bef2",
                    "target_device_key_hash": "0xdeadbeef00000000000000000000000000000000000000000000000000000000",
                    "recovery_threshold": 2,
                    "chain_id": 212013,
                    "operator_nonce": 9,
                    "asserting": {{ "kind": "{role_kind}", "device_key_hash": "{role_hash}" }}
                }}"#
            )
        };
        let primary = K11OpIntent::from_json(&make("primary", "0xprimaryhash0000000000000000000000000000000000000000000000000000"))
            .unwrap()
            .render();
        let companion = K11OpIntent::from_json(&make(
            "companion",
            "0xcompanionhash000000000000000000000000000000000000000000000000000",
        ))
        .unwrap()
        .render();
        assert_eq!(primary.text, companion.text);
        let prim_non_role: Vec<_> = primary
            .fields
            .iter()
            .filter(|(l, _)| l != "Asserting role")
            .collect();
        let comp_non_role: Vec<_> = companion
            .fields
            .iter()
            .filter(|(l, _)| l != "Asserting role")
            .collect();
        assert_eq!(prim_non_role, comp_non_role);
        let prim_role = primary.fields.iter().find(|(l, _)| l == "Asserting role").unwrap();
        let comp_role = companion.fields.iter().find(|(l, _)| l == "Asserting role").unwrap();
        assert!(prim_role.1.starts_with("PRIMARY"));
        assert!(comp_role.1.starts_with("COMPANION"));
    }
}
