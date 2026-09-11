//! Per-member iLink bots (2026-09-11).
//!
//! A clawbot is a special contact that exists only in the WeChat account that
//! scanned its login QR — measured by the owner: no sharing, no "add member",
//! no name card, absent on any other phone. So a household is NOT served by one
//! bot: it is served by **one bot per member**. Each member scans their own
//! connect QR (minted from their invite in parent-control), the gate custodies
//! one bot token per member, runs one inbound loop per token, and routes them
//! all to the same family agents. Tokens live in `ilink_tokens_file` (0600,
//! next to the secrets file); the legacy single `AGENTKEYS_WEIXIN_ILINK_BOT_TOKEN`
//! in the secrets file stays the OWNER's bot (contact `self-owner`), so a stack
//! armed before this change keeps working unchanged.
use std::collections::BTreeMap;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The owner's own contact id — the console mints its invite under this id,
/// and the legacy single-token bot maps onto it.
pub const OWNER_CONTACT_ID: &str = "self-owner";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberBot {
    pub token: String,
    pub base_url: String,
    pub bot_id: String,
    /// The iLink user id of the account that scanned — the member's WeChat as
    /// the gate sees it (`ilink_user_id` of the confirmed login).
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub connected_at_secs: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BotStore {
    /// Keyed by contact id.
    #[serde(default)]
    pub bots: BTreeMap<String, MemberBot>,
}

impl BotStore {
    pub fn load(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
                tracing::warn!(path, error = %e, "member bot tokens file unparsable — starting empty");
                BotStore::default()
            }),
            Err(_) => BotStore::default(),
        }
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let p = std::path::Path::new(path);
        if path.is_empty() {
            anyhow::bail!("no tokens file path configured");
        }
        if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp = format!("{path}.tmp");
        let raw = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, raw).with_context(|| format!("writing {tmp}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path).with_context(|| format!("renaming {tmp} → {path}"))?;
        Ok(())
    }
}

/// The tokens file lives next to the secrets file.
pub fn default_tokens_file(secrets_file: &str) -> String {
    let p = std::path::Path::new(secrets_file);
    match p.parent().filter(|d| !d.as_os_str().is_empty()) {
        Some(dir) => dir
            .join("weixin-ilink-tokens.json")
            .to_string_lossy()
            .to_string(),
        None => "weixin-ilink-tokens.json".to_string(),
    }
}

/// Each member's loop keeps its own cursor + context tokens: `<state_file>.<contact>`
/// (the owner keeps the legacy path).
pub fn member_state_file(base: &str, contact_id: &str) -> String {
    let safe: String = contact_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{base}.{safe}")
}

/// A member's bot is private to the account that scanned it, so the first
/// inbound on that bot names the member's transport id — learn it once. The
/// scan's `ilink_user_id` is recorded at connect and is normally the same id,
/// but the registry row is the routing truth, so it follows what the transport
/// actually sends. Never re-attributes an id another contact already owns.
pub fn learn_transport_id(state: &crate::state::WeixinGatewayState, contact_id: &str, from: &str) {
    if from.is_empty() {
        return;
    }
    let reg = state.registry.snapshot();
    let Some(c) = reg.bound.iter().find(|c| c.contact_id == contact_id) else {
        return;
    };
    if c.transport_id == from {
        return;
    }
    if reg
        .bound
        .iter()
        .any(|o| o.contact_id != contact_id && o.transport == "weixin" && o.transport_id == from)
    {
        tracing::warn!(contact = %contact_id, from, "inbound on a member's bot from an id bound to ANOTHER contact — not re-attributed");
        return;
    }
    let was = c.transport_id.clone();
    let res = state.registry.mutate(|r| {
        if let Some(m) = r.bound.iter_mut().find(|m| m.contact_id == contact_id) {
            m.transport_id = from.to_string();
        }
        Ok(())
    });
    match res {
        Ok(()) => {
            tracing::info!(contact = %contact_id, %was, now = %from, "member bot: transport id learned from its first inbound")
        }
        Err(e) => {
            tracing::warn!(contact = %contact_id, error = %e, "member bot: transport id NOT learned (registry write failed)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trips_with_0600_and_defaults_next_to_the_secrets() {
        let dir = std::env::temp_dir().join(format!("ak-bots-{}", std::process::id()));
        let path = dir.join("tokens.json").to_string_lossy().to_string();
        let mut s = BotStore::default();
        s.bots.insert(
            "c-wife".into(),
            MemberBot {
                token: "wife@im.bot:secret".into(),
                base_url: "https://ilink".into(),
                bot_id: "wife@im.bot".into(),
                user_id: "wife@im.wechat".into(),
                connected_at_secs: 7,
            },
        );
        s.save(&path).unwrap();
        let back = BotStore::load(&path);
        assert_eq!(
            back.bots.get("c-wife").map(|b| b.user_id.as_str()),
            Some("wife@im.wechat")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(BotStore::load("/definitely/missing/tokens.json")
            .bots
            .is_empty());
        assert!(BotStore::default().save("").is_err());
        assert_eq!(
            default_tokens_file("/etc/agentkeys/weixin-secrets.env"),
            "/etc/agentkeys/weixin-ilink-tokens.json"
        );
        assert_eq!(
            member_state_file("/var/lib/ak/ilink.json", "c-wife"),
            "/var/lib/ak/ilink.json.c-wife"
        );
        assert_eq!(member_state_file("s.json", "奶奶/1"), "s.json.___1");
        std::fs::remove_dir_all(&dir).ok();
    }
}
