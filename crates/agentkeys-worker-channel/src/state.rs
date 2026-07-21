//! Channel worker process state — mirrors the config worker but with a distinct
//! bucket (`$CHANNEL_BUCKET`) per arch.md §17.2 per-data-class separation, plus
//! the in-process NRT wakeup registry (§14.12).

use std::sync::Arc;

use anyhow::{anyhow, Context};

use crate::sts_mint::ChannelStsMinter;
use crate::wakeup::WakeupRegistry;

/// Long-poll ceiling default when `AGENTKEYS_CHANNEL_MAX_POLL_SECONDS` is unset.
/// Matches the F2 broker long-poll shape (§14 — hold ≤25 s).
const DEFAULT_MAX_POLL_SECONDS: u64 = 25;
/// #522 — inline `body_b64` ceiling (DECODED bytes). Voice clips ride inline
/// (a 20 s wav ≈ 640 KB); anything bigger belongs in `body_ref`. Override:
/// `AGENTKEYS_CHANNEL_INLINE_MAX_BYTES`.
const DEFAULT_INLINE_MAX_BYTES: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct ChannelWorkerConfig {
    pub channel_bucket: String,
    pub region: String,
    pub broker_pubkey_pem: String,
    pub chain_rpc_http: String,
    pub registry_contract: String,
    pub scope_contract: String,
    pub epoch_contract: String,
    pub chain_profile: String,
    /// Worker-held envelope KEK (stage 1 — the channel feed is worker-encrypted
    /// today, exactly like the memory worker). Feeds are OPERATOR-owned since
    /// #430 (D8: `bots/<operator>/channel/<id>/` is the household bus every
    /// granted actor meets on); the signer-derived-KEK v3 path stays a
    /// follow-up, as does per-actor STS for cross-actor channel S3 (today the
    /// cross-actor path rides the worker role when the caller passes no STS).
    pub kek_hex: String,
    /// Long-poll ceiling: the max seconds a `/v1/channel/poll` request is held
    /// when no event is immediately available (§14.12 NRT).
    pub max_poll_seconds: u64,
    /// #522 — max DECODED bytes an inline `body_b64` may carry; larger payloads
    /// must ride `body_ref` (413 `channel_body_too_large` otherwise — there was
    /// previously NO size validation at all, only axum's implicit ~2 MB).
    pub inline_max_bytes: usize,
}

impl ChannelWorkerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let chain_profile =
            std::env::var("AGENTKEYS_CHAIN").unwrap_or_else(|_| "heima".to_string());
        let profile_uc = chain_profile.to_uppercase().replace('-', "_");

        let channel_bucket = std::env::var("CHANNEL_BUCKET").context(
            "CHANNEL_BUCKET must be set (per arch.md §17.2 distinct from MEMORY_BUCKET / \
             VAULT_BUCKET / CONFIG_BUCKET)",
        )?;
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|_| "us-east-1".into());
        let broker_pubkey_pem =
            std::env::var("BROKER_CAP_PUBKEY_PEM").context("BROKER_CAP_PUBKEY_PEM must be set")?;
        let chain_rpc_http = std::env::var("AGENTKEYS_CHAIN_RPC_HTTP")
            .or_else(|_| std::env::var(format!("CHAIN_RPC_HTTP_{profile_uc}")))
            .or_else(|_| std::env::var("HEIMA_RPC_HTTP"))
            .context("AGENTKEYS_CHAIN_RPC_HTTP must be set")?;
        let registry_contract = profile_env(&profile_uc, "SIDECAR_REGISTRY_ADDRESS")?;
        let scope_contract = profile_env(&profile_uc, "SCOPE_CONTRACT_ADDRESS")?;
        let epoch_contract = profile_env(&profile_uc, "K3_EPOCH_COUNTER_ADDRESS")?;

        let kek_hex = std::env::var("AGENTKEYS_CHANNEL_KEK_HEX").context(
            "AGENTKEYS_CHANNEL_KEK_HEX must be set (64 hex chars, the feed envelope KEK)",
        )?;
        validate_kek(&kek_hex)?;

        let max_poll_seconds = std::env::var("AGENTKEYS_CHANNEL_MAX_POLL_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_POLL_SECONDS);
        let inline_max_bytes = std::env::var("AGENTKEYS_CHANNEL_INLINE_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_INLINE_MAX_BYTES);

        Ok(ChannelWorkerConfig {
            channel_bucket,
            region,
            broker_pubkey_pem,
            chain_rpc_http,
            registry_contract,
            scope_contract,
            epoch_contract,
            chain_profile,
            kek_hex,
            max_poll_seconds,
            inline_max_bytes,
        })
    }
}

/// Reject the obvious placeholder KEKs (all-zero / single-repeated-byte), the
/// same guard the config worker applies. Decode to BYTES first so alternating
/// hex like `0101…` is caught (a codex audit finding on the config worker).
fn validate_kek(kek_hex: &str) -> anyhow::Result<()> {
    if kek_hex.len() != 64 {
        return Err(anyhow!(
            "AGENTKEYS_CHANNEL_KEK_HEX must be 64 hex chars (32 bytes), got {}",
            kek_hex.len()
        ));
    }
    let kek_bytes = hex::decode(kek_hex)
        .map_err(|e| anyhow!("AGENTKEYS_CHANNEL_KEK_HEX not valid hex: {e}"))?;
    if kek_bytes.iter().all(|&b| b == 0) {
        return Err(anyhow!(
            "AGENTKEYS_CHANNEL_KEK_HEX decodes to all zeros — rejecting (placeholder)"
        ));
    }
    if kek_bytes.iter().all(|&b| b == kek_bytes[0]) {
        return Err(anyhow!(
            "AGENTKEYS_CHANNEL_KEK_HEX decodes to all the same byte (0x{:02x}) — rejecting \
             (placeholder)",
            kek_bytes[0]
        ));
    }
    Ok(())
}

fn profile_env(profile_uc: &str, base: &str) -> anyhow::Result<String> {
    let key = format!("{base}_{profile_uc}");
    std::env::var(&key).with_context(|| format!("{key} must be set"))
}

pub struct ChannelWorkerState {
    pub config: ChannelWorkerConfig,
    pub http: reqwest::Client,
    /// #541 — the cap→STS minter (`/v1/cap/channel-sts`). `None` when the host
    /// env lacks `AGENTKEYS_BROKER_URL`/`AGENTKEYS_CHANNEL_STS_TOKEN`; the
    /// worker then serves header-relayed requests only and every other storage
    /// touch fails LOUDLY. There is deliberately NO ambient S3 client in this
    /// state anymore — the instance-profile path is retired, not deprecated.
    pub sts_minter: Option<ChannelStsMinter>,
    /// Durable audit emitter (#229) — every publish/poll/teardown emits an
    /// `AuditEnvelope` to the audit-service worker after cap-verify.
    pub audit: agentkeys_worker_creds::audit::AuditEmitter,
    /// The NRT write-through wakeup registry (§14.12).
    pub wakeup: WakeupRegistry,
}

pub type SharedChannelWorkerState = Arc<ChannelWorkerState>;

impl ChannelWorkerState {
    pub async fn build(config: ChannelWorkerConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::new();
        let sts_minter = ChannelStsMinter::from_env(http.clone());
        if sts_minter.is_none() {
            tracing::warn!(
                "channel-sts minter DISABLED (AGENTKEYS_BROKER_URL / AGENTKEYS_CHANNEL_STS_TOKEN \
                 unset): only requests relaying X-Aws-* creds can touch storage; everything else \
                 fails loudly — ambient (instance-profile) access is retired (#541)"
            );
        }
        Ok(ChannelWorkerState {
            config,
            http,
            sts_minter,
            audit: agentkeys_worker_creds::audit::AuditEmitter::from_env(),
            wakeup: WakeupRegistry::new(),
        })
    }
}
