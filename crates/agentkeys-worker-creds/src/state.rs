//! Worker process state — environment-driven config + shared S3 client.
//!
//! Per arch.md §22a, contract addresses are chain-profile-scoped. The
//! worker reads `AGENTKEYS_CHAIN` (default `heima`), uppercases it with
//! `-` → `_`, and looks up env keys `{NAME}_{PROFILE_UC}`. This matches
//! the layout `scripts/operator-workstation.env` writes via env_set in
//! `scripts/heima-bring-up.sh` step 6.

use std::sync::Arc;

use anyhow::{anyhow, Context};
use aws_sdk_s3::Client as S3Client;

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub vault_bucket: String,
    pub region: String,
    pub broker_pubkey_pem: String,
    pub chain_rpc_http: String,
    pub registry_contract: String,
    pub scope_contract: String,
    pub epoch_contract: String,
    /// Active chain profile name (e.g. "heima"). Surfaced for logs +
    /// /healthz.
    pub chain_profile: String,
    pub kek_hex_stage1: String,
}

impl WorkerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let chain_profile =
            std::env::var("AGENTKEYS_CHAIN").unwrap_or_else(|_| "heima".to_string());
        let profile_uc = chain_profile.to_uppercase().replace('-', "_");

        let vault_bucket = std::env::var("VAULT_BUCKET").context("VAULT_BUCKET must be set")?;
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|_| "us-east-1".into());
        let broker_pubkey_pem = std::env::var("BROKER_CAP_PUBKEY_PEM")
            .context("BROKER_CAP_PUBKEY_PEM must be set (P-256 SubjectPublicKeyInfo PEM)")?;
        let chain_rpc_http = std::env::var("AGENTKEYS_CHAIN_RPC_HTTP")
            .or_else(|_| std::env::var(format!("CHAIN_RPC_HTTP_{profile_uc}")))
            .or_else(|_| std::env::var("HEIMA_RPC_HTTP"))
            .context("AGENTKEYS_CHAIN_RPC_HTTP (or CHAIN_RPC_HTTP_<profile> or HEIMA_RPC_HTTP) must be set")?;
        let registry_contract = profile_env(&profile_uc, "SIDECAR_REGISTRY_ADDRESS")?;
        let scope_contract = profile_env(&profile_uc, "SCOPE_CONTRACT_ADDRESS")?;
        let epoch_contract = profile_env(&profile_uc, "K3_EPOCH_COUNTER_ADDRESS")?;
        let kek_hex_stage1 = std::env::var("AGENTKEYS_WORKER_KEK_HEX")
            .context("AGENTKEYS_WORKER_KEK_HEX must be set (32-byte hex). Stage 2 replaces this with mTLS-derived KEK")?;
        if kek_hex_stage1.len() != 64 {
            return Err(anyhow!(
                "AGENTKEYS_WORKER_KEK_HEX must be 64 hex chars (32 bytes), got {}",
                kek_hex_stage1.len()
            ));
        }
        // Reject obviously-weak KEK patterns (all zeros, all same byte).
        // Must decode to BYTES first — the prior "all same hex char"
        // check missed patterns like `0101…` which is the byte 0x01
        // repeated 32 times but with hex chars alternating between 0/1.
        // Codex audit finding.
        let kek_bytes = hex::decode(&kek_hex_stage1)
            .map_err(|e| anyhow!("AGENTKEYS_WORKER_KEK_HEX not valid hex: {e}"))?;
        if kek_bytes.iter().all(|&b| b == 0) {
            return Err(anyhow!(
                "AGENTKEYS_WORKER_KEK_HEX decodes to all zeros — rejecting (placeholder)"
            ));
        }
        if kek_bytes.iter().all(|&b| b == kek_bytes[0]) {
            return Err(anyhow!(
                "AGENTKEYS_WORKER_KEK_HEX decodes to all the same byte (0x{:02x}) — \
                 rejecting (placeholder)",
                kek_bytes[0]
            ));
        }
        // Fail-loud WARN per arch.md §22b.2 stage-1 simplifications inventory:
        // KEK from env is a stage-1 simplification; stage 2 (#91) replaces
        // with mTLS-attested derivation from the signer enclave.
        eprintln!(
            "==> ⚠️  WARN [arch.md §22b.2]: agentkeys-worker-creds running with env-injected \
             KEK (AGENTKEYS_WORKER_KEK_HEX) on chain={chain_profile}. This is the stage-1 \
             simplification. Stage 2 (issue #91) replaces with mTLS-derived KEK from the \
             signer enclave (arch.md §15.1)."
        );
        Ok(WorkerConfig {
            vault_bucket,
            region,
            broker_pubkey_pem,
            chain_rpc_http,
            registry_contract,
            scope_contract,
            epoch_contract,
            chain_profile,
            kek_hex_stage1,
        })
    }
}

/// Pure key-name builder, split from the env read so the substitution
/// logic is testable without touching process env (which is global —
/// `set_var` in one test leaks into parallel siblings).
fn profile_env_key(profile_uc: &str, base: &str) -> String {
    format!("{base}_{profile_uc}")
}

fn profile_env(profile_uc: &str, base: &str) -> anyhow::Result<String> {
    let key = profile_env_key(profile_uc, base);
    std::env::var(&key).with_context(|| format!("{key} must be set"))
}

pub struct WorkerState {
    pub config: WorkerConfig,
    pub s3: S3Client,
    pub http: reqwest::Client,
    /// Durable audit emitter (#229) — every store/fetch/teardown emits an
    /// `AuditEnvelope` to the audit-service worker after cap-verify.
    pub audit: crate::audit::AuditEmitter,
}

pub type SharedWorkerState = Arc<WorkerState>;

impl WorkerState {
    pub async fn build(config: WorkerConfig) -> anyhow::Result<Self> {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region.clone()))
            .load()
            .await;
        let s3 = S3Client::new(&sdk_config);
        Ok(WorkerState {
            config,
            s3,
            http: reqwest::Client::new(),
            audit: crate::audit::AuditEmitter::from_env(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_env_uppercase_underscore_substitution() {
        assert_eq!(
            profile_env_key("HEIMA_PASEO", "SOME_BASE"),
            "SOME_BASE_HEIMA_PASEO"
        );
        assert_eq!(
            profile_env_key("HEIMA", "SIDECAR_REGISTRY_ADDRESS"),
            "SIDECAR_REGISTRY_ADDRESS_HEIMA"
        );
    }
}
