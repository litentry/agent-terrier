//! Classifier worker process state. A COMPUTE gate (#178 §15.6): it needs the
//! broker cap pubkey + the chain RPC/contracts for the SAME cap-verify chain the
//! storage workers run (isolation layers 1-2), but NO S3 bucket / KEK (the effect
//! is inference over the in-process catalog, not an encrypted S3 write).

use std::sync::Arc;

use anyhow::Context;

use crate::catalog::Catalog;

#[derive(Debug, Clone)]
pub struct ClassifyWorkerConfig {
    pub broker_pubkey_pem: String,
    pub chain_rpc_http: String,
    pub registry_contract: String,
    pub scope_contract: String,
    pub epoch_contract: String,
    pub chain_profile: String,
}

impl ClassifyWorkerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let chain_profile =
            std::env::var("AGENTKEYS_CHAIN").unwrap_or_else(|_| "heima".to_string());
        let profile_uc = chain_profile.to_uppercase().replace('-', "_");

        let broker_pubkey_pem =
            std::env::var("BROKER_CAP_PUBKEY_PEM").context("BROKER_CAP_PUBKEY_PEM must be set")?;
        let chain_rpc_http = std::env::var("AGENTKEYS_CHAIN_RPC_HTTP")
            .or_else(|_| std::env::var(format!("CHAIN_RPC_HTTP_{profile_uc}")))
            .or_else(|_| std::env::var("HEIMA_RPC_HTTP"))
            .context("AGENTKEYS_CHAIN_RPC_HTTP must be set")?;
        let registry_contract = profile_env(&profile_uc, "SIDECAR_REGISTRY_ADDRESS")?;
        let scope_contract = profile_env(&profile_uc, "SCOPE_CONTRACT_ADDRESS")?;
        let epoch_contract = profile_env(&profile_uc, "K3_EPOCH_COUNTER_ADDRESS")?;
        Ok(ClassifyWorkerConfig {
            broker_pubkey_pem,
            chain_rpc_http,
            registry_contract,
            scope_contract,
            epoch_contract,
            chain_profile,
        })
    }
}

fn profile_env(profile_uc: &str, base: &str) -> anyhow::Result<String> {
    let key = format!("{base}_{profile_uc}");
    std::env::var(&key).with_context(|| format!("{key} must be set"))
}

pub struct ClassifyWorkerState {
    pub config: ClassifyWorkerConfig,
    pub http: reqwest::Client,
    pub catalog: Catalog,
}

pub type SharedClassifyWorkerState = Arc<ClassifyWorkerState>;

impl ClassifyWorkerState {
    pub fn build(config: ClassifyWorkerConfig) -> Self {
        ClassifyWorkerState {
            config,
            http: reqwest::Client::new(),
            catalog: Catalog::bundled(),
        }
    }
}
