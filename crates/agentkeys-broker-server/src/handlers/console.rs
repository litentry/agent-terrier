use super::accept::{env_profile, load_chain_read_config};
use crate::{error::BrokerError, state::SharedState};
use agentkeys_core::chain_profile::ChainProfile;
use agentkeys_protocol::console_chain::{
    ConsoleChainInfo, ConsoleConfig, ConsoleContract, ConsoleFleet,
};
use axum::{extract::State, http::HeaderMap, Json};

pub(crate) fn profile() -> Result<ChainProfile, BrokerError> {
    ChainProfile::resolve(
        None,
        std::env::var("AGENTKEYS_CHAIN").ok().as_deref(),
        std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE")
            .ok()
            .as_deref(),
    )
    .map(|(profile, _)| profile)
    .map_err(|error| BrokerError::BackendUnreachable(error.to_string()))
}

pub async fn config(State(state): State<SharedState>) -> Result<Json<ConsoleConfig>, BrokerError> {
    let mut profile = profile()?;
    let (rpc, registry) = load_chain_read_config().map_err(BrokerError::BackendUnreachable)?;
    profile.rpc.http = rpc;
    let broker = state.config.oidc_issuer.trim_end_matches('/').to_owned();
    for (name, env) in [
        ("SidecarRegistry", "SIDECAR_REGISTRY_ADDRESS"),
        ("AgentKeysScope", "SCOPE_CONTRACT_ADDRESS"),
        ("EntryPoint", "ENTRYPOINT_ADDRESS"),
    ] {
        let address = if name == "SidecarRegistry" {
            format!("0x{}", hex::encode(registry))
        } else {
            env_profile(env).map_err(BrokerError::BackendUnreachable)?
        };
        let contract = profile
            .contracts
            .iter_mut()
            .find(|contract| contract.name == name)
            .ok_or_else(|| {
                BrokerError::BackendUnreachable(format!("chain profile missing {name}"))
            })?;
        contract.address = address;
    }
    let audit = super::anchor::audit_contract_for_registry(&registry)
        .map(|address| format!("0x{}", hex::encode(address)));
    if let Some(contract) = profile
        .contracts
        .iter_mut()
        .find(|contract| contract.name == "CredentialAudit")
    {
        if let Some(address) = audit {
            contract.address = address;
        } else {
            profile
                .contracts
                .retain(|contract| contract.name != "CredentialAudit");
        }
    }
    let worker = |name: &str| -> Result<String, BrokerError> {
        let key = format!("AGENTKEYS_WORKER_{}_URL", name.to_uppercase());
        match std::env::var(key)
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(value) if agentkeys_protocol::worker_override_matches_broker(&value, &broker) => {
                Ok(value)
            }
            Some(_) => Err(BrokerError::BackendUnreachable(format!(
                "{name} worker belongs to a different stack"
            ))),
            None => agentkeys_protocol::derive_worker_url(&broker, name).ok_or_else(|| {
                BrokerError::BackendUnreachable(format!("cannot derive {name} worker URL"))
            }),
        }
    };
    let chain = ConsoleChainInfo {
        name: profile.name.clone(),
        display: profile.display_name,
        chain_id: profile.chain_id,
        rpc: profile.rpc.http,
        wss: profile.rpc.wss,
        explorer: profile.explorer.url.clone(),
        token_symbol: profile.token.symbol,
        token_decimals: profile.token.decimals,
        finality: profile.finality.default_block_tag,
        contracts: profile
            .contracts
            .iter()
            .map(|contract| ConsoleContract {
                name: contract.name.clone(),
                address: contract.address.clone(),
                purpose: contract.purpose.clone(),
                deployed_at: contract.deployed_at.clone(),
                explorer_url: profile.explorer.contract_url(&contract.address),
            })
            .collect(),
        daemon_chain: profile.name,
        daemon_broker: broker.clone(),
    };
    Ok(Json(ConsoleConfig {
        chain,
        signer_url: super::auth::session::signer_url(&state)?,
        config_url: worker("config")?,
        memory_url: worker("memory")?,
        credential_url: worker("cred")?,
        audit_url: worker("audit")?,
        channel_url: worker("channel")?,
        classify_url: worker("classify")?,
    }))
}

pub async fn fleet(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<ConsoleFleet>, BrokerError> {
    let claims = super::wallet::require_master_session(&headers, &state)?;
    if !matches!(claims.agentkeys.identity_type.as_str(), "evm" | "passkey") {
        return Err(BrokerError::Unauthorized(
            "verified master session required".into(),
        ));
    }
    state
        .config
        .login_access
        .require_omni(&state, &claims.agentkeys.omni_account)
        .await?;
    let (rpc, registry) = load_chain_read_config().map_err(BrokerError::BackendUnreachable)?;
    let scope = env_profile("SCOPE_CONTRACT_ADDRESS").map_err(BrokerError::BackendUnreachable)?;
    let fleet = agentkeys_web_core::chain::read_fleet(
        &state.http,
        &rpc,
        &format!("0x{}", hex::encode(registry)),
        &scope,
        &claims.agentkeys.omni_account,
    )
    .await
    .map_err(BrokerError::BackendUnreachable)?;
    Ok(Json(fleet))
}
