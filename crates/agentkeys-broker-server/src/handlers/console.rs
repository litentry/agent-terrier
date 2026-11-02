use super::accept::{env_profile, load_chain_read_config};
use crate::{error::BrokerError, state::SharedState};
use agentkeys_core::chain_profile::ChainProfile;
use agentkeys_protocol::console_chain::{
    ConsoleChainInfo, ConsoleConfig, ConsoleContract, ConsoleFleet,
};
use axum::{extract::State, http::HeaderMap, Json};

pub(crate) fn profile() -> Result<ChainProfile, BrokerError> {
    crate::chain_config::profile().map_err(BrokerError::BackendUnreachable)
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
    let worker = |name: &str| {
        let key = format!("AGENTKEYS_WORKER_{}_URL", name.to_uppercase());
        worker_url(&broker, name, std::env::var(key).ok())
    };
    let required_worker = |name: &str| {
        worker(name)?.ok_or_else(|| {
            BrokerError::BackendUnreachable(format!("cannot derive {name} worker URL"))
        })
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
        config_url: required_worker("config")?,
        memory_url: required_worker("memory")?,
        credential_url: required_worker("cred")?,
        audit_url: worker("audit")?,
        channel_url: required_worker("channel")?,
        classify_url: required_worker("classify")?,
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

fn worker_url(
    broker: &str,
    name: &str,
    configured: Option<String>,
) -> Result<Option<String>, BrokerError> {
    match configured.filter(|value| !value.trim().is_empty()) {
        Some(value) if agentkeys_protocol::worker_override_matches_broker(&value, broker) => {
            Ok(Some(value))
        }
        Some(_) => Err(BrokerError::BackendUnreachable(format!(
            "{name} worker belongs to a different stack"
        ))),
        None => Ok(agentkeys_protocol::derive_worker_url(broker, name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_coordinates_preserve_explicit_and_derived_stack_boundaries() {
        let local = "http://127.0.0.1:4100";
        assert_eq!(worker_url(local, "audit", None).unwrap(), None);
        let configured = "http://127.0.0.1:4200".to_owned();
        assert_eq!(
            worker_url(local, "audit", Some(configured.clone())).unwrap(),
            Some(configured)
        );
        assert!(worker_url(local, "audit", Some("https://audit.foreign.example".into())).is_err());
        assert!(worker_url(
            "https://broker.public.example",
            "audit",
            Some("https://audit.foreign.example".into())
        )
        .is_err());
        assert_eq!(
            worker_url("https://broker.public.example", "audit", None).unwrap(),
            Some("https://audit.public.example".into())
        );
    }
}
