use agentkeys_core::chain_profile::{rpc_http_override, ChainProfile};

pub(crate) fn profile() -> Result<ChainProfile, String> {
    let (mut profile, _) = ChainProfile::resolve(
        None,
        std::env::var("AGENTKEYS_CHAIN").ok().as_deref(),
        std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE")
            .ok()
            .as_deref(),
    )
    .map_err(|error| error.to_string())?;
    if let Some(endpoint) = rpc_http_override(&profile.name, |name| std::env::var(name).ok()) {
        profile.rpc.http = endpoint;
    }
    Ok(profile)
}

pub(crate) fn contract(profile: &ChainProfile, name: &str) -> Result<String, String> {
    let address = profile
        .contract(name)
        .ok_or_else(|| format!("chain profile is missing {name}"))?
        .address
        .clone();
    let decoded = hex::decode(address.strip_prefix("0x").unwrap_or(&address))
        .map_err(|_| format!("chain profile has invalid {name} address"))?;
    if decoded.len() != 20 || decoded == [0; 20] {
        return Err(format!("chain profile has invalid {name} address"));
    }
    Ok(address)
}
