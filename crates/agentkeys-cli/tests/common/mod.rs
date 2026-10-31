pub fn development_signing() -> agentkeys_cli::development_signing::DevelopmentSigning {
    let mut profile = agentkeys_core::chain_profile::ChainProfile::load_builtin("anvil").unwrap();
    profile
        .contracts
        .push(agentkeys_core::chain_profile::ContractInfo {
            name: "EntryPoint".into(),
            address: format!("0x{:040x}", 2),
            purpose: String::new(),
            deployed_at: String::new(),
        });
    agentkeys_cli::development_signing::DevelopmentSigning::new(&profile, true, None).unwrap()
}
