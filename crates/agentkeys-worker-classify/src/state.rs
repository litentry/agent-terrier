use std::{sync::Arc, time::Duration};

use crate::catalog::Catalog;
use agentkeys_core::{capability_verify::AuthorityConfig, chain_profile::ChainProfile};

pub struct ClassifyWorkerConfig {
    pub authority: AuthorityConfig,
    pub chain_profile: String,
    pub browser_origins: String,
}

impl ClassifyWorkerConfig {
    pub fn local(
        profile: &ChainProfile,
        development: bool,
        broker_public_key: String,
        browser_origins: String,
    ) -> anyhow::Result<Self> {
        profile.require_local_development(development, None)?;
        Ok(Self {
            authority: AuthorityConfig::from_profile(profile, broker_public_key)?,
            chain_profile: profile.name.clone(),
            browser_origins,
        })
    }
}

pub struct ClassifyWorkerState {
    pub config: ClassifyWorkerConfig,
    pub http: reqwest::Client,
    pub catalog: Catalog,
}

pub type SharedClassifyWorkerState = Arc<ClassifyWorkerState>;

impl ClassifyWorkerState {
    pub fn build(config: ClassifyWorkerConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
            catalog: Catalog::bundled(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::chain_profile::{ChainKind, ContractInfo};
    use p256::pkcs8::{EncodePublicKey, LineEnding};

    #[test]
    fn local_classifier_requires_development_profile_contracts_and_valid_issuer() {
        let signer = p256::SecretKey::random(&mut rand_core::OsRng);
        let public = signer
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let mut profile = ChainProfile::load_builtin("anvil").unwrap();
        let configured = |profile: &ChainProfile, enabled| {
            ClassifyWorkerConfig::local(profile, enabled, public.clone(), String::new())
        };
        assert!(configured(&profile, true).is_err());
        profile.contracts = ["SidecarRegistry", "AgentKeysScope", "K3EpochCounter"]
            .iter()
            .enumerate()
            .map(|(index, name)| ContractInfo {
                name: name.to_string(),
                address: format!("0x{:040x}", index + 1),
                purpose: String::new(),
                deployed_at: String::new(),
            })
            .collect();
        assert!(configured(&profile, true).is_ok());
        assert!(configured(&profile, false).is_err());
        assert!(
            ClassifyWorkerConfig::local(&profile, true, "invalid".into(), String::new()).is_err()
        );
        profile.chain_kind = ChainKind::EthereumL1;
        assert!(configured(&profile, true).is_err());
        profile.chain_kind = ChainKind::LocalDev;
        profile.rpc.http = "http://192.0.2.1".into();
        assert!(configured(&profile, true).is_err());
    }
}
