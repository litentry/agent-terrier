use std::collections::BTreeMap;

use agentkeys_core::chain_profile::ChainProfile;
use agentkeys_protocol::{model_runtime, sandbox_env};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

pub const BOOTSTRAP_VERSION: u32 = 1;
pub const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;
pub const STARTUP_TIMEOUT_SECONDS: u64 = 30;
pub const RUNTIME_SCRIPT: &str = "/opt/terrier/packages/agent-terrier-runtime/start.mjs";

const ENDPOINTS: &[&str] = &[
    sandbox_env::BROKER_URL,
    sandbox_env::SIGNER_URL,
    sandbox_env::CHANNEL_WORKER_URL,
    "AGENTKEYS_WORKER_CRED_URL",
    "AGENTKEYS_WORKER_MEMORY_URL",
    "AGENTKEYS_WORKER_CONFIG_URL",
    model_runtime::BASE_URL,
];
const TOKENS: &[&str] = &[
    sandbox_env::SESSION_JWT,
    sandbox_env::BRIDGE_TOKEN,
    sandbox_env::MGMT_TOKEN,
    model_runtime::API_KEY,
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBootstrap {
    pub version: u32,
    pub chain_profile: ChainProfile,
    pub environment: BTreeMap<String, String>,
}

impl RuntimeBootstrap {
    pub fn agent_environment(&self) -> BTreeMap<String, String> {
        self.environment
            .iter()
            .filter(|(name, _)| {
                [
                    model_runtime::BASE_URL,
                    model_runtime::API_KEY,
                    model_runtime::MODEL_ID,
                    sandbox_env::BRIDGE_TOKEN,
                    sandbox_env::MGMT_TOKEN,
                ]
                .contains(&name.as_str())
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == BOOTSTRAP_VERSION,
            "unsupported bootstrap version"
        );
        self.chain_profile.require_local_development(true, None)?;
        for name in self.environment.keys() {
            ensure!(
                ENDPOINTS.contains(&name.as_str())
                    || TOKENS.contains(&name.as_str())
                    || [
                        sandbox_env::ACTOR_OMNI,
                        sandbox_env::OPERATOR_OMNI,
                        sandbox_env::CHAT_CHANNEL_ID,
                        model_runtime::MODEL_ID
                    ]
                    .contains(&name.as_str()),
                "unsupported bootstrap environment field"
            );
        }
        for name in ENDPOINTS {
            let value = self.value(name)?;
            agentkeys_protocol::model_config::require_local_endpoint(value)
                .map_err(anyhow::Error::msg)?;
            if *name != model_runtime::BASE_URL {
                ensure!(
                    reqwest::Url::parse(value)?.path() == "/",
                    "service endpoint must be an origin"
                );
            }
        }
        for name in TOKENS {
            let value = self.value(name)?;
            ensure!(
                value.len() >= 16
                    && value.len() <= 16 * 1024
                    && !value
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()),
                "invalid bootstrap credential"
            );
        }
        for name in [sandbox_env::ACTOR_OMNI, sandbox_env::OPERATOR_OMNI] {
            let value = self
                .value(name)?
                .strip_prefix("0x")
                .unwrap_or(self.value(name)?);
            ensure!(
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid bootstrap actor identity"
            );
        }
        for name in [sandbox_env::CHAT_CHANNEL_ID, model_runtime::MODEL_ID] {
            let value = self.value(name)?;
            ensure!(
                !value.is_empty()
                    && value.len() <= 256
                    && !value
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()),
                "invalid bootstrap model or channel identifier"
            );
        }
        model_runtime::validate_environment(|name| self.environment.get(name).map(String::as_str))
            .map_err(anyhow::Error::msg)
    }

    fn value(&self, name: &str) -> Result<&str> {
        self.environment
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow::anyhow!("incomplete bootstrap configuration"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> RuntimeBootstrap {
        let mut environment = BTreeMap::new();
        for name in ENDPOINTS {
            environment.insert((*name).into(), "http://127.0.0.1:1".into());
        }
        for name in TOKENS {
            environment.insert((*name).into(), "synthetic-proof-only".into());
        }
        for name in [sandbox_env::ACTOR_OMNI, sandbox_env::OPERATOR_OMNI] {
            environment.insert(name.into(), "ab".repeat(32));
        }
        environment.insert(sandbox_env::CHAT_CHANNEL_ID.into(), "opchat-test".into());
        environment.insert(model_runtime::MODEL_ID.into(), "fixture-model".into());
        RuntimeBootstrap {
            version: BOOTSTRAP_VERSION,
            chain_profile: ChainProfile::load_builtin("anvil").unwrap(),
            environment,
        }
    }

    #[test]
    fn bootstrap_requires_explicit_local_services_and_scoped_credentials() {
        let valid = fixture();
        valid.validate().unwrap();
        let agent_environment = valid.agent_environment();
        assert_eq!(agent_environment.len(), 5);
        assert!(!agent_environment.contains_key(sandbox_env::SESSION_JWT));
        assert!(!agent_environment.contains_key(sandbox_env::SIGNER_URL));
        assert_eq!(
            agent_environment[model_runtime::API_KEY],
            valid.environment[model_runtime::API_KEY]
        );
        for name in valid.environment.keys() {
            let mut invalid = fixture();
            invalid.environment.remove(name);
            assert!(
                invalid.validate().is_err(),
                "missing required field accepted"
            );
        }
        for (name, value) in [
            (sandbox_env::BROKER_URL, "https://example.invalid"),
            (sandbox_env::SIGNER_URL, "http://127.0.0.1:1/wrong"),
            (model_runtime::BASE_URL, "http://secret@localhost/v1"),
            (sandbox_env::SESSION_JWT, "secret\nsecond-line"),
            (sandbox_env::ACTOR_OMNI, "wrong-actor"),
            (sandbox_env::DEVICE_KEY_HEX, "never-pass-private-keys"),
            ("NODE_OPTIONS", "--require=arbitrary-code"),
        ] {
            let mut invalid = fixture();
            invalid.environment.insert(name.into(), value.into());
            let error = invalid.validate().unwrap_err().to_string();
            assert!(!error.contains(value));
        }
        let mut invalid = fixture();
        invalid.chain_profile.chain_id = 1;
        assert!(invalid.validate().is_err());
        invalid = fixture();
        invalid.version += 1;
        assert!(invalid.validate().is_err());
    }
}
