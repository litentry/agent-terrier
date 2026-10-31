//! Explicit relay configuration; no host credential discovery.

use crate::speech::SpeechBackend;
use agentkeys_core::{models, protected_file};
use agentkeys_protocol::{normalize_omni_0x, DecisionProvider};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Parser, Clone)]
#[command(name = "agentkeys-gate", about = "Authenticated, metered model relay")]
pub struct Cli {
    #[arg(long, env = "AGENTKEYS_GATE_LISTEN", default_value = "127.0.0.1:8077")]
    pub listen: SocketAddr,
    /// Explicit compatible endpoint; defaults to the local model recipe.
    #[arg(long, env = "AGENTKEYS_GATE_UPSTREAM_BASE_URL")]
    pub upstream_base_url: Option<String>,
    /// Optional explicit credential. Prefer the protected file form.
    #[arg(
        long,
        env = "AGENTKEYS_GATE_UPSTREAM_API_KEY",
        hide_env_values = true,
        conflicts_with = "upstream_api_key_file"
    )]
    pub upstream_api_key: Option<String>,
    #[arg(long, env = "AGENTKEYS_GATE_UPSTREAM_API_KEY_FILE")]
    pub upstream_api_key_file: Option<PathBuf>,
    /// Override the requested chat model.
    #[arg(long, env = "AGENTKEYS_GATE_MODEL")]
    pub model: Option<String>,
    /// Default for a request with no model; defaults to the local recipe.
    #[arg(long, env = "AGENTKEYS_GATE_DEFAULT_MODEL")]
    pub default_model: Option<String>,
    /// Explicit protected JSON describing optional decision endpoints.
    #[arg(long, env = "AGENTKEYS_GATE_DECISION_CONFIG")]
    pub decision_config: Option<PathBuf>,
    /// Owner-only relay key records and budgets. Absent means no callers are authorized.
    #[arg(long, env = "AGENTKEYS_GATE_KEYS_FILE")]
    pub keys_file: Option<PathBuf>,
    #[arg(long, env = "AGENTKEYS_GATE_DEFAULT_BUDGET_TOKENS")]
    pub default_budget_tokens: Option<u64>,
    #[arg(long, env = "AGENTKEYS_GATE_ADMIN_TOKEN", hide_env_values = true)]
    pub admin_token: Option<String>,
    #[arg(long, env = "AGENTKEYS_AUDIT_URL")]
    pub audit_url: Option<String>,
    #[arg(long, env = "AGENTKEYS_GATE_REQUIRE_AUDIT", default_value_t = false)]
    pub require_audit: bool,
    #[arg(long, env = "AGENTKEYS_GATE_SEARCH_URL")]
    pub search_url: Option<String>,
    #[arg(long, env = "AGENTKEYS_GATE_SEARCH_ENGINES", default_value = "")]
    pub search_engines: String,
}

/// One relay key record: the caller credential a sandbox/device presents,
/// bound to the owning user + the device it is attributed to.
/// Serialize too (#427): the key registry write-throughs back to the keys
/// file after an admin provision/disable, so restarts re-hydrate.
#[derive(Clone, Serialize, Deserialize)]
pub struct RelayKey {
    /// The bearer secret the caller presents. Never logged, never audited.
    pub key: String,
    /// Stable public identifier for stats + audit rows.
    pub key_id: String,
    /// Owning user omni (`0x` + 64 hex) — ALL usage accumulates here (#384).
    pub user_omni: String,
    /// Device this key is attributed to in the per-device breakdown.
    pub device_id: String,
    #[serde(default)]
    pub label: String,
    /// #427 — the delegate actor omni this key attributes to (broker-minted
    /// per-delegate keys). `None` for hand-provisioned device keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_omni: Option<String>,
    /// #427 — per-DELEGATE token ceiling UNDER the user budget (epic #425
    /// decision 6: budgets keyed by delegate, rolling up to the user).
    /// `None` = only the user-level budget applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u64>,
    /// #427 — archive deprovisions by DISABLING (turns refuse with 401), so
    /// usage history + the key row survive for rollups.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserBudget {
    pub user_omni: String,
    pub budget_tokens: u64,
}

/// On-disk shape of `--keys-file`.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeysFile {
    #[serde(default)]
    pub default_budget_tokens: Option<u64>,
    #[serde(default)]
    pub users: Vec<UserBudget>,
    #[serde(default)]
    pub keys: Vec<RelayKey>,
}

#[derive(Clone)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub api_key: String,
    pub model_override: Option<String>,
    pub default_model: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub base_url: String,
    pub engines: String,
}

#[derive(Clone)]
pub struct GateConfig {
    pub listen: SocketAddr,
    pub upstream: UpstreamConfig,
    pub keys: Vec<RelayKey>,
    pub user_budgets: HashMap<String, u64>,
    pub default_budget_tokens: Option<u64>,
    pub admin_token: Option<String>,
    pub keys_file: Option<PathBuf>,
    pub audit_url: Option<String>,
    pub require_audit: bool,
    pub speech_backend: Option<Arc<dyn SpeechBackend>>,
    pub search: Option<SearchConfig>,
    pub decision: DecisionUpstreams,
}

#[derive(Clone)]
pub struct DecisionEndpoint {
    pub base_url: String,
    pub api_key: String,
}

#[derive(Clone, Default)]
pub struct DecisionUpstreams {
    pub jev: Option<DecisionEndpoint>,
    pub kev: Option<DecisionEndpoint>,
}

impl DecisionUpstreams {
    pub fn get(&self, provider: DecisionProvider) -> Option<&DecisionEndpoint> {
        match provider {
            DecisionProvider::Jev => self.jev.as_ref(),
            DecisionProvider::Kev => self.kev.as_ref(),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DecisionFile {
    jev: Option<EndpointFile>,
    kev: Option<EndpointFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointFile {
    base_url: String,
    api_key_file: Option<PathBuf>,
}

fn read_protected(path: &Path) -> anyhow::Result<zeroize::Zeroizing<String>> {
    protected_file::read_text(
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("configuration path must be UTF-8"))?,
    )
}

fn endpoint_file(endpoint: Option<EndpointFile>) -> anyhow::Result<Option<DecisionEndpoint>> {
    endpoint
        .map(|endpoint| {
            models::base_url(&endpoint.base_url)?;
            let api_key = match endpoint.api_key_file {
                Some(path) => read_credential(&path)?,
                None => String::new(),
            };
            Ok(DecisionEndpoint {
                base_url: endpoint.base_url.trim_end_matches('/').to_owned(),
                api_key,
            })
        })
        .transpose()
}

fn read_credential(path: &Path) -> anyhow::Result<String> {
    let value = read_protected(path)?;
    let value = value.trim();
    anyhow::ensure!(
        !value.is_empty() && !value.contains(['\n', '\r']),
        "credential file must contain one nonempty token"
    );
    Ok(value.to_owned())
}

impl GateConfig {
    pub fn from_cli(cli: Cli) -> anyhow::Result<Self> {
        anyhow::ensure!(
            cli.upstream_api_key.is_none() || cli.upstream_api_key_file.is_none(),
            "choose one upstream credential source"
        );
        let api_key = match (&cli.upstream_api_key, &cli.upstream_api_key_file) {
            (Some(value), _) => {
                anyhow::ensure!(
                    !value.trim().is_empty() && !value.contains(['\n', '\r']),
                    "explicit upstream credential must be nonempty and single-line"
                );
                value.clone()
            }
            (_, Some(path)) => read_credential(path)?,
            _ => String::new(),
        };
        let base_url = cli
            .upstream_base_url
            .unwrap_or_else(|| models::default_base_url().to_owned());
        models::base_url(&base_url)?;
        let default_model = cli
            .default_model
            .unwrap_or_else(|| models::default_chat_model().to_owned());
        anyhow::ensure!(
            !default_model.trim().is_empty(),
            "default model cannot be empty"
        );
        anyhow::ensure!(
            cli.model
                .as_ref()
                .is_none_or(|model| !model.trim().is_empty()),
            "model override cannot be empty"
        );
        let decisions: DecisionFile = match &cli.decision_config {
            Some(path) => serde_json::from_str(&read_protected(path)?)?,
            None => DecisionFile::default(),
        };
        let mut keys = Vec::new();
        let mut user_budgets = HashMap::new();
        let mut default_budget = cli.default_budget_tokens;
        if let Some(path) = &cli.keys_file {
            let parsed: KeysFile = serde_json::from_str(&read_protected(path)?)?;
            keys = parsed
                .keys
                .into_iter()
                .map(|mut key| {
                    key.user_omni = normalize_omni_0x(&key.user_omni);
                    key
                })
                .collect();
            user_budgets = parsed
                .users
                .into_iter()
                .map(|user| (normalize_omni_0x(&user.user_omni), user.budget_tokens))
                .collect();
            default_budget = default_budget.or(parsed.default_budget_tokens);
        }
        let search = cli
            .search_url
            .map(|base_url| -> anyhow::Result<SearchConfig> {
                models::base_url(&base_url)?;
                Ok(SearchConfig {
                    base_url: base_url.trim_end_matches('/').to_owned(),
                    engines: cli.search_engines,
                })
            })
            .transpose()?;
        Ok(Self {
            listen: cli.listen,
            upstream: UpstreamConfig {
                base_url: base_url.trim_end_matches('/').to_owned(),
                api_key,
                model_override: cli.model,
                default_model: Some(default_model),
            },
            keys,
            user_budgets,
            default_budget_tokens: default_budget,
            admin_token: cli.admin_token,
            keys_file: cli.keys_file,
            audit_url: cli.audit_url,
            require_audit: cli.require_audit,
            speech_backend: None,
            search,
            decision: DecisionUpstreams {
                jev: endpoint_file(decisions.jev)?,
                kev: endpoint_file(decisions.kev)?,
            },
        })
    }

    pub fn budget_for(&self, user_omni: &str) -> Option<u64> {
        self.user_budgets
            .get(user_omni)
            .copied()
            .or(self.default_budget_tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(budgets: &[(&str, u64)], default: Option<u64>) -> GateConfig {
        GateConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: UpstreamConfig {
                base_url: "http://127.0.0.1:1/v1".into(),
                api_key: "k".into(),
                model_override: None,
                default_model: None,
            },
            keys: vec![],
            user_budgets: budgets.iter().map(|(u, b)| (u.to_string(), *b)).collect(),
            default_budget_tokens: default,
            admin_token: None,
            keys_file: None,
            audit_url: None,
            require_audit: false,
            speech_backend: None,
            search: None,
            decision: DecisionUpstreams::default(),
        }
    }

    #[test]
    fn budget_resolution_override_then_default_then_unlimited() {
        let user = format!("0x{}", "aa".repeat(32));
        let cfg = cfg_with(&[(user.as_str(), 100)], Some(50));
        assert_eq!(cfg.budget_for(&user), Some(100));
        assert_eq!(cfg.budget_for("0xother"), Some(50));
        let cfg = cfg_with(&[], None);
        assert_eq!(cfg.budget_for(&user), None);
    }

    fn cli_min() -> Cli {
        Cli {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream_base_url: None,
            upstream_api_key: None,
            upstream_api_key_file: None,
            default_model: None,
            decision_config: None,
            search_url: None,
            search_engines: "bing".into(),
            model: None,
            keys_file: None,
            default_budget_tokens: None,
            admin_token: None,
            audit_url: None,
            require_audit: false,
        }
    }

    #[test]
    fn defaults_select_local_recipe_without_credentials_or_optional_adapters() {
        let config = GateConfig::from_cli(cli_min()).unwrap();
        assert_eq!(config.upstream.base_url, models::default_base_url());
        assert_eq!(
            config.upstream.default_model.as_deref(),
            Some(models::default_chat_model())
        );
        assert!(config.upstream.api_key.is_empty());
        assert!(config.keys.is_empty() && config.admin_token.is_none());
        assert!(config.speech_backend.is_none() && config.search.is_none());
        assert!(config.decision.jev.is_none() && config.decision.kev.is_none());
    }

    #[test]
    fn explicit_credentials_and_decision_endpoints_are_isolated_and_protected() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let credential = directory.path().join("credential");
        protected_file::write(credential.to_str().unwrap(), b"synthetic-token", true).unwrap();
        let mut cli = cli_min();
        cli.upstream_api_key_file = Some(credential.clone());
        let config = GateConfig::from_cli(cli).unwrap();
        assert_eq!(config.upstream.api_key, "synthetic-token");
        assert!(config.decision.jev.is_none());

        let decision = directory.path().join("decision.json");
        let source = serde_json::json!({"kev":{"base_url":"http://127.0.0.1:8009", "api_key_file":credential}});
        protected_file::write(
            decision.to_str().unwrap(),
            source.to_string().as_bytes(),
            true,
        )
        .unwrap();
        let mut cli = cli_min();
        cli.decision_config = Some(decision.clone());
        let config = GateConfig::from_cli(cli.clone()).unwrap();
        assert!(config.decision.jev.is_none());
        assert!(config.upstream.api_key.is_empty());
        assert_eq!(config.decision.kev.unwrap().api_key, "synthetic-token");
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(GateConfig::from_cli(cli).is_err());
        assert_eq!(std::fs::read(&credential).unwrap(), b"synthetic-token");
    }

    #[test]
    fn explicit_invalid_values_fail_without_falling_back() {
        for base in [
            "",
            "file:///tmp/models",
            "https://user:pass@example.invalid/v1",
            "http://localhost:1/v1?key=x",
        ] {
            let mut cli = cli_min();
            cli.upstream_base_url = Some(base.into());
            assert!(GateConfig::from_cli(cli).is_err());
        }
        let mut cli = cli_min();
        cli.upstream_api_key = Some(String::new());
        assert!(GateConfig::from_cli(cli).is_err());
        let mut cli = cli_min();
        cli.upstream_api_key_file = Some("/missing/credential".into());
        assert!(GateConfig::from_cli(cli).is_err());
        let mut cli = cli_min();
        cli.upstream_api_key = Some("explicit".into());
        cli.upstream_api_key_file = Some("/missing/credential".into());
        assert!(GateConfig::from_cli(cli).is_err());
    }

    #[test]
    fn keys_file_parses_and_normalizes() {
        let raw = serde_json::json!({
            "default_budget_tokens": 1000,
            "users": [{"user_omni": "aa".repeat(32), "budget_tokens": 5}],
            "keys": [{
                "key": "gk_secret",
                "key_id": "k1",
                "user_omni": "aa".repeat(32),
                "device_id": "esp32-01"
            }]
        });
        let parsed: KeysFile = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.default_budget_tokens, Some(1000));
        assert_eq!(parsed.keys[0].label, "");
        assert!(!parsed.keys[0].user_omni.starts_with("0x"));
        assert_eq!(
            normalize_omni_0x(&parsed.keys[0].user_omni),
            format!("0x{}", "aa".repeat(32))
        );
    }
}
