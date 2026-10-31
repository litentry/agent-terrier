//! Explicit local memory-model configuration; no host credential discovery.

use agentkeys_protocol::model_config;
use std::path::Path;

pub const DEFAULT_CONFIG_FILE: &str = "/opt/agentkeys/openviking/ov.conf";
pub const DEFAULT_WORKSPACE: &str = "/opt/agentkeys/openviking/workspace";
pub const DEFAULT_EMBED_PROVIDER: &str = "openai";
pub const LOCAL_EMBED_MODEL: &str = "bge-small-zh-v1.5-f16";
pub const LOCAL_EMBED_DIMENSION: u32 = 512;
pub const LOCAL_MODELS_DIR: &str = "/opt/agentkeys/openviking/models";

#[derive(Clone, PartialEq, Eq)]
pub enum ServerConfigPlan {
    Rendered {
        config: serde_json::Value,
        summary: String,
    },
    Disabled {
        reason: String,
    },
    Refused {
        reason: String,
    },
}

impl std::fmt::Debug for ServerConfigPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rendered { summary, .. } => formatter
                .debug_struct("Rendered")
                .field("summary", summary)
                .finish(),
            Self::Disabled { reason } => formatter
                .debug_struct("Disabled")
                .field("reason", reason)
                .finish(),
            Self::Refused { reason } => formatter
                .debug_struct("Refused")
                .field("reason", reason)
                .finish(),
        }
    }
}

pub fn config_file_path(lookup: impl Fn(&str) -> Option<String>) -> String {
    non_blank(lookup("OPENVIKING_CONFIG_FILE")).unwrap_or_else(|| DEFAULT_CONFIG_FILE.into())
}

pub fn engine_configured(lookup: impl Fn(&str) -> Option<String>) -> bool {
    [
        "OPENVIKING_WORKSPACE",
        "OPENVIKING_EMBED_PROVIDER",
        "OPENVIKING_EMBED_MODEL",
        "OPENVIKING_EMBED_API_KEY",
        "OPENVIKING_EMBED_API_BASE",
        "OPENVIKING_EMBED_DIMENSION",
        "OPENVIKING_EMBED_MODEL_PATH",
        "OPENVIKING_ENDPOINT",
        "OPENVIKING_CONFIG_FILE",
    ]
    .iter()
    .any(|key| non_blank(lookup(key)).is_some())
}

fn non_blank(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn refused(reason: &str) -> ServerConfigPlan {
    ServerConfigPlan::Refused {
        reason: reason.into(),
    }
}

pub fn plan_server_config(
    lookup: impl Fn(&str) -> Option<String>,
    model_file_present: impl Fn(&str) -> bool,
) -> ServerConfigPlan {
    let read = |key: &str| non_blank(lookup(key));
    let provider =
        read("OPENVIKING_EMBED_PROVIDER").unwrap_or_else(|| DEFAULT_EMBED_PROVIDER.into());
    if provider == "disabled" {
        return ServerConfigPlan::Disabled {
            reason: "Memory embeddings explicitly disabled".into(),
        };
    }
    if !matches!(provider.as_str(), "openai" | "local") {
        return refused("Unsupported memory embedding provider; use openai, local, or disabled");
    }
    let default_model = if provider == "local" {
        LOCAL_EMBED_MODEL
    } else {
        model_config::default_embedding_model()
    };
    let default_dimension = if provider == "local" {
        LOCAL_EMBED_DIMENSION
    } else {
        model_config::default_embedding_dimension()
    };
    let model = read("OPENVIKING_EMBED_MODEL").unwrap_or_else(|| default_model.into());
    let dimension = match read("OPENVIKING_EMBED_DIMENSION") {
        Some(raw) => match raw.parse::<u32>() {
            Ok(value) if value > 0 => value,
            _ => return refused("OPENVIKING_EMBED_DIMENSION must be a positive integer"),
        },
        None if model == default_model => default_dimension,
        None => {
            return refused(
                "A custom embedding model requires an explicit OPENVIKING_EMBED_DIMENSION",
            )
        }
    };
    if model == default_model && dimension != default_dimension {
        return refused("Embedding dimension does not match the selected built-in model");
    }
    let key = read("OPENVIKING_EMBED_API_KEY");
    let base = read("OPENVIKING_EMBED_API_BASE");
    let dense = if provider == "local" {
        if key.is_some() || base.is_some() {
            return refused(
                "The file-based local embedder does not accept API credentials or an API endpoint",
            );
        }
        let model_path = read("OPENVIKING_EMBED_MODEL_PATH")
            .unwrap_or_else(|| format!("{LOCAL_MODELS_DIR}/{model}.gguf"));
        if !model_file_present(&model_path) {
            return refused("The selected local embedding model file is missing; install it explicitly before starting memory");
        }
        let cache_directory = Path::new(&model_path)
            .parent()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| LOCAL_MODELS_DIR.into());
        serde_json::json!({"provider":provider, "model":model, "dimension":dimension,
            "model_path":model_path, "cache_dir":cache_directory})
    } else {
        if key.is_some() && base.is_none() {
            return refused("An embedding API key requires an explicit OPENVIKING_EMBED_API_BASE; endpoint and credential must be configured together");
        }
        let base = base.unwrap_or_else(|| model_config::default_base_url().into());
        if let Err(reason) = model_config::base_url(&base) {
            return refused(reason);
        }
        let mut dense = serde_json::json!({"provider":provider, "model":model, "dimension":dimension,
            "api_base":base, "encoding_format":"float", "input":"text"});
        if let Some(key) = key {
            dense["api_key"] = key.into();
        }
        dense
    };
    let summary = format!(
        "provider={provider} dimension={dimension} key={}",
        if dense.get("api_key").is_some() {
            "<set>"
        } else {
            "-"
        }
    );
    ServerConfigPlan::Rendered {
        config: serde_json::json!({
            "storage":{"workspace":read("OPENVIKING_WORKSPACE").unwrap_or_else(|| DEFAULT_WORKSPACE.into())},
            "embedding":{"dense":dense},
        }),
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            assert!(
                key.starts_with("OPENVIKING_"),
                "must not discover host credentials"
            );
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.to_string())
        }
    }

    fn rendered(pairs: &[(&str, &str)]) -> (serde_json::Value, String) {
        match plan_server_config(lookup(pairs), |_| true) {
            ServerConfigPlan::Rendered { config, summary } => (config, summary),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn memory_defaults_to_the_public_local_model_recipe_without_credentials() {
        let (config, summary) = rendered(&[("OPENVIKING_WORKSPACE", "/tmp/terrier-memory")]);
        let dense = &config["embedding"]["dense"];
        assert_eq!(dense["provider"], "openai");
        assert_eq!(dense["api_base"], model_config::default_base_url());
        assert_eq!(dense["model"], model_config::default_embedding_model());
        assert_eq!(
            dense["dimension"],
            model_config::default_embedding_dimension()
        );
        assert_eq!(dense["encoding_format"], "float");
        assert!(dense.get("api_key").is_none());
        assert!(summary.contains("key=-"));
    }

    #[test]
    fn explicit_endpoint_and_key_remain_paired_and_redacted() {
        let plan = plan_server_config(
            lookup(&[
                ("OPENVIKING_EMBED_API_BASE", "http://127.0.0.1:1234/v1"),
                ("OPENVIKING_EMBED_API_KEY", "synthetic-relay-token"),
            ]),
            |_| false,
        );
        assert!(!format!("{plan:?}").contains("synthetic-relay-token"));
        let ServerConfigPlan::Rendered { config, summary } = plan else {
            panic!("must render")
        };
        assert_eq!(
            config["embedding"]["dense"]["api_base"],
            "http://127.0.0.1:1234/v1"
        );
        assert_eq!(
            config["embedding"]["dense"]["api_key"],
            "synthetic-relay-token"
        );
        assert!(!summary.contains("synthetic-relay-token"));
        assert!(matches!(
            plan_server_config(
                lookup(&[("OPENVIKING_EMBED_API_KEY", "synthetic-relay-token")]),
                |_| false
            ),
            ServerConfigPlan::Refused { .. }
        ));
    }

    #[test]
    fn custom_models_require_an_explicit_valid_dimension() {
        for dimension in ["", "0", "-1", "invalid", "4294967296"] {
            assert!(matches!(
                plan_server_config(
                    lookup(&[
                        ("OPENVIKING_EMBED_MODEL", "custom-model"),
                        ("OPENVIKING_EMBED_DIMENSION", dimension),
                    ]),
                    |_| false
                ),
                ServerConfigPlan::Refused { .. }
            ));
        }
        let (config, _) = rendered(&[
            ("OPENVIKING_EMBED_MODEL", "custom-model"),
            ("OPENVIKING_EMBED_DIMENSION", "256"),
        ]);
        assert_eq!(config["embedding"]["dense"]["dimension"], 256);
        assert!(matches!(
            plan_server_config(lookup(&[("OPENVIKING_EMBED_DIMENSION", "1")]), |_| false),
            ServerConfigPlan::Refused { .. }
        ));
    }

    #[test]
    fn invalid_explicit_provider_and_endpoint_never_select_defaults() {
        for endpoint in [
            "ftp://models.example",
            "http://user:sentinel@localhost/v1",
            "http://localhost/v1?key=sentinel",
            "malformed",
        ] {
            let plan =
                plan_server_config(lookup(&[("OPENVIKING_EMBED_API_BASE", endpoint)]), |_| {
                    false
                });
            assert!(matches!(plan, ServerConfigPlan::Refused { .. }));
            assert!(!format!("{plan:?}").contains("sentinel"));
        }
        assert!(matches!(
            plan_server_config(
                lookup(&[("OPENVIKING_EMBED_PROVIDER", "unsupported")]),
                |_| false
            ),
            ServerConfigPlan::Refused { .. }
        ));
        assert!(matches!(
            plan_server_config(lookup(&[("OPENVIKING_EMBED_PROVIDER", "disabled")]), |_| {
                false
            }),
            ServerConfigPlan::Disabled { .. }
        ));
    }

    #[test]
    fn file_embedder_requires_its_model_and_rejects_ignored_api_settings() {
        let pairs = [("OPENVIKING_EMBED_PROVIDER", "local")];
        assert!(matches!(
            plan_server_config(lookup(&pairs), |_| false),
            ServerConfigPlan::Refused { .. }
        ));
        let (config, _) = rendered(&pairs);
        assert_eq!(config["embedding"]["dense"]["model"], LOCAL_EMBED_MODEL);
        assert_eq!(
            config["embedding"]["dense"]["dimension"],
            LOCAL_EMBED_DIMENSION
        );
        assert!(config["embedding"]["dense"].get("api_key").is_none());
        assert!(matches!(
            plan_server_config(
                lookup(&[
                    ("OPENVIKING_EMBED_PROVIDER", "local"),
                    ("OPENVIKING_EMBED_API_BASE", "http://localhost/v1"),
                ]),
                |_| true
            ),
            ServerConfigPlan::Refused { .. }
        ));
    }

    #[test]
    fn configuration_is_opt_in_and_paths_are_explicit() {
        assert!(!engine_configured(lookup(&[])));
        assert_eq!(config_file_path(lookup(&[])), DEFAULT_CONFIG_FILE);
        assert!(engine_configured(lookup(&[(
            "OPENVIKING_WORKSPACE",
            "/tmp/memory"
        )])));
        assert_eq!(
            config_file_path(lookup(&[("OPENVIKING_CONFIG_FILE", " /tmp/memory.conf ")])),
            "/tmp/memory.conf"
        );
    }
}
