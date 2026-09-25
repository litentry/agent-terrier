//! The OpenViking SERVER's `ov.conf`, planned from the `OPENVIKING_*` /
//! `ARK_*` env a pod carries (plan `docs/plan/dsh-plugin-abstraction.md`
//! PR 3). One typed owner behind the engine seam, replacing the bash+python
//! renderer that lived in `docker/dsh-sandbox/start-openviking.sh` and
//! produced two pod-only crashes (#631 unexported vars, #651 unbound `HOME`).
//! The in-sandbox daemon renders the file at boot (before its checkpoint
//! restore touches the marker the start script waits for); the script only
//! waits, then execs the server when a config exists.
//!
//! The rules are the script's, verbatim (measured on openviking 0.4.11+):
//! - the server hard-fails with NO embedding config and with an empty model,
//!   so `OPENVIKING_EMBED_MODEL` stays REQUIRED — explicit-or-disabled;
//! - the KEY leg defaults onto the sandbox's model-path pair (#572): base +
//!   key travel TOGETHER, so a gate `gk_` key goes to the gate base (metered
//!   `/v1/embeddings` relay, no raw vendor key in the sandbox) and a raw key
//!   to real Ark; a dedicated `OPENVIKING_EMBED_API_KEY` (+ `_API_BASE`)
//!   overrides both; never mix the legs;
//! - the `local` provider (#694 step 5: the engine's llama-cpp GGUF embedder
//!   baked into the foreign base) takes no key, fixes the dimension at 512,
//!   and is REFUSED when the model file is missing (an image built without
//!   `OV_LOCAL_EMBED=1`) — never started with a provider it cannot serve.
//!
//! Everything here is pure over a lookup; the writer is the one I/O.

use std::path::Path;

pub const DEFAULT_CONFIG_FILE: &str = "/opt/agentkeys/openviking/ov.conf";
pub const DEFAULT_WORKSPACE: &str = "/opt/agentkeys/openviking/workspace";
pub const DEFAULT_EMBED_PROVIDER: &str = "volcengine";
pub const DEFAULT_EMBED_DIMENSION: u32 = 2048;
/// The engine appends `/embeddings` (or `/embeddings/multimodal`) itself.
pub const DEFAULT_ARK_EMBED_BASE: &str = "https://ark.cn-beijing.volces.com/api/v3";
pub const LOCAL_EMBED_MODEL: &str = "bge-small-zh-v1.5-f16";
pub const LOCAL_EMBED_DIMENSION: u32 = 512;
pub const LOCAL_MODELS_DIR: &str = "/opt/agentkeys/openviking/models";

/// The outcome of planning the server config for this environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerConfigPlan {
    /// Write `config` — the engine boots with this embedder.
    Rendered {
        config: serde_json::Value,
        /// One redacted line for the log (no key material).
        summary: String,
    },
    /// Clean stop: no embedding model or no key source — the engine is
    /// deliberately off; the daemon mirror idles, chat is unaffected.
    Disabled { reason: String },
    /// A provider the image cannot serve (the `local` embedder without its
    /// model file): loud, and the engine is not started.
    Refused { reason: String },
}

/// Where the config file lives: `OPENVIKING_CONFIG_FILE`, else the default.
pub fn config_file_path(lookup: impl Fn(&str) -> Option<String>) -> String {
    lookup("OPENVIKING_CONFIG_FILE")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CONFIG_FILE.to_string())
}

/// Is an engine configured for this environment at all? (A master daemon
/// or a bare dev box carries none of these — nothing to render.)
pub fn engine_configured(lookup: impl Fn(&str) -> Option<String>) -> bool {
    [
        "OPENVIKING_WORKSPACE",
        "OPENVIKING_EMBED_PROVIDER",
        "OPENVIKING_EMBED_MODEL",
        "OPENVIKING_EMBED_API_KEY",
        "OPENVIKING_ENDPOINT",
        "OPENVIKING_CONFIG_FILE",
    ]
    .iter()
    .any(|k| lookup(k).map(|v| !v.trim().is_empty()).unwrap_or(false))
}

fn non_blank(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Plan the server config (pure). `model_file_present` answers whether the
/// local embedder's GGUF exists at a path.
pub fn plan_server_config(
    lookup: impl Fn(&str) -> Option<String>,
    model_file_present: impl Fn(&str) -> bool,
) -> ServerConfigPlan {
    let read = |k: &str| non_blank(lookup(k));
    let workspace = read("OPENVIKING_WORKSPACE").unwrap_or_else(|| DEFAULT_WORKSPACE.to_string());
    let provider =
        read("OPENVIKING_EMBED_PROVIDER").unwrap_or_else(|| DEFAULT_EMBED_PROVIDER.to_string());
    let mut model = read("OPENVIKING_EMBED_MODEL");
    let mut dimension = read("OPENVIKING_EMBED_DIMENSION")
        .and_then(|d| d.parse::<u32>().ok())
        .unwrap_or(DEFAULT_EMBED_DIMENSION);
    let dense = if provider == "local" {
        // #694 step 5 — the engine's local GGUF embedder: model_path/cache_dir
        // are its keys (openviking_cli/utils/config/embedding_config.py @
        // v0.4.16); it validates no api_key / api_base.
        let model_name = model
            .clone()
            .unwrap_or_else(|| LOCAL_EMBED_MODEL.to_string());
        model = Some(model_name.clone());
        dimension = LOCAL_EMBED_DIMENSION;
        let model_path = read("OPENVIKING_EMBED_MODEL_PATH")
            .unwrap_or_else(|| format!("{LOCAL_MODELS_DIR}/{model_name}.gguf"));
        if !model_file_present(&model_path) {
            return ServerConfigPlan::Refused {
                reason: format!(
                    "OPENVIKING_EMBED_PROVIDER=local but no model at {model_path} — this image was \
                     built without OV_LOCAL_EMBED=1 (seed-dsh-base.sh); refusing to start the engine \
                     with a provider it cannot serve (set the provider back to volcengine or rebuild the base)"
                ),
            };
        }
        let cache_dir = Path::new(&model_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| LOCAL_MODELS_DIR.to_string());
        serde_json::json!({
            "provider": provider,
            "model": model_name,
            "dimension": dimension,
            "model_path": model_path,
            "cache_dir": cache_dir,
        })
    } else {
        // #572 — no dedicated embed key ⇒ the model-path pair, base + key
        // TOGETHER (a gate gk_ key only ever pairs with the gate base).
        let mut key = read("OPENVIKING_EMBED_API_KEY");
        let mut base = read("OPENVIKING_EMBED_API_BASE");
        if key.is_none() {
            if let (Some(ark_key), Some(ark_base)) = (read("ARK_API_KEY"), read("ARK_BASE_URL")) {
                key = Some(ark_key);
                base = Some(ark_base);
            }
        }
        let base = base.unwrap_or_else(|| DEFAULT_ARK_EMBED_BASE.to_string());
        let Some(model_name) = model.clone() else {
            return ServerConfigPlan::Disabled {
                reason: "OPENVIKING_EMBED_MODEL unset — the engine cannot boot without an explicit \
                         embedding model (it validates at startup); the agent keeps its built-in memory \
                         and the daemon mirror idles until the engine answers /health"
                    .to_string(),
            };
        };
        let Some(key) = key else {
            return ServerConfigPlan::Disabled {
                reason: "no embedding key source — neither a dedicated OPENVIKING_EMBED_API_KEY nor the \
                         ARK_API_KEY + ARK_BASE_URL pair; the engine stays off"
                    .to_string(),
            };
        };
        serde_json::json!({
            "provider": provider,
            "model": model_name,
            "dimension": dimension,
            "api_key": key,
            "api_base": base,
        })
    };
    let summary = format!(
        "provider={} model={} dimension={} base={} key={}",
        provider,
        model.as_deref().unwrap_or("-"),
        dimension,
        dense
            .get("api_base")
            .and_then(|v| v.as_str())
            .unwrap_or("-"),
        if dense.get("api_key").is_some() {
            "<set>"
        } else {
            "-"
        },
    );
    ServerConfigPlan::Rendered {
        config: serde_json::json!({
            "storage": { "workspace": workspace },
            "embedding": { "dense": dense },
        }),
        summary,
    }
}

/// Write the config 0600 (the embed key rides inside), parent dirs created,
/// atomically (tmp + rename) so a reader never sees a half file.
pub fn write_server_config(path: &Path, config: &serde_json::Value) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let body = serde_json::to_string_pretty(config).map_err(std::io::Error::other)?;
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(kk, _)| *kk == k)
                .map(|(_, v)| v.to_string())
        }
    }
    fn no_file(_: &str) -> bool {
        false
    }
    fn any_file(_: &str) -> bool {
        true
    }

    #[test]
    fn a_gate_provisioned_pod_pairs_the_ark_key_with_the_ark_base() {
        // #572: base + key travel together — the gk_ relay key goes to the
        // gate base, never to real Ark.
        let plan = plan_server_config(
            lookup(&[
                ("OPENVIKING_EMBED_MODEL", "ep-embed"),
                ("ARK_API_KEY", "gk_relay"),
                ("ARK_BASE_URL", "https://gate.agentterrier.cn/v1"),
            ]),
            no_file,
        );
        let ServerConfigPlan::Rendered { config, summary } = plan else {
            panic!("{plan:?}")
        };
        assert_eq!(config["storage"]["workspace"], DEFAULT_WORKSPACE);
        assert_eq!(config["embedding"]["dense"]["provider"], "volcengine");
        assert_eq!(config["embedding"]["dense"]["model"], "ep-embed");
        assert_eq!(config["embedding"]["dense"]["dimension"], 2048);
        assert_eq!(config["embedding"]["dense"]["api_key"], "gk_relay");
        assert_eq!(
            config["embedding"]["dense"]["api_base"],
            "https://gate.agentterrier.cn/v1"
        );
        assert!(
            summary.contains("key=<set>") && !summary.contains("gk_relay"),
            "{summary}"
        );
    }

    #[test]
    fn a_dedicated_embed_key_overrides_the_pair_and_defaults_to_real_ark() {
        let plan = plan_server_config(
            lookup(&[
                ("OPENVIKING_EMBED_MODEL", "ep-embed"),
                ("OPENVIKING_EMBED_API_KEY", "raw-key"),
                ("OPENVIKING_EMBED_DIMENSION", "1024"),
                ("ARK_API_KEY", "gk_relay"),
                ("ARK_BASE_URL", "https://gate.agentterrier.cn/v1"),
            ]),
            no_file,
        );
        let ServerConfigPlan::Rendered { config, .. } = plan else {
            panic!("{plan:?}")
        };
        assert_eq!(config["embedding"]["dense"]["api_key"], "raw-key");
        assert_eq!(
            config["embedding"]["dense"]["api_base"],
            DEFAULT_ARK_EMBED_BASE
        );
        assert_eq!(config["embedding"]["dense"]["dimension"], 1024);
    }

    #[test]
    fn no_model_or_no_key_is_a_clean_disable_never_a_render() {
        assert!(matches!(
            plan_server_config(
                lookup(&[("ARK_API_KEY", "k"), ("ARK_BASE_URL", "b")]),
                no_file
            ),
            ServerConfigPlan::Disabled { .. }
        ));
        assert!(matches!(
            plan_server_config(lookup(&[("OPENVIKING_EMBED_MODEL", "ep-embed")]), no_file),
            ServerConfigPlan::Disabled { .. }
        ));
        // an ARK key WITHOUT its base is not a pair — never half a leg
        assert!(matches!(
            plan_server_config(
                lookup(&[("OPENVIKING_EMBED_MODEL", "ep"), ("ARK_API_KEY", "k")]),
                no_file
            ),
            ServerConfigPlan::Disabled { .. }
        ));
    }

    #[test]
    fn the_local_embedder_takes_no_key_fixes_512_and_is_refused_without_its_model() {
        let env = [
            ("OPENVIKING_EMBED_PROVIDER", "local"),
            ("ARK_API_KEY", "k"),
            ("ARK_BASE_URL", "b"),
        ];
        let ServerConfigPlan::Rendered { config, .. } = plan_server_config(lookup(&env), any_file)
        else {
            panic!("local with a model file must render")
        };
        let dense = &config["embedding"]["dense"];
        assert_eq!(dense["provider"], "local");
        assert_eq!(dense["model"], LOCAL_EMBED_MODEL);
        assert_eq!(dense["dimension"], 512);
        assert_eq!(
            dense["model_path"],
            format!("{LOCAL_MODELS_DIR}/{LOCAL_EMBED_MODEL}.gguf")
        );
        assert_eq!(dense["cache_dir"], LOCAL_MODELS_DIR);
        assert!(dense.get("api_key").is_none());
        assert!(matches!(
            plan_server_config(lookup(&env), no_file),
            ServerConfigPlan::Refused { .. }
        ));
    }

    #[test]
    fn the_config_path_and_the_configured_probe_follow_the_env() {
        assert_eq!(config_file_path(lookup(&[])), DEFAULT_CONFIG_FILE);
        assert_eq!(
            config_file_path(lookup(&[("OPENVIKING_CONFIG_FILE", " /tmp/x.conf ")])),
            "/tmp/x.conf"
        );
        assert!(!engine_configured(lookup(&[])));
        assert!(engine_configured(lookup(&[(
            "OPENVIKING_EMBED_MODEL",
            "ep"
        )])));
        assert!(!engine_configured(lookup(&[(
            "OPENVIKING_EMBED_MODEL",
            "  "
        )])));
    }

    #[test]
    fn the_writer_lands_a_private_file_atomically() {
        let dir = std::env::temp_dir().join(format!("ak-ovconf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("ov.conf");
        write_server_config(
            &path,
            &serde_json::json!({ "storage": { "workspace": "/w" } }),
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"workspace\": \"/w\""));
        assert!(!path.with_extension("tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
