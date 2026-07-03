//! Runtime configuration — CLI flags + env vars, read ONCE at startup and
//! treated as immutable (the `from_env`/inject pattern; AGENTS.md bans
//! `std::env::set_var` in tests, so tests build `GateConfig` directly).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;

use agentkeys_inference_creds::Resolver;
use agentkeys_protocol::normalize_omni_0x;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "agentkeys-gate",
    about = "AgentKeys metered key-custody LLM-egress relay (#384) — holds the vendor \
             inference key, meters per-user token usage with per-device/per-key stats, \
             audits every turn as GateTurn (#332)"
)]
pub struct Cli {
    /// HTTP bind address. OpenAI-compatible endpoint at `POST
    /// /v1/chat/completions`; rollup at `GET /v1/usage`; health at `GET /healthz`.
    #[arg(long, env = "AGENTKEYS_GATE_LISTEN", default_value = "0.0.0.0:8077")]
    pub listen: SocketAddr,

    /// Upstream OpenAI-compatible base URL — an explicit, engine-agnostic
    /// override. When unset, the **ark family** resolves it (#338: env
    /// `ARK_BASE_URL` > `ark.env` family file > the built-in Ark default), so
    /// the relay's upstream comes from the SAME source every other component
    /// reads — never a gate-private notion of "where Ark is".
    #[arg(long, env = "AGENTKEYS_GATE_UPSTREAM_BASE_URL")]
    pub upstream_base_url: Option<String>,

    /// Upstream API key — the ONE vendor key the relay holds (never handed to
    /// sandboxes). Explicit override; when unset (and no `_FILE`), the **ark
    /// family** resolves it (#338: env `ARK_API_KEY` > `ark.env` family file —
    /// rotate with `scripts/operator/secrets/rotate-inference-cred.sh ark`).
    #[arg(long, env = "AGENTKEYS_GATE_UPSTREAM_API_KEY")]
    pub upstream_api_key: Option<String>,

    /// Owner-only file (0600) holding the upstream API key — an engine-agnostic
    /// escape hatch. For the Ark deployment prefer the per-family `ark.env`
    /// (the loader finds it without any flag).
    #[arg(long, env = "AGENTKEYS_GATE_UPSTREAM_API_KEY_FILE")]
    pub upstream_api_key_file: Option<PathBuf>,

    /// Optional upstream model / Ark endpoint-id override. When unset the
    /// caller's `model` is forwarded verbatim.
    #[arg(long, env = "AGENTKEYS_GATE_MODEL")]
    pub model: Option<String>,

    /// JSON file with the relay key records + per-user budgets (see
    /// `KeysFile`). Without it the relay 401s every request (logged loudly).
    #[arg(long, env = "AGENTKEYS_GATE_KEYS_FILE")]
    pub keys_file: Option<PathBuf>,

    /// Default per-user token budget when the keys file has no per-user
    /// override. Unset = unlimited (but still metered).
    #[arg(long, env = "AGENTKEYS_GATE_DEFAULT_BUDGET_TOKENS")]
    pub default_budget_tokens: Option<u64>,

    /// Bearer token for operator queries of `GET /v1/usage` across all users.
    #[arg(long, env = "AGENTKEYS_GATE_ADMIN_TOKEN")]
    pub admin_token: Option<String>,

    /// Audit worker base URL for `GateTurn` appends. Unset = no audit emission
    /// (logged loudly at boot; pair with --require-audit for the strict mode).
    #[arg(long, env = "AGENTKEYS_AUDIT_URL")]
    pub audit_url: Option<String>,

    /// Fail a (non-streamed) turn if its GateTurn audit row cannot be appended
    /// — matches the `AGENTKEYS_WORKER_REQUIRE_AUDIT` staged-rollout posture.
    #[arg(long, env = "AGENTKEYS_GATE_REQUIRE_AUDIT", default_value_t = false)]
    pub require_audit: bool,

    /// AWS region for the shared BackendClient constructor (unused on the
    /// audit-only path, but required by the one-owner client).
    #[arg(long, env = "AWS_REGION", default_value = "us-east-1")]
    pub aws_region: String,
}

/// One relay key record: the caller credential a sandbox/device presents,
/// bound to the owning user + the device it is attributed to.
#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserBudget {
    pub user_omni: String,
    pub budget_tokens: u64,
}

/// On-disk shape of `--keys-file`.
#[derive(Debug, Clone, Deserialize)]
pub struct KeysFile {
    #[serde(default)]
    pub default_budget_tokens: Option<u64>,
    #[serde(default)]
    pub users: Vec<UserBudget>,
    #[serde(default)]
    pub keys: Vec<RelayKey>,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub api_key: String,
    pub model_override: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GateConfig {
    pub listen: SocketAddr,
    pub upstream: UpstreamConfig,
    pub keys: Vec<RelayKey>,
    /// Per-user budget overrides (user omni → tokens).
    pub user_budgets: HashMap<String, u64>,
    pub default_budget_tokens: Option<u64>,
    pub admin_token: Option<String>,
    pub audit_url: Option<String>,
    pub require_audit: bool,
    pub aws_region: String,
}

impl GateConfig {
    pub fn from_cli(cli: Cli) -> anyhow::Result<Self> {
        Self::from_cli_with(cli, &Resolver::from_process())
    }

    /// Testable core: the ark-family resolver is injected (never mutate process
    /// env in tests). Precedence per upstream field: explicit `AGENTKEYS_GATE_*`
    /// form > the ark family (env > `ark.env` file > built-in default, #338).
    /// A fully-explicit config never consults the family at all.
    pub fn from_cli_with(cli: Cli, ark: &Resolver) -> anyhow::Result<Self> {
        let explicit_key = match (&cli.upstream_api_key, &cli.upstream_api_key_file) {
            (Some(k), _) if !k.is_empty() => Some(k.clone()),
            (_, Some(path)) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("reading upstream api key file {path:?}: {e}"))?
                    .trim()
                    .to_string(),
            ),
            _ => None,
        };
        // lookup_var (not `ark()`): the relay forwards the caller's `model`, so
        // it must not require LLM_ENDPOINT_ID just to resolve a key. Errors here
        // are unreadable/malformed ark.env — fail loud, never skip.
        let api_key = match explicit_key {
            Some(k) => k,
            None => ark
                .lookup_var("ARK_API_KEY")?
                .map(|(v, _)| v)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no upstream API key — set AGENTKEYS_GATE_UPSTREAM_API_KEY (or _FILE), \
                         or provide the ark family (env ARK_API_KEY, or ark.env via \
                         scripts/operator/secrets/rotate-inference-cred.sh ark) — #338"
                    )
                })?,
        };
        let base_url = match cli.upstream_base_url {
            Some(b) if !b.is_empty() => b,
            _ => ark
                .lookup_var("ARK_BASE_URL")?
                .map(|(v, _)| v)
                .unwrap_or_else(|| agentkeys_inference_creds::DEFAULT_ARK_BASE.to_string()),
        };

        let mut keys = Vec::new();
        let mut user_budgets = HashMap::new();
        let mut default_budget = cli.default_budget_tokens;
        if let Some(path) = &cli.keys_file {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading keys file {path:?}: {e}"))?;
            let parsed: KeysFile = serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("parsing keys file {path:?}: {e}"))?;
            keys = parsed
                .keys
                .into_iter()
                .map(|mut k| {
                    k.user_omni = normalize_omni_0x(&k.user_omni);
                    k
                })
                .collect();
            user_budgets = parsed
                .users
                .into_iter()
                .map(|u| (normalize_omni_0x(&u.user_omni), u.budget_tokens))
                .collect();
            // CLI/env wins over the file's default (explicit operator override).
            default_budget = default_budget.or(parsed.default_budget_tokens);
        }

        Ok(Self {
            listen: cli.listen,
            upstream: UpstreamConfig {
                base_url: base_url.trim_end_matches('/').to_string(),
                api_key,
                model_override: cli.model,
            },
            keys,
            user_budgets,
            default_budget_tokens: default_budget,
            admin_token: cli.admin_token,
            audit_url: cli.audit_url,
            require_audit: cli.require_audit,
            aws_region: cli.aws_region,
        })
    }

    /// The user's effective token budget: per-user override → default → none
    /// (unlimited but metered).
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
            },
            keys: vec![],
            user_budgets: budgets.iter().map(|(u, b)| (u.to_string(), *b)).collect(),
            default_budget_tokens: default,
            admin_token: None,
            audit_url: None,
            require_audit: false,
            aws_region: "us-east-1".into(),
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
            model: None,
            keys_file: None,
            default_budget_tokens: None,
            admin_token: None,
            audit_url: None,
            require_audit: false,
            aws_region: "us-east-1".into(),
        }
    }

    fn resolver_of(pairs: &[(&str, &str)], dir: Option<&std::path::Path>) -> Resolver {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Resolver::with(
            Box::new(move |k| map.get(k).cloned()),
            dir.map(|d| d.to_path_buf()),
        )
    }

    #[test]
    fn upstream_resolves_from_ark_family_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("ark.env"),
            "ARK_API_KEY=file-key\nARK_BASE_URL=https://file.example/api/v3/\n",
        )
        .unwrap();
        let cfg =
            GateConfig::from_cli_with(cli_min(), &resolver_of(&[], Some(tmp.path()))).unwrap();
        assert_eq!(cfg.upstream.api_key, "file-key");
        // trailing slash trimmed, same as the explicit path
        assert_eq!(cfg.upstream.base_url, "https://file.example/api/v3");
    }

    #[test]
    fn explicit_gate_override_beats_family_and_default_base_applies() {
        let mut cli = cli_min();
        cli.upstream_api_key = Some("explicit-key".into());
        let cfg =
            GateConfig::from_cli_with(cli, &resolver_of(&[("ARK_API_KEY", "family-key")], None))
                .unwrap();
        assert_eq!(cfg.upstream.api_key, "explicit-key");
        // no explicit base_url and no family value → the built-in Ark default
        assert_eq!(
            cfg.upstream.base_url,
            agentkeys_inference_creds::DEFAULT_ARK_BASE
        );
    }

    #[test]
    fn missing_key_everywhere_fails_naming_all_sources() {
        let err = GateConfig::from_cli_with(cli_min(), &resolver_of(&[], None))
            .unwrap_err()
            .to_string();
        assert!(err.contains("AGENTKEYS_GATE_UPSTREAM_API_KEY"), "{err}");
        assert!(err.contains("ark family"), "{err}");
        assert!(err.contains("rotate-inference-cred.sh"), "{err}");
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
