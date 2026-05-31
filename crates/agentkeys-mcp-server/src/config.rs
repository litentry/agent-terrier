//! Runtime configuration.
//!
//! Pulled from CLI flags + env vars; never from the workspace. The config is
//! built once at startup, cloned into every request handler via shared state,
//! and treated as immutable from then on.

use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "agentkeys-mcp-server",
    about = "AgentKeys MCP server — Phase 1 (issue #107)"
)]
pub struct Cli {
    /// Transport mode: `http` (default, for vendor deploys), `stdio`
    /// (for local MCP hosts that spawn this as a subprocess), or
    /// `mcp-endpoint` (connect outward to a xiaozhi-style relay URL).
    #[arg(long, env = "MCP_TRANSPORT", default_value = "http")]
    pub transport: String,

    /// MCP endpoint relay URL (xiaozhi `mcp-endpoint-server` style).
    /// Required when `--transport=mcp-endpoint`. Format:
    /// `ws[s]://host:port/mcp_endpoint/mcp/?token=...`. The token comes
    /// from your xiaozhi agent's MCP endpoint config (智控台 → 智能体
    /// → 配置角色 → MCP接入点).
    #[arg(long, env = "MCP_ENDPOINT")]
    pub mcp_endpoint: Option<String>,

    /// Backend mode: `http` (default — talks to real broker + workers via
    /// `--broker-url` / `--memory-url` / `--audit-url`) or `in-memory`
    /// (seeded with the three-act demo fixture; no external services
    /// needed; for the fresh-laptop dev demo).
    #[arg(long, env = "MCP_BACKEND", default_value = "http")]
    pub backend: String,

    /// HTTP bind address.
    #[arg(long, env = "MCP_LISTEN", default_value = "0.0.0.0:8088")]
    pub listen: SocketAddr,

    /// Broker base URL (e.g. `https://broker.litentry.org`).
    #[arg(long, env = "AGENTKEYS_BROKER_URL")]
    pub broker_url: Option<String>,

    /// Memory worker base URL.
    #[arg(long, env = "AGENTKEYS_MEMORY_URL")]
    pub memory_url: Option<String>,

    /// Audit worker base URL.
    #[arg(long, env = "AGENTKEYS_AUDIT_URL")]
    pub audit_url: Option<String>,

    /// Comma-separated `<vendor_id>:<bearer_token>` pairs that the HTTP
    /// transport will accept. Empty = HTTP refuses every request with 401.
    /// Format intentionally simple — vendor onboarding portal in M2 will
    /// replace this with a persisted issuance store.
    #[arg(long, env = "MCP_VENDOR_TOKENS", default_value = "")]
    pub vendor_tokens: String,

    /// Daily spend cap (in RMB units) used by the deterministic policy
    /// engine for `permission.check(scope="payment.spend")`. Per the
    /// three-act demo storyboard in `agent-iam-strategy.md` §4.3.
    #[arg(long, env = "MCP_DEFAULT_DAILY_SPEND_CAP_RMB", default_value_t = 500)]
    pub default_daily_spend_cap_rmb: u64,

    /// Ambient actor omni — used when the LLM-side `tools/call` doesn't
    /// supply an `actor`. In xiaozhi-hosted mode there's one agent per
    /// MCP server, so the LLM shouldn't need to know its own actor id.
    /// Defaults to the demo actor when --backend=in-memory.
    #[arg(long, env = "MCP_DEFAULT_ACTOR")]
    pub default_actor: Option<String>,

    /// Ambient operator omni — same rationale as default_actor.
    #[arg(long, env = "MCP_DEFAULT_OPERATOR_OMNI")]
    pub default_operator_omni: Option<String>,

    /// Ambient device-key hash — same rationale. Identifies the device the
    /// agent runs on for cap-mint binding.
    #[arg(long, env = "MCP_DEFAULT_DEVICE_KEY_HASH")]
    pub default_device_key_hash: Option<String>,

    /// Agent session JWT whose `agentkeys.omni_account` == `default_actor`.
    /// Used by the HTTP backend to mint per-actor STS creds for worker S3 ops
    /// (`/v1/mint-oidc-jwt` → `AssumeRoleWithWebIdentity`, tagged with the
    /// actor) and forward them as `X-Aws-*` headers. Without it the worker
    /// falls back to its instance profile and every S3 op 502s. arch.md §17.2
    /// / issue #90.
    #[arg(long, env = "MCP_AGENT_SESSION_BEARER")]
    pub agent_session_bearer: Option<String>,

    /// Per-data-class IAM role ARN the worker S3 op assumes via web-identity.
    /// memory ops → memory_role_arn; credential ops → vault_role_arn.
    #[arg(long, env = "MCP_MEMORY_ROLE_ARN")]
    pub memory_role_arn: Option<String>,

    #[arg(long, env = "MCP_VAULT_ROLE_ARN")]
    pub vault_role_arn: Option<String>,

    /// AWS region for the STS `AssumeRoleWithWebIdentity` call.
    #[arg(long, env = "AWS_REGION", default_value = "us-east-1")]
    pub aws_region: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub transport: Transport,
    pub backend: BackendKind,
    pub listen: SocketAddr,
    pub mcp_endpoint: Option<String>,
    pub broker_url: Option<String>,
    pub memory_url: Option<String>,
    pub audit_url: Option<String>,
    /// vendor_id → bearer_token
    pub vendor_tokens: HashMap<String, String>,
    pub default_daily_spend_cap_rmb: u64,
    /// Ambient identity used when the LLM doesn't pass actor / operator /
    /// device. Populated to demo fixture in InMemory mode; left None for
    /// HTTP mode unless explicitly set via CLI/env.
    pub default_actor: Option<String>,
    pub default_operator_omni: Option<String>,
    pub default_device_key_hash: Option<String>,
    /// Agent session JWT (omni == default_actor) for the per-actor STS relay.
    pub agent_session_bearer: Option<String>,
    pub memory_role_arn: Option<String>,
    pub vault_role_arn: Option<String>,
    pub aws_region: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http,
    Stdio,
    /// Connect outward to a xiaozhi MCP-endpoint relay URL as a WebSocket
    /// client. The relay forwards messages between this server (as the
    /// tool) and the xiaozhi-server/cloud (as the client). No HTTP listen
    /// socket; no firmware on the xiaozhi device needs to change.
    McpEndpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Http,
    InMemory,
}

impl Config {
    pub fn from_cli(cli: Cli) -> anyhow::Result<Self> {
        let transport = match cli.transport.as_str() {
            "http" => Transport::Http,
            "stdio" => Transport::Stdio,
            "mcp-endpoint" | "mcp_endpoint" => Transport::McpEndpoint,
            other => {
                anyhow::bail!("unknown transport `{other}` (expected http|stdio|mcp-endpoint)")
            }
        };

        if transport == Transport::McpEndpoint && cli.mcp_endpoint.is_none() {
            anyhow::bail!(
                "--transport=mcp-endpoint requires --mcp-endpoint <ws[s]://...> (or env MCP_ENDPOINT)"
            );
        }

        let backend = match cli.backend.as_str() {
            "http" => BackendKind::Http,
            "in-memory" | "in_memory" => BackendKind::InMemory,
            other => anyhow::bail!("unknown backend `{other}` (expected http|in-memory)"),
        };

        let mut vendor_tokens = HashMap::new();
        for pair in cli
            .vendor_tokens
            .split(',')
            .filter(|s| !s.trim().is_empty())
        {
            let (vendor, token) = pair
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("malformed vendor_token entry: {pair}"))?;
            vendor_tokens.insert(vendor.trim().to_string(), token.trim().to_string());
        }

        // In-memory dev mode auto-seeds a default vendor token if the
        // operator didn't supply one, so the runbook stays one-command.
        if backend == BackendKind::InMemory && vendor_tokens.is_empty() {
            vendor_tokens.insert("magiclick".into(), "demo-tok".into());
        }

        // In-memory dev mode also auto-seeds the demo identity so the
        // LLM can call memory.get with just {"namespace": "travel"}.
        // The DEMO_* constants come from backend/in_memory.rs and match
        // what the three-act fixture seeds.
        let (default_actor, default_operator_omni, default_device_key_hash) =
            if backend == BackendKind::InMemory {
                use crate::backend::in_memory::{DEMO_ACTOR, DEMO_DEVICE_KEY_HASH, DEMO_OPERATOR};
                (
                    Some(cli.default_actor.unwrap_or_else(|| DEMO_ACTOR.into())),
                    Some(
                        cli.default_operator_omni
                            .unwrap_or_else(|| DEMO_OPERATOR.into()),
                    ),
                    Some(
                        cli.default_device_key_hash
                            .unwrap_or_else(|| DEMO_DEVICE_KEY_HASH.into()),
                    ),
                )
            } else {
                (
                    cli.default_actor,
                    cli.default_operator_omni,
                    cli.default_device_key_hash,
                )
            };

        Ok(Self {
            transport,
            backend,
            listen: cli.listen,
            mcp_endpoint: cli.mcp_endpoint,
            broker_url: cli.broker_url,
            memory_url: cli.memory_url,
            audit_url: cli.audit_url,
            vendor_tokens,
            default_daily_spend_cap_rmb: cli.default_daily_spend_cap_rmb,
            default_actor,
            default_operator_omni,
            default_device_key_hash,
            agent_session_bearer: cli.agent_session_bearer,
            memory_role_arn: cli.memory_role_arn,
            vault_role_arn: cli.vault_role_arn,
            aws_region: cli.aws_region,
        })
    }

    /// Convenience builder for tests — no parsing, no env reads.
    pub fn for_tests() -> Self {
        Self {
            transport: Transport::Http,
            backend: BackendKind::Http,
            listen: "127.0.0.1:0".parse().unwrap(),
            mcp_endpoint: None,
            broker_url: None,
            memory_url: None,
            audit_url: None,
            vendor_tokens: HashMap::new(),
            default_daily_spend_cap_rmb: 500,
            default_actor: None,
            default_operator_omni: None,
            default_device_key_hash: None,
            agent_session_bearer: None,
            memory_role_arn: None,
            vault_role_arn: None,
            aws_region: "us-east-1".to_string(),
        }
    }

    pub fn with_vendor_token(mut self, vendor: &str, token: &str) -> Self {
        self.vendor_tokens
            .insert(vendor.to_string(), token.to_string());
        self
    }
}
