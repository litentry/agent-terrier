//! Chain profiles — one-stop config for every EVM backbone AgentKeys can target.
//!
//! AgentKeys's chain layer is pluggable per arch.md §22: contracts are plain
//! Solidity portable across any EVM-compatible chain (Heima, Base, Ethereum,
//! Sepolia, Anvil for local dev, …). Each chain has different RPC endpoints,
//! confirmation depth, gas model, and explorer URL shape. This module loads a
//! named profile that bundles all of these into one struct so callers (CLI,
//! daemon, broker, workers) don't have to know which env var maps to which
//! chain.
//!
//! ## Selecting a profile
//!
//! Order of resolution (first match wins):
//!
//! 1. Explicit `ChainProfile::load_from_file(path)` — operator points at a
//!    custom JSON file. For chains the binary doesn't ship by default.
//! 2. `AGENTKEYS_CHAIN_PROFILE_FILE` env var → load_from_file(path)
//! 3. `--chain <name>` CLI flag → `ChainProfile::load_builtin(name)`
//! 4. `AGENTKEYS_CHAIN` env var → `ChainProfile::load_builtin(name)`
//! 5. Default: `heima` (per arch.md §22 default chain backbone)
//!
//! ## Built-in profiles
//!
//! The binary embeds 7 profiles at compile time via `include_str!`. Adding a
//! new built-in is a one-file change under `chain-profiles/<name>.json` plus
//! one entry in the `BUILTIN_PROFILES` slice. Operators with custom chains
//! ship their own JSON and point at it via env var — no recompile needed.
//!
//! ## Wire shape: see `chain-profiles/heima.json` for the canonical example.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Compile-time embedded profiles. Adding a new chain backbone = drop a JSON
/// under `chain-profiles/` + append a `(name, include_str!(...))` row here.
const BUILTIN_PROFILES: &[(&str, &str)] = &[
    ("heima", include_str!("../chain-profiles/heima.json")),
    (
        "heima-paseo",
        include_str!("../chain-profiles/heima-paseo.json"),
    ),
    ("base", include_str!("../chain-profiles/base.json")),
    (
        "base-sepolia",
        include_str!("../chain-profiles/base-sepolia.json"),
    ),
    ("ethereum", include_str!("../chain-profiles/ethereum.json")),
    ("sepolia", include_str!("../chain-profiles/sepolia.json")),
    ("anvil", include_str!("../chain-profiles/anvil.json")),
];

/// The default chain when nothing is specified. Matches arch.md §22.
pub const DEFAULT_PROFILE: &str = "heima";

#[derive(Debug, Error)]
pub enum ChainProfileError {
    #[error("unknown chain profile '{0}'; built-ins: {1}")]
    UnknownProfile(String, String),

    #[error("failed to read profile file '{path}': {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse profile JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

/// One named EVM chain backbone — everything broker/daemon/CLI need to know
/// about a chain to deploy contracts, mint caps, and verify on-chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProfile {
    pub name: String,
    pub display_name: String,
    /// EVM chain ID for `eth_chainId` / EIP-155 tx signing. `0` means
    /// "auto-detect via eth_chainId at startup" — used by Heima Paseo where
    /// the runtime sets `ChainId = HEIMA_PARA_ID.into()` and the paraID can
    /// change between deployments.
    pub chain_id: u64,
    pub chain_kind: ChainKind,
    pub rpc: RpcEndpoints,
    pub explorer: ExplorerLinks,
    pub token: TokenInfo,
    pub finality: FinalityConfig,
    pub gas: GasConfig,
    pub deploy: DeployConfig,
    /// Deployed stage-1 contract registry for this chain — the addresses the
    /// broker/daemon/workers read and the parent-control UI displays (#153).
    /// Empty for chains where AgentKeys contracts aren't deployed. This is the
    /// single embedded source of truth (mirrors `docs/spec/deployed-contracts.md`);
    /// operators targeting a custom deploy override it via a profile file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contracts: Vec<ContractInfo>,
    /// Present for dev/test chains; absent for production. See
    /// `DevEnvironment` doc-comment for the convention around
    /// `is_development_default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_environment: Option<DevEnvironment>,
}

/// One deployed contract on a chain: name + address + operator-facing purpose.
/// Mirrors the per-chain table in `docs/spec/deployed-contracts.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    /// Contract name, e.g. `CredentialAudit`. Matches the Solidity source file.
    pub name: String,
    /// `0x`-prefixed EVM address (mixed-case checksum as deployed).
    pub address: String,
    /// One-line operator-facing description of what this contract anchors.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub purpose: String,
    /// Free-form deploy marker (date / "stage-1" / block) for display.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub deployed_at: String,
}

impl ChainProfile {
    /// Look up one deployed contract by name (case-insensitive). `None` if this
    /// chain has no such contract in its registry.
    pub fn contract(&self, name: &str) -> Option<&ContractInfo> {
        self.contracts
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ChainKind {
    /// Substrate parachain with Frontier pallet for EVM compatibility
    /// (Heima, Moonbeam, Astar). EVM tx via `pallet_ethereum::transact`.
    SubstrateFrontier,
    /// Layer-1 EVM execution (Ethereum mainnet, Sepolia).
    EthereumL1,
    /// OP-stack rollup (Base, Optimism, Mode, Zora). Soft finality at
    /// sequencer; hard finality on Ethereum settle.
    OptimismL2,
    /// Arbitrum Nitro rollup. Distinct gas model from OP-stack.
    Arbitrum,
    /// Local dev node (Anvil, Hardhat) for tests + demo bring-up.
    LocalDev,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEndpoints {
    pub http: String,
    pub wss: String,
    /// Only set for `substrate-frontier` chains where the Polkadot.js Apps
    /// view and Substrate-side extrinsics use a different WSS than the
    /// EVM-side `eth_*` RPC. Other kinds omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub substrate_wss: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorerLinks {
    pub url: String,
    pub tx_url_template: String,
    pub address_url_template: String,
    /// Optional separate template for *contract* pages, when the explorer
    /// distinguishes them from plain accounts (Heima's explorer uses
    /// `/contract/{address}` for contracts vs `/address/{address}` for EOAs).
    /// Empty ⇒ `contract_url()` falls back to `address_url()`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub contract_url_template: String,
    /// Optional pointer at the open-source explorer codebase, when one is
    /// available. Stage 1 uses it to track *where* to land agentkeys-
    /// specific indexing + display for ScopeContract / SidecarRegistry /
    /// K3EpochCounter events. Heima ships forks of subscan-essentials
    /// (backend + frontend) under github.com/litentry that are the
    /// natural integration target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscan_source: Option<SubscanSource>,
}

/// Pointer to the open-source explorer codebase for a chain. Set per-chain
/// in the profile JSON when the operator (or AgentKeys project) plans to
/// land custom indexing for the on-chain stage-1 contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscanSource {
    pub backend_repo: String,
    pub frontend_repo: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl ExplorerLinks {
    /// Render the explorer URL for one transaction by substituting `{tx_hash}`.
    pub fn tx_url(&self, tx_hash: &str) -> String {
        self.tx_url_template.replace("{tx_hash}", tx_hash)
    }

    /// Render the explorer URL for one address by substituting `{address}`.
    pub fn address_url(&self, address: &str) -> String {
        self.address_url_template.replace("{address}", address)
    }

    /// Render the explorer URL for one *contract* by substituting `{address}`.
    /// Falls back to [`Self::address_url`] when no contract-specific template
    /// is set (most explorers serve contracts under `/address/` too).
    pub fn contract_url(&self, address: &str) -> String {
        if self.contract_url_template.is_empty() {
            self.address_url(address)
        } else {
            self.contract_url_template.replace("{address}", address)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Which block tag the broker uses for scope/registry/epoch reads.
    /// `"latest"` = no confirmation wait (Heima/Anvil); `"safe"` = OP-stack
    /// L1-posted; `"finalized"` = Ethereum 2-epoch finalized.
    pub default_block_tag: String,
    /// Wait this many confirmations before treating a chain submission as
    /// authoritative for cap-mint decisions. Used for chains where block-tag
    /// alone isn't expressive enough.
    #[serde(default)]
    pub confirmation_blocks: u64,
    /// Time-based fallback for confirmation; useful for time-finality chains
    /// (Heima parachain) where block count varies with relay-chain pacing.
    #[serde(default)]
    pub confirmation_seconds: u64,
    /// Operator-facing notes about this chain's finality model. Surfaced in
    /// CLI verbose output to head off "why is this slow" confusion.
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// `"eip1559"` or `"legacy"`. Anvil + some local dev chains use legacy.
    pub model: String,
    pub max_priority_fee_gwei: u64,
    pub max_fee_gwei: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployConfig {
    /// Env var the operator sets with their deployer private key for
    /// hot-key contract deploys via Foundry. In production sovereign-mode
    /// deploys, the signer signs the deploy tx and this var is unused.
    pub deployer_env_var: String,
    /// `--chain` argument to pass to `forge script ... --chain <X>`.
    pub foundry_chain_arg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_test_key: Option<String>,
}

/// Per-profile development-environment metadata. Populated for testnet /
/// local-dev profiles; absent for production chains.
///
/// The `is_development_default` flag identifies the canonical chain
/// AgentKeys operators should use when bringing up a fresh dev/test
/// deployment. Per convention (arch.md §22a): production default is
/// `heima` mainnet, development default is `heima-paseo` testnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevEnvironment {
    /// `true` for the canonical development chain (heima-paseo). Callers
    /// pick the dev default by scanning all built-in profiles for the
    /// one with this flag set.
    #[serde(default)]
    pub is_development_default: bool,
    /// Optional Substrate-sudo metadata (`pallet_sudo` configuration).
    /// Testnets typically expose sudo backed by the well-known dev Alice
    /// key; production chains do not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo: Option<SudoConfig>,
}

/// Substrate `pallet_sudo` metadata. The sudoer is one account that can
/// call `sudo.sudo(call)` to execute any extrinsic with root origin —
/// bypassing every other origin check. Testnet convenience; never in
/// production.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoConfig {
    /// `true` if the runtime ships `pallet_sudo`.
    pub enabled: bool,
    /// Human-readable label for the sudoer (e.g. "alice" for the
    /// well-known Substrate dev account).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sudoer_alias: String,
    /// SURI seed phrase for the sudoer, when known. For Alice this is
    /// the well-known dev phrase published in `subkey` docs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sudoer_seed_phrase: String,
    /// Sudoer public key in hex (`0x...`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sudoer_public_key: String,
    /// Sudoer's SS58 address under the generic prefix 42 (re-encode for
    /// chain-specific prefix via `subkey` / `polkadot-js`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sudoer_ss58_generic: String,
    /// Free-form note explaining how to invoke sudo (Polkadot.js Apps,
    /// subxt, @polkadot/api, …) for this chain.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sudo_via: String,
    /// Operator-facing warnings (e.g. "anyone can sign as Alice; testnet
    /// only"). Surfaced in CLI verbose output before any sudo-related op.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl ChainProfile {
    /// Load one of the built-in profiles by name. Names are case-insensitive.
    ///
    /// Use this for the standard chains AgentKeys ships with. For operator-
    /// custom chains use `load_from_file` instead.
    pub fn load_builtin(name: &str) -> Result<Self, ChainProfileError> {
        let lookup = name.to_ascii_lowercase();
        for (n, json) in BUILTIN_PROFILES {
            if *n == lookup {
                return Ok(serde_json::from_str(json)?);
            }
        }
        let available: Vec<&str> = BUILTIN_PROFILES.iter().map(|(n, _)| *n).collect();
        Err(ChainProfileError::UnknownProfile(
            name.to_string(),
            available.join(", "),
        ))
    }

    /// Load a profile from a JSON file. For operator-custom chains.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ChainProfileError> {
        let path_str = path.as_ref().display().to_string();
        let text = fs::read_to_string(&path).map_err(|e| ChainProfileError::ReadFile {
            path: path_str,
            source: e,
        })?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Resolve a profile per the documented precedence (file path > CLI name >
    /// env var > default).
    ///
    /// `cli_name` is the value passed via `--chain` (or `None` if the flag
    /// wasn't given). `env_name` is `std::env::var("AGENTKEYS_CHAIN").ok()`.
    /// `env_file` is `std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE").ok()`.
    /// Returns the resolved profile plus a debug string explaining which
    /// step matched (handy for `--verbose` output).
    pub fn resolve(
        cli_name: Option<&str>,
        env_name: Option<&str>,
        env_file: Option<&str>,
    ) -> Result<(Self, String), ChainProfileError> {
        if let Some(path) = env_file {
            if !path.is_empty() {
                let p = Self::load_from_file(path)?;
                return Ok((
                    p,
                    format!("loaded from $AGENTKEYS_CHAIN_PROFILE_FILE={path}"),
                ));
            }
        }
        if let Some(name) = cli_name {
            if !name.is_empty() {
                let p = Self::load_builtin(name)?;
                return Ok((p, format!("built-in profile via --chain={name}")));
            }
        }
        if let Some(name) = env_name {
            if !name.is_empty() {
                let p = Self::load_builtin(name)?;
                return Ok((p, format!("built-in profile via $AGENTKEYS_CHAIN={name}")));
            }
        }
        let p = Self::load_builtin(DEFAULT_PROFILE)?;
        Ok((p, format!("built-in default profile {DEFAULT_PROFILE}")))
    }

    /// List built-in profile names — handy for `agentkeys chain list` output.
    pub fn list_builtin_names() -> Vec<&'static str> {
        BUILTIN_PROFILES.iter().map(|(n, _)| *n).collect()
    }

    /// Find the canonical development-default profile across all built-ins
    /// (the one with `dev_environment.is_development_default == true`).
    /// Per arch.md §22a: this is `heima-paseo`. Used by tooling that wants
    /// to differentiate "the production default" (`DEFAULT_PROFILE`) from
    /// "the dev default" (this method).
    pub fn development_default_name() -> Option<&'static str> {
        for (name, json) in BUILTIN_PROFILES {
            if let Ok(p) = serde_json::from_str::<ChainProfile>(json) {
                if p.dev_environment
                    .as_ref()
                    .map(|d| d.is_development_default)
                    .unwrap_or(false)
                {
                    return Some(name);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_loads_and_parses() {
        for name in ChainProfile::list_builtin_names() {
            let p = ChainProfile::load_builtin(name)
                .unwrap_or_else(|e| panic!("builtin '{name}' failed to load: {e}"));
            assert_eq!(p.name, name, "profile.name must match file name");
        }
    }

    #[test]
    fn heima_profile_has_known_values() {
        let p = ChainProfile::load_builtin("heima").unwrap();
        assert_eq!(p.chain_id, 212013);
        assert_eq!(p.chain_kind, ChainKind::SubstrateFrontier);
        assert_eq!(p.token.symbol, "HEI");
        assert!(
            p.rpc.substrate_wss.is_some(),
            "heima must carry substrate_wss"
        );
    }

    #[test]
    fn heima_carries_stage1_contract_registry() {
        let p = ChainProfile::load_builtin("heima").unwrap();
        // The 4 stage-1 core contracts the audit decode + UI reference must be
        // present with the canonical mainnet addresses (mirrors
        // docs/spec/deployed-contracts.md). Pin them so a profile edit that
        // drops/renames one fails CI.
        for (name, addr) in [
            (
                "AgentKeysScope",
                "0xd44b375daefc65768f417d0f0125b68d5ba7df3b",
            ),
            (
                "SidecarRegistry",
                "0x1Ac62f1C2D828476a5D784e850a700dC1f17e0bE",
            ),
            (
                "K3EpochCounter",
                "0x6c9e675c699a06acefbc156afdee6bfbfe32ccb3",
            ),
            (
                "CredentialAudit",
                "0x63c4545ac01c77cc74044f25b8edea3880224577",
            ),
        ] {
            let c = p
                .contract(name)
                .unwrap_or_else(|| panic!("heima profile must carry {name}"));
            assert_eq!(c.address, addr, "{name} address drift");
            assert!(!c.purpose.is_empty(), "{name} must carry a purpose");
        }
        // Case-insensitive lookup + miss path.
        assert!(p.contract("credentialaudit").is_some());
        assert!(p.contract("NotAContract").is_none());
    }

    #[test]
    fn heima_explorer_uses_real_evm_explorer_urls() {
        // #153: the chain page + audit decode link to the live Heima EVM
        // explorer — contracts under /contract/, accounts under /address/.
        let p = ChainProfile::load_builtin("heima").unwrap();
        let addr = "0x63c4545ac01c77cc74044f25b8edea3880224577";
        assert_eq!(
            p.explorer.contract_url(addr),
            format!("https://explorer.heima.network/contract/{addr}")
        );
        assert_eq!(
            p.explorer.address_url(addr),
            format!("https://explorer.heima.network/address/{addr}")
        );
    }

    #[test]
    fn contract_url_falls_back_to_address_url_without_template() {
        // base has no contract_url_template → contract_url() === address_url().
        let p = ChainProfile::load_builtin("base").unwrap();
        let addr = "0x0000000000000000000000000000000000000001";
        assert_eq!(p.explorer.contract_url(addr), p.explorer.address_url(addr));
    }

    #[test]
    fn production_l1_chains_have_no_agentkeys_contracts() {
        // ethereum mainnet has no AgentKeys deploy — registry must be empty
        // (the field defaults to an empty vec when absent from the JSON).
        let p = ChainProfile::load_builtin("ethereum").unwrap();
        assert!(p.contracts.is_empty());
    }

    #[test]
    fn base_profile_has_known_values() {
        let p = ChainProfile::load_builtin("base").unwrap();
        assert_eq!(p.chain_id, 8453);
        assert_eq!(p.chain_kind, ChainKind::OptimismL2);
        assert_eq!(p.finality.default_block_tag, "safe");
        assert!(
            p.rpc.substrate_wss.is_none(),
            "base must not carry substrate_wss"
        );
    }

    #[test]
    fn ethereum_profile_uses_finalized_tag() {
        let p = ChainProfile::load_builtin("ethereum").unwrap();
        assert_eq!(p.chain_id, 1);
        assert_eq!(p.finality.default_block_tag, "finalized");
        assert!(p.finality.confirmation_blocks >= 32);
    }

    #[test]
    fn anvil_profile_has_instant_finality() {
        let p = ChainProfile::load_builtin("anvil").unwrap();
        assert_eq!(p.chain_id, 31337);
        assert_eq!(p.finality.confirmation_blocks, 0);
        assert_eq!(p.finality.confirmation_seconds, 0);
        assert!(
            p.deploy.default_test_key.is_some(),
            "anvil ships a default test key"
        );
    }

    #[test]
    fn case_insensitive_lookup() {
        let a = ChainProfile::load_builtin("HEIMA").unwrap();
        let b = ChainProfile::load_builtin("heima").unwrap();
        assert_eq!(a.chain_id, b.chain_id);
    }

    #[test]
    fn unknown_profile_lists_available() {
        let err = ChainProfile::load_builtin("doesnotexist").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("doesnotexist"));
        assert!(msg.contains("heima"));
        assert!(msg.contains("ethereum"));
    }

    #[test]
    fn resolve_uses_default_when_nothing_given() {
        let (p, why) = ChainProfile::resolve(None, None, None).unwrap();
        assert_eq!(p.name, DEFAULT_PROFILE);
        assert!(why.contains(DEFAULT_PROFILE));
    }

    #[test]
    fn resolve_cli_name_beats_env_name() {
        let (p, _) = ChainProfile::resolve(Some("base"), Some("ethereum"), None).unwrap();
        assert_eq!(p.name, "base");
    }

    #[test]
    fn resolve_env_file_beats_cli_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.json");
        // Reuse the heima json content so deserialize succeeds; rename it to
        // prove the file path won.
        let body = r#"{
          "name": "custom-x",
          "display_name": "custom",
          "chain_id": 999,
          "chain_kind": "ethereum-l1",
          "rpc": {"http": "http://x", "wss": "ws://x"},
          "explorer": {"url": "", "tx_url_template": "", "address_url_template": ""},
          "token": {"symbol": "X", "decimals": 18},
          "finality": {"default_block_tag": "latest"},
          "gas": {"model": "legacy", "max_priority_fee_gwei": 0, "max_fee_gwei": 0},
          "deploy": {"deployer_env_var": "X_KEY", "foundry_chain_arg": "x"}
        }"#;
        std::fs::write(&path, body).unwrap();
        let (p, why) =
            ChainProfile::resolve(Some("base"), Some("ethereum"), Some(path.to_str().unwrap()))
                .unwrap();
        assert_eq!(p.name, "custom-x");
        assert_eq!(p.chain_id, 999);
        assert!(why.contains("AGENTKEYS_CHAIN_PROFILE_FILE"));
    }

    #[test]
    fn explorer_url_substitution() {
        let p = ChainProfile::load_builtin("base").unwrap();
        let url = p.explorer.tx_url("0xabc123");
        assert!(url.contains("0xabc123"));
        assert!(url.starts_with("https://basescan.org"));
    }

    #[test]
    fn heima_paseo_chain_id_is_2013() {
        // Heima Paseo's EVM chain ID is 2013 (= HEIMA_PARA_ID; mainnet's
        // 212013 prefixes the year). Verified live 2026-05-18 against
        // https://rpc.paseo-parachain.heima.network — eth_chainId
        // returns 0x7dd. Pin this so a future "let's auto-detect"
        // refactor doesn't silently swap to the wrong chain.
        let p = ChainProfile::load_builtin("heima-paseo").unwrap();
        assert_eq!(p.chain_id, 2013);
        let mainnet = ChainProfile::load_builtin("heima").unwrap();
        assert_ne!(
            p.chain_id, mainnet.chain_id,
            "paseo and mainnet must not collide"
        );
    }

    #[test]
    fn heima_paseo_is_development_default_with_alice_sudo() {
        let p = ChainProfile::load_builtin("heima-paseo").unwrap();
        let dev = p
            .dev_environment
            .as_ref()
            .expect("heima-paseo carries dev metadata");
        assert!(dev.is_development_default, "heima-paseo is THE dev default");
        let sudo = dev.sudo.as_ref().expect("heima-paseo carries sudo config");
        assert!(sudo.enabled);
        assert_eq!(sudo.sudoer_alias, "alice");
        // Pin the well-known Alice public key — guards against accidental
        // edits substituting a different dev account.
        assert_eq!(
            sudo.sudoer_public_key,
            "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
        );
        assert!(
            sudo.sudoer_seed_phrase.contains("//Alice"),
            "Alice seed phrase must derive via //Alice"
        );
        assert!(
            !sudo.warnings.is_empty(),
            "sudo warnings must surface to operators"
        );
    }

    #[test]
    fn development_default_name_returns_heima_paseo() {
        // Per arch.md §22a, heima-paseo is the canonical dev default.
        // Adding a second dev-default profile would break this — that's
        // the intended behavior (you can have one production default and
        // one dev default, no more).
        assert_eq!(
            ChainProfile::development_default_name(),
            Some("heima-paseo")
        );
    }

    #[test]
    fn production_chains_carry_no_dev_environment() {
        for name in &["heima", "base", "base-sepolia", "ethereum", "sepolia"] {
            let p = ChainProfile::load_builtin(name).unwrap();
            assert!(
                p.dev_environment.is_none(),
                "{name} is production-shaped; must NOT have dev_environment metadata"
            );
        }
    }
}
