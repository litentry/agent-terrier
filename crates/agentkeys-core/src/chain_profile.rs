//! Local chain configuration and explicit custom profiles.
//! Resolution order: profile file, CLI name, environment name, local default.
//! Signing material is never part of a chain profile.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const BUILTIN_PROFILES: &[(&str, &str)] =
    &[("anvil", include_str!("../chain-profiles/anvil.json"))];

pub const DEFAULT_PROFILE: &str = "anvil";

pub fn rpc_http_override(
    chain_name: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let suffix = chain_name.to_uppercase().replace('-', "_");
    lookup(&format!("AGENTKEYS_CHAIN_RPC_HTTP_{suffix}"))
        .or_else(|| lookup("AGENTKEYS_CHAIN_RPC_HTTP"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Error)]
pub enum ChainProfileError {
    #[error("development signing requires AGENT_TERRIER_LOCAL_DEV=1, the local development chain ID and a loopback RPC endpoint")]
    DevelopmentSigningForbidden,

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
    /// Runtime deployment addresses; local setup writes these to an ignored custom profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contracts: Vec<ContractInfo>,
    /// Version of the deployed contract SET for this chain (e.g. `"0.1"`). The
    /// idempotency key: `crates/agentkeys-chain/VERSION` is the EXPECTED source
    /// version; a deploy redeploys + bumps this only when they differ (no
    /// bytecode comparison — Solidity metadata + immutables make it unreliable).
    /// `None` for chains with no deployed contracts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_set_version: Option<String>,
    /// Present for dev/test chains; absent for production. See
    /// `DevEnvironment` doc-comment for the convention around
    /// `is_development_default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_environment: Option<DevEnvironment>,
    /// Per-chain native-token funding amounts — the SoT for the deploy scripts so
    /// ETH-priced chains (Base) aren't funded at HEI-sized amounts (a HEI-sized
    /// 0.35 deposit on Base would escrow ~$1000s and exceed the deployer balance).
    /// Read via `agentkeys chain show <chain> | jq -r .funding.<field>`; absent
    /// fields fall back to the deploy script's built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding: Option<Funding>,
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
    /// `maxPriorityFeePerGas` (gwei) for master UserOps. Wired into the op's
    /// gas_fees by the broker (gwei→wei), falling back to the broker default when a
    /// profile has no usable fee (legacy/anvil `max_fee_gwei == 0`).
    pub max_priority_fee_gwei: u64,
    /// `maxFeePerGas` (gwei) for master UserOps — the chain's real fee ceiling, NOT
    /// a blanket value. It sizes the EntryPoint prefund reserve (× total gas), so on
    /// a cheap L2 (Base ~0.005 gwei base fee → ~2 here) a Heima-scale 40+ gwei would
    /// reserve a prefund the paymaster deposit can't cover (false AA31).
    pub max_fee_gwei: u64,
    /// ERC-4337 UserOp `verificationGasLimit` for master ops (accept / scope /
    /// revoke / #278 D6 register). `validateUserOp` runs an on-chain P-256 verify
    /// (~3.4k gas on a RIP-7212 precompile chain, #170 / #288) — BUT the D6 register
    /// also deploys the P256Account inside the UserOp (initCode), which the EntryPoint
    /// runs within this limit (~1.3M on Base). So set it to cover the DEPLOY, not just
    /// the verify (Base: 1.6M even with the precompile; the earlier 200k OOG'd the
    /// deploy → AA13). `None` ⇒ the broker's 1.5M default (chains on the pure-Solidity
    /// verifier). NEVER set it below the real cost: under-gas reverts inside
    /// `validateUserOp` as a false `SIG_VALIDATION_FAILED` (#225 / gap #7).
    /// Env `ACCEPT_VERIFICATION_GAS_LIMIT[_<CHAIN>]` overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_gas_limit: Option<u128>,
    /// ERC-4337 UserOp `preVerificationGas` for master ops. `None` ⇒ the broker
    /// default (100k). Env `ACCEPT_PRE_VERIFICATION_GAS[_<CHAIN>]` overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_verification_gas: Option<u128>,
}

/// Per-chain native-token funding amounts, all in **wei encoded as decimal
/// strings** (wei exceeds the JSON safe-integer range; strings avoid precision
/// loss and the deploy scripts consume them verbatim via `jq -r`). Every field
/// is optional — a missing/empty field means "use the deploy script's built-in
/// default". ETH-priced chains (Base) set these far lower than HEI chains.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Funding {
    /// Min deployer native balance required before a contract deploy proceeds
    /// (`heima-bring-up.sh`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub deploy_min_wei: String,
    /// VerifyingPaymaster EntryPoint deposit top-up target (`heima-deploy-paymaster.sh`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub paymaster_deposit_wei: String,
    /// Refill the paymaster deposit when it drops below this.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub paymaster_min_deposit_wei: String,
    /// Deployer native reserve held back in the ERC-4337 register pre-flight
    /// (`_erc4337_lib.sh`): ≈ the chain ExistentialDeposit so spending the account
    /// deposit can't reap the DEPLOYER. `"0"` on non-substrate chains (no ED).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ed_buffer_wei: String,
    /// The EntryPoint contract's standing native buffer (`heima-deploy-erc4337.sh`):
    /// a generous balance (≫ the ED) so account-recreation can't reap the EntryPoint
    /// (the AA91 class). SEPARATE from `ed_buffer_wei` (the bare deployer ED) — the
    /// two were conflated, which over-charged the deployer pre-flight. Consumers
    /// fall back to `ed_buffer_wei` when this is unset (un-migrated profiles).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub entrypoint_native_buffer_wei: String,
    /// Per-account EntryPoint deposit top-up for the #164 master register
    /// (`_erc4337_lib.sh`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account_deposit_wei: String,
    /// `maxFeePerGas` for the register UserOp (`_erc4337_lib.sh`). The EntryPoint's
    /// required prefund = this × Σ(gas limits), so an ETH chain MUST set a
    /// chain-realistic (low) cap or the prefund alone is unaffordable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub userop_max_fee_wei: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployConfig {
    /// Env var the operator sets with their deployer private key for
    /// hot-key contract deploys via Foundry. In production sovereign-mode
    /// deploys, the signer signs the deploy tx and this var is unused.
    pub deployer_env_var: String,
    /// `--chain` argument to pass to `forge script ... --chain <X>`.
    pub foundry_chain_arg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet_url: Option<String>,
}

/// Development metadata, with the local profile selected by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevEnvironment {
    /// `true` for the canonical local development chain. Callers
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
#[serde(deny_unknown_fields)]
pub struct SudoConfig {
    /// `true` if the runtime ships `pallet_sudo`.
    pub enabled: bool,
    /// Human-readable label for the sudoer (e.g. "alice" for the
    /// well-known Substrate dev account).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sudoer_alias: String,
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
    pub fn require_local_development(
        &self,
        enabled: bool,
        rpc_override: Option<&str>,
    ) -> Result<(), ChainProfileError> {
        let expected_chain_id = Self::load_builtin(DEFAULT_PROFILE)?.chain_id;
        let endpoint = rpc_override.unwrap_or(&self.rpc.http);
        let is_loopback = reqwest::Url::parse(endpoint).is_ok_and(|url| {
            let host = url.host_str().unwrap_or("");
            let host = host.trim_start_matches('[').trim_end_matches(']');
            url.scheme() == "http"
                && url.username().is_empty()
                && url.password().is_none()
                && (host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback()))
        });
        if enabled
            && self.chain_kind == ChainKind::LocalDev
            && self.chain_id == expected_chain_id
            && is_loopback
        {
            Ok(())
        } else {
            Err(ChainProfileError::DevelopmentSigningForbidden)
        }
    }

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

    /// Find the development default in the public profile inventory.
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

    fn fixture() -> ChainProfile {
        serde_json::from_str(include_str!(
            "../../../e2e/fixtures/chain-profiles/local-test.json"
        ))
        .unwrap()
    }

    #[test]
    fn development_signing_checks_profile_kind_id_and_effective_endpoint() {
        let mut profile = ChainProfile::load_builtin(DEFAULT_PROFILE).unwrap();
        assert!(profile.require_local_development(true, None).is_ok());
        assert!(profile.require_local_development(false, None).is_err());
        for endpoint in [
            "https://rpc.example.test",
            "http://localhost.example.test",
            "http://192.0.2.1",
            "http://user:password@localhost",
            "",
        ] {
            assert!(profile
                .require_local_development(true, Some(endpoint))
                .is_err());
        }
        assert!(profile
            .require_local_development(true, Some("http://[::1]:8545"))
            .is_ok());
        profile.chain_kind = ChainKind::EthereumL1;
        assert!(profile.require_local_development(true, None).is_err());
        profile.chain_kind = ChainKind::LocalDev;
        profile.chain_id += 1;
        assert!(profile.require_local_development(true, None).is_err());
    }

    #[test]
    fn default_is_local_without_deployed_accounts_or_signing_material() {
        let (profile, reason) = ChainProfile::resolve(None, None, None).unwrap();
        assert_eq!(profile.name, DEFAULT_PROFILE);
        assert_eq!(profile.chain_kind, ChainKind::LocalDev);
        assert_eq!(profile.chain_id, 31337);
        assert_eq!(profile.rpc.http, "http://localhost:8545");
        assert!(profile.contracts.is_empty());
        assert_eq!(
            ChainProfile::development_default_name(),
            Some(DEFAULT_PROFILE)
        );
        assert_eq!(ChainProfile::list_builtin_names(), vec![DEFAULT_PROFILE]);
        assert!(reason.contains(DEFAULT_PROFILE));
    }

    #[test]
    fn explicit_unknown_configuration_fails_instead_of_selecting_a_default() {
        assert!(ChainProfile::resolve(Some("unknown"), None, None).is_err());
        assert!(ChainProfile::resolve(None, Some("unknown"), None).is_err());
        assert!(ChainProfile::resolve(None, None, Some("missing-profile.json")).is_err());
        assert_eq!(
            ChainProfile::load_builtin("ANVIL").unwrap().name,
            DEFAULT_PROFILE
        );
    }

    #[test]
    fn explicit_profile_file_wins_and_cli_name_precedes_environment() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        std::fs::write(&path, serde_json::to_vec(&fixture()).unwrap()).unwrap();
        let (profile, _) =
            ChainProfile::resolve(Some("unknown"), Some("unknown"), path.to_str()).unwrap();
        assert_eq!(profile.name, "test-chain");
        assert_eq!(
            ChainProfile::resolve(Some("anvil"), Some("unknown"), None)
                .unwrap()
                .0
                .name,
            "anvil"
        );
    }

    #[test]
    fn custom_registry_and_explorer_remain_supported() {
        let mut profile = fixture();
        assert!(profile.contract("credentialaudit").is_some());
        assert!(profile.contract("missing").is_none());
        let address = format!("0x{}", "01".repeat(20));
        assert_eq!(
            profile.explorer.contract_url(&address),
            profile.explorer.address_url(&address)
        );
        profile.explorer.contract_url_template =
            "https://explorer.example.test/contract/{address}".into();
        assert_eq!(
            profile.explorer.contract_url(&address),
            format!("https://explorer.example.test/contract/{address}")
        );
        assert_eq!(
            profile.explorer.tx_url("synthetic-hash"),
            "https://explorer.example.test/tx/synthetic-hash"
        );
    }

    #[test]
    fn profiles_reject_embedded_signing_material_without_echoing_it() {
        let mut profile = serde_json::to_value(fixture()).unwrap();
        let canary = "synthetic-sensitive-canary";
        profile["deploy"]["default_test_key"] = canary.into();
        let error = serde_json::from_value::<ChainProfile>(profile).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
        assert!(!error.to_string().contains(canary));
        let sudo = serde_json::json!({"enabled": true, "sudoer_seed_phrase": canary});
        assert!(!serde_json::from_value::<SudoConfig>(sudo)
            .unwrap_err()
            .to_string()
            .contains(canary));
    }
}
