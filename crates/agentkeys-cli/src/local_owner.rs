use std::time::Duration;

use agentkeys_backend_client::protocol::BuildAcceptUserOpResponse;
use agentkeys_core::chain_profile::{rpc_http_override, ChainProfile};
use agentkeys_core::erc4337::*;
use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{development_signing::DevelopmentSigning, CommandContext};

const LOCAL_MASTER_ROLES: u8 = 0b111;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum OwnerAction {
    Register,
    Grant,
    Revoke,
}

#[derive(clap::Args)]
pub struct OwnerOptions {
    #[arg(value_enum)]
    pub action: OwnerAction,
    #[arg(long)]
    pub operator_omni: String,
    #[arg(long)]
    pub key_file: String,
    #[arg(long, default_value = "localhost")]
    pub rp_id: String,
    #[arg(long)]
    pub beneficiary: String,
    #[arg(long)]
    pub actor_omni: Option<String>,
    #[arg(long)]
    pub service: Vec<String>,
    #[arg(long)]
    pub read_only: bool,
    #[arg(long)]
    pub verification_gas: Option<u128>,
    #[arg(long, default_value_t = DEFAULT_CALL_GAS_LIMIT)]
    pub call_gas: u128,
}

#[derive(Serialize, Deserialize)]
pub struct OwnerPlan {
    pub development_only: bool,
    pub operator_omni: String,
    pub account: String,
    pub device_key_hash: String,
    pub already_registered: bool,
    pub build: Option<BuildAcceptUserOpResponse>,
    pub transaction_data: Option<String>,
}

struct LocalChain {
    profile: ChainProfile,
    development: DevelopmentSigning,
    endpoint: String,
    client: reqwest::Client,
}

fn hex_value(value: &[u8]) -> String {
    format!("0x{}", hex::encode(value))
}

fn fixed<const SIZE: usize>(value: &str) -> Result<[u8; SIZE]> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))?
        .try_into()
        .map_err(|_| anyhow!("expected {SIZE}-byte hexadecimal value"))
}

impl LocalChain {
    async fn connect(context: &CommandContext) -> Result<Self> {
        let development = context.development_signing()?;
        let profile = context.chain_profile()?.clone();
        let endpoint = rpc_http_override(&profile.name, |name| std::env::var(name).ok())
            .unwrap_or_else(|| profile.rpc.http.clone());
        development.require_local_service(&endpoint)?;
        let chain = Self {
            profile,
            development,
            endpoint,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()?,
        };
        let metadata = chain.rpc("anvil_metadata", json!([])).await?;
        ensure!(
            metadata["chainId"].as_u64() == Some(chain.profile.chain_id)
                && metadata["clientVersion"]
                    .as_str()
                    .is_some_and(|version| version.starts_with("anvil/"))
                && metadata["forkedNetwork"].is_null()
                && metadata["instanceId"]
                    .as_str()
                    .is_some_and(|identity| fixed::<32>(identity).is_ok()),
            "owner operations require an unforked local Anvil node"
        );
        ensure!(
            chain.rpc("eth_chainId", json!([])).await? == format!("0x{:x}", chain.profile.chain_id)
                && chain.rpc("eth_accounts", json!([])).await? == json!([]),
            "local chain identity or unlocked-account configuration mismatch"
        );
        Ok(chain)
    }

    async fn rpc(&self, method: &str, parameters: Value) -> Result<Value> {
        let response: Value = self
            .client
            .post(&self.endpoint)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":parameters}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        ensure!(
            response.get("error").is_none(),
            "local chain RPC {method} failed"
        );
        response
            .get("result")
            .cloned()
            .context("local chain RPC result missing")
    }

    fn contract(&self, name: &str) -> Result<[u8; 20]> {
        let address = fixed(
            &self
                .profile
                .contract(name)
                .with_context(|| format!("local contract {name} is not deployed"))?
                .address,
        )?;
        ensure!(address != [0; 20], "zero contract address");
        Ok(address)
    }

    async fn call(&self, contract: &[u8; 20], data: &[u8]) -> Result<[u8; 32]> {
        let result = self
            .rpc(
                "eth_call",
                json!([{"to":hex_value(contract),"data":hex_value(data)},"latest"]),
            )
            .await?;
        fixed(result.as_str().context("invalid contract result")?)
    }

    async fn code_exists(&self, address: &[u8; 20]) -> Result<bool> {
        let result = self
            .rpc("eth_getCode", json!([hex_value(address), "latest"]))
            .await?;
        let code = result
            .as_str()
            .and_then(|code| code.strip_prefix("0x"))
            .context("invalid contract code response")?;
        Ok(!hex::decode(code)?.is_empty())
    }
}

pub async fn prepare(context: &CommandContext, options: &OwnerOptions) -> Result<OwnerPlan> {
    let operator = fixed::<32>(&options.operator_omni)?;
    ensure!(operator != [0; 32], "operator identity cannot be zero");
    let beneficiary = fixed::<20>(&options.beneficiary)?;
    ensure!(beneficiary != [0; 20], "beneficiary cannot be zero");
    ensure!(
        options.rp_id == "localhost",
        "local owner passkeys use the localhost relying party"
    );
    let actor = options.actor_omni.as_deref().map(fixed::<32>).transpose()?;
    match options.action {
        OwnerAction::Register => ensure!(
            actor.is_none() && options.service.is_empty() && !options.read_only,
            "register does not accept grant arguments"
        ),
        OwnerAction::Grant => ensure!(
            actor.is_some() && !options.service.is_empty(),
            "grant requires an actor and at least one service"
        ),
        OwnerAction::Revoke => ensure!(
            actor.is_some() && options.service.is_empty() && !options.read_only,
            "revoke requires only an actor"
        ),
    }
    ensure!(
        options.service.len() <= 64
            && options.service.iter().all(|service| !service.is_empty()
                && service.len() <= 256
                && !service.contains(char::is_whitespace)),
        "invalid or excessive service identifiers"
    );
    if options.action != OwnerAction::Register {
        ensure!(
            std::path::Path::new(&options.key_file).exists(),
            "existing owner passkey required"
        );
    }
    let chain = LocalChain::connect(context).await?;
    let entry_point = chain.contract("EntryPoint")?;
    let registry = chain.contract("SidecarRegistry")?;
    let scope = chain.contract("AgentKeysScope")?;
    let factory = chain.contract("P256AccountFactory")?;
    for address in [&entry_point, &registry, &scope, &factory] {
        ensure!(
            chain.code_exists(address).await?,
            "profile contract has no deployed code"
        );
    }
    let registered = chain
        .call(&registry, &operator_master_wallet_calldata(&operator))
        .await?;
    ensure!(registered == [0; 32] || std::path::Path::new(&options.key_file).exists(), "registered owner passkey is missing; restore its original key instead of generating another");
    let (public_x, public_y, rp_id_hash) = crate::k11_webauthn::software_webauthn_keygen(
        &chain.development,
        &options.key_file,
        &options.rp_id,
    )?;
    let public_x = fixed::<32>(&public_x)?;
    let public_y = fixed::<32>(&public_y)?;
    let rp_id_hash = fixed::<32>(&rp_id_hash)?;
    let credential = master_cred_id_hash(&operator);
    let salt = master_account_salt(&operator);
    let predicted = chain
        .call(
            &factory,
            &factory_account_calldata(&credential, &public_x, &public_y, &rp_id_hash, &salt),
        )
        .await?;
    ensure!(
        predicted[..12] == [0; 12],
        "invalid account address returned by factory"
    );
    let account: [u8; 20] = predicted[12..].try_into()?;
    ensure!(
        registered == [0; 32] || registered == predicted,
        "owner key does not match the on-chain master account"
    );
    let mut plan = OwnerPlan {
        development_only: true,
        operator_omni: hex_value(&operator),
        account: hex_value(&account),
        device_key_hash: hex_value(&master_device_key_hash(&operator)),
        already_registered: registered == predicted,
        build: None,
        transaction_data: None,
    };
    if options.action == OwnerAction::Register && plan.already_registered {
        return Ok(plan);
    }
    ensure!(
        options.action == OwnerAction::Register || plan.already_registered,
        "register the local owner first"
    );
    let call_data = match options.action {
        OwnerAction::Register => register_batch_calldata(
            &registry,
            &RegisterFirstMaster {
                device_key_hash: master_device_key_hash(&operator),
                operator_omni: operator,
                actor_omni: operator,
                cred_id_hash: credential,
                rpid_hash: rp_id_hash,
                pub_x: public_x,
                pub_y: public_y,
                roles: LOCAL_MASTER_ROLES,
            },
        ),
        OwnerAction::Grant => scope_batch_calldata(
            &scope,
            &operator,
            &actor.context("missing actor")?,
            &ScopeGrant {
                services: options
                    .service
                    .iter()
                    .map(|service| agentkeys_core::device_crypto::keccak256(service.as_bytes()))
                    .collect(),
                read_only: options.read_only,
                max_per_call: 0,
                max_per_period: 0,
                max_total: 0,
                period_seconds: 0,
            },
        ),
        OwnerAction::Revoke => execute_batch_calldata(
            &[scope],
            &[0],
            &[revoke_scope_calldata(
                &operator,
                &actor.context("missing actor")?,
            )],
        ),
    };
    let init_code = if chain.code_exists(&account).await? {
        Vec::new()
    } else {
        p256_account_factory_init_code(
            &factory,
            &credential,
            &public_x,
            &public_y,
            &rp_id_hash,
            &salt,
        )
    };
    let gas_price = chain.rpc("eth_gasPrice", json!([])).await?;
    let gas_price = u128::from_str_radix(
        gas_price
            .as_str()
            .and_then(|value| value.strip_prefix("0x"))
            .context("invalid gas quote")?,
        16,
    )?;
    let gas_price = gas_price.checked_mul(2).context("gas quote overflow")?;
    let verification_gas = options
        .verification_gas
        .or(chain.profile.gas.verification_gas_limit)
        .unwrap_or(DEFAULT_VERIFICATION_GAS_LIMIT);
    ensure!(
        verification_gas > 0 && options.call_gas > 0,
        "gas limits must be positive"
    );
    let mut operation = PackedUserOp {
        sender: account,
        nonce: chain
            .call(&entry_point, &entrypoint_nonce_calldata(&account))
            .await?,
        init_code,
        call_data,
        account_gas_limits: pack_u128_pair(verification_gas, options.call_gas),
        pre_verification_gas: pack_u128_pair(
            0,
            chain
                .profile
                .gas
                .pre_verification_gas
                .unwrap_or(DEFAULT_PRE_VERIFICATION_GAS),
        ),
        gas_fees: pack_u128_pair(gas_price, gas_price),
        paymaster_and_data: Vec::new(),
        signature: Vec::new(),
    };
    let hash = hex_value(&operation.user_op_hash(&entry_point, chain.profile.chain_id));
    chain.development.verify_build(
        &wire_user_op_from_packed(&operation),
        &hash,
        &hex_value(&entry_point),
        chain.profile.chain_id,
    )?;
    let (authenticator, client_data, location, r, s) = crate::k11_webauthn::software_webauthn_sign(
        &chain.development,
        &options.key_file,
        &hash,
        &options.rp_id,
    )?;
    operation.signature = encode_webauthn_signature(
        &credential,
        &hex::decode(authenticator)?,
        &hex::decode(client_data)?,
        location as u128,
        &fixed::<32>(&r)?,
        &fixed::<32>(&s)?,
    );
    plan.transaction_data = Some(hex_value(&handle_ops_calldata(
        std::slice::from_ref(&operation),
        &beneficiary,
    )));
    plan.build = Some(BuildAcceptUserOpResponse {
        user_op: wire_user_op_from_packed(&operation),
        user_op_hash: hash,
        entry_point: hex_value(&entry_point),
        chain_id: chain.profile.chain_id,
    });
    Ok(plan)
}

pub async fn verify(context: &CommandContext, transaction: &str, plan: OwnerPlan) -> Result<Value> {
    fixed::<32>(transaction)?;
    let chain = LocalChain::connect(context).await?;
    let build = plan.build.context("owner plan has no operation")?;
    chain.development.verify_build(
        &build.user_op,
        &build.user_op_hash,
        &build.entry_point,
        build.chain_id,
    )?;
    let operation = wire_to_packed(&build.user_op).map_err(anyhow::Error::msg)?;
    let receipt = chain
        .rpc("eth_getTransactionReceipt", json!([transaction]))
        .await?;
    ensure!(
        receipt["transactionHash"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(transaction)),
        "transaction is not confirmed by this chain"
    );
    let success = agentkeys_core::user_operation_receipt::execution_succeeded(
        &receipt,
        &chain.contract("EntryPoint")?,
        &operation,
        &build.user_op_hash,
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(success, "owner operation reverted");
    Ok(
        json!({"verified":true,"development_only":true,"transaction_hash":transaction,"user_op_hash":build.user_op_hash,"account":hex_value(&operation.sender)}),
    )
}
