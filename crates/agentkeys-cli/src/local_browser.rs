use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use agentkeys_backend_client::protocol::{
    hosted_signer::*, BuildAcceptUserOpResponse, SubmitAcceptUserOpRequest,
};
use agentkeys_core::{
    browser_enrollment, device_crypto::DeviceKey, erc4337::*, registry::TIER_MASTER,
};
use agentkeys_web_core::broker::BrokerClient;
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};

use crate::agent_operation::{AgentOperationJournal, AgentOperationKind, AgentOperationRecord};
use crate::local_owner::{fixed, hex_value, LocalChain};
use crate::{agent_admin, k11_webauthn, local_data, CommandContext};

#[derive(clap::Args)]
pub struct BrowserOptions {
    #[arg(long)]
    pub operator_omni: String,
    #[arg(long)]
    pub key_file: String,
    #[arg(long)]
    pub device_key_file: String,
    #[arg(long)]
    pub session_file: String,
    #[arg(long)]
    pub broker_url: String,
    #[arg(long)]
    pub website_origin: String,
    #[arg(long)]
    pub confirm_device_key_hash: String,
    #[arg(long)]
    pub operations_dir: String,
}

#[derive(Debug, thiserror::Error)]
#[error("browser approval is incomplete; repeat the same command to check its saved operation without signing again")]
pub struct IncompleteApproval(pub Value);

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(unix)]
fn lock_operations(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0,
        "browser operation directory must be owned by this user with private permissions"
    );
    directory
        .try_lock()
        .map_err(|_| anyhow!("another browser approval owns this directory"))?;
    Ok(directory)
}

#[cfg(not(unix))]
fn lock_operations(_path: &Path) -> Result<std::fs::File> {
    anyhow::bail!("local browser approval requires Unix file permissions")
}

fn check_binding(
    intent: &HostedSignerIntent,
    options: &BrowserOptions,
    account: &[u8; 20],
    chain_id: u64,
) -> Result<()> {
    let origin = reqwest::Url::parse(&options.website_origin)?;
    ensure!(
        origin.scheme() == "http"
            && origin.host_str() == Some("localhost")
            && origin.origin().ascii_serialization() == options.website_origin
            && intent.origin == options.website_origin
            && intent.rp_id == "localhost",
        "browser request does not match the selected localhost website origin"
    );
    ensure!(
        fixed::<32>(&intent.operator_omni)? == fixed::<32>(&options.operator_omni)?
            && fixed::<20>(&intent.account)? == *account
            && intent.chain_id == chain_id,
        "browser request belongs to another owner, account or chain"
    );
    ensure!(
        fixed::<32>(&intent.device_key_hash)? == fixed::<32>(&options.confirm_device_key_hash)?,
        "browser device fingerprint does not match the explicit confirmation"
    );
    Ok(())
}

async fn active(chain: &LocalChain, intent: &HostedSignerIntent) -> Result<bool> {
    let operator = fixed::<32>(&intent.operator_omni)?;
    let device = chain
        .device(
            &chain.contract("SidecarRegistry")?,
            &fixed::<32>(&intent.device_key_hash)?,
        )
        .await?;
    if !device.is_registered() {
        return Ok(false);
    }
    let credential_hash = browser_enrollment::credential_hash(&intent.credential_id)?;
    let public_x = fixed::<32>(&intent.public_key_x)?;
    let public_y = fixed::<32>(&intent.public_key_y)?;
    use sha2::{Digest, Sha256};
    let rp_hash: [u8; 32] = Sha256::digest(intent.rp_id.as_bytes()).into();
    ensure!(
        !device.revoked
            && device.operator_omni == operator
            && device.actor_omni == operator
            && device.tier == TIER_MASTER
            && device.roles == HOSTED_SIGNER_CAP_MINT_ROLE
            && device.k11_cred_id == credential_hash
            && device.k11_rp_id_hash == rp_hash
            && device.k11_pub_x == public_x
            && device.k11_pub_y == public_y,
        "existing browser device binding differs or was revoked"
    );
    let mut calldata = agentkeys_core::audit::calldata::selector("signers(bytes32)").to_vec();
    calldata.extend_from_slice(&credential_hash);
    let raw = chain
        .rpc(
            "eth_call",
            json!([{"to":intent.account,"data":hex_value(&calldata)},"latest"]),
        )
        .await?;
    let bytes = hex::decode(
        raw.as_str()
            .context("invalid account signer response")?
            .trim_start_matches("0x"),
    )?;
    let signer = agentkeys_backend_client::protocol::chain_abi::decode_account_signer(&bytes)
        .map_err(anyhow::Error::msg)?;
    let generation = chain
        .call(
            &fixed::<20>(&intent.account)?,
            &agentkeys_core::audit::calldata::selector("signerGeneration()"),
        )
        .await?;
    let generation = agentkeys_backend_client::protocol::chain_abi::decode_u64(&generation)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        signer.active
            && signer.generation == Some(generation)
            && signer.pub_x == public_x
            && signer.pub_y == public_y
            && signer.rp_id_hash == rp_hash,
        "browser account signer differs or is no longer active"
    );
    Ok(true)
}

fn validate_build(
    development: &crate::development_signing::DevelopmentSigning,
    build: &BuildAcceptUserOpResponse,
    account: &[u8; 20],
    nonce: &[u8; 32],
    expected: &[u8],
) -> Result<()> {
    development.verify_build(
        &build.user_op,
        &build.user_op_hash,
        &build.entry_point,
        build.chain_id,
    )?;
    let operation = wire_to_packed(&build.user_op).map_err(anyhow::Error::msg)?;
    ensure!(
        operation.sender == *account
            && operation.nonce == *nonce
            && operation.call_data == expected
            && operation.init_code.is_empty()
            && operation.signature.is_empty()
            && operation.paymaster_and_data.is_empty(),
        "broker operation differs from the exact local browser registration"
    );
    Ok(())
}

fn incomplete(intent: &HostedSignerIntent, hash: &str) -> anyhow::Error {
    IncompleteApproval(
        json!({"development_only":true,"complete":false,"pending":true,
        "user_op_hash":hash,"account":intent.account,"device_key_hash":intent.device_key_hash}),
    )
    .into()
}

async fn confirm(
    chain: &LocalChain,
    intent: &HostedSignerIntent,
    build: &BuildAcceptUserOpResponse,
    response: &Value,
) -> Result<Value> {
    ensure!(
        response["user_op_hash"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(&build.user_op_hash)),
        "browser approval receipt names a different operation"
    );
    if response["pending"] == true || response["tx_hash"].as_str().is_none_or(str::is_empty) {
        return Err(incomplete(intent, &build.user_op_hash));
    }
    let transaction = response["tx_hash"]
        .as_str()
        .context("missing transaction identity")?;
    fixed::<32>(transaction)?;
    let receipt = chain
        .rpc("eth_getTransactionReceipt", json!([transaction]))
        .await?;
    ensure!(
        receipt["transactionHash"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(transaction)),
        "browser approval transaction is not confirmed by this chain"
    );
    let operation = wire_to_packed(&build.user_op).map_err(anyhow::Error::msg)?;
    ensure!(
        agentkeys_core::user_operation_receipt::execution_succeeded(
            &receipt,
            &chain.contract("EntryPoint")?,
            &operation,
            &build.user_op_hash
        )
        .map_err(anyhow::Error::msg)?,
        "browser approval operation reverted; no retry was submitted"
    );
    ensure!(
        active(chain, intent).await?,
        "browser registration is not active on chain"
    );
    Ok(
        json!({"development_only":true,"complete":true,"already_approved":false,
        "account":intent.account,"device_key_hash":intent.device_key_hash,"origin":intent.origin,
        "user_op_hash":build.user_op_hash,"transaction_hash":transaction}),
    )
}

pub async fn approve(context: &CommandContext, options: &BrowserOptions) -> Result<Value> {
    let chain = LocalChain::connect(context).await?;
    chain
        .development
        .require_local_service(&options.broker_url)?;
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_BROWSER_APPROVAL_BYTES as u64 + 1)
        .read_to_end(&mut encoded)?;
    ensure!(
        encoded.len() <= MAX_BROWSER_APPROVAL_BYTES,
        "browser approval exceeds the input size limit"
    );
    let request: HostedSignerApproval =
        serde_json::from_slice(&encoded).context("invalid public browser approval")?;
    let intent = &request.enrollment.intent;
    let key = DeviceKey::load(&options.device_key_file)?;
    let operator = fixed::<32>(&options.operator_omni)?;
    let account = chain.owner_binding(&operator, &key).await?;
    check_binding(intent, options, &account, chain.profile.chain_id)?;
    let challenge =
        browser_enrollment::verify_public_proofs(intent, &request.proof, &request.device_proof)?;
    ensure!(
        fixed::<32>(&request.enrollment.challenge)? == challenge,
        "browser challenge does not match its signed intent"
    );
    let session = local_data::load_session(
        &options.session_file,
        &options.broker_url,
        &options.operator_omni,
        &key,
        now()?,
    )?;
    ensure!(
        fixed::<20>(&session.account)? == account,
        "owner session account differs from the chain"
    );
    let directory = Path::new(&options.operations_dir);
    let _lock = lock_operations(directory)?;
    let records: Vec<_> = std::fs::read_dir(directory)?
        .take(2)
        .collect::<std::io::Result<_>>()?;
    ensure!(
        records.len() <= 1,
        "ambiguous browser approval records; no transaction was signed"
    );
    let broker = BrokerClient::with_client(chain.client.clone(), &options.broker_url);
    let device_hash = key.device_key_hash()?;
    let journal = AgentOperationJournal {
        directory,
        operator_omni: &options.operator_omni,
        broker_url: &options.broker_url,
        request_device_key_hash: &device_hash,
    };
    if let Some(record) = records.first() {
        let record = AgentOperationRecord::load(
            record.path().to_str().context("invalid operation path")?,
            &journal,
            &chain.development,
        )?;
        ensure!(
            record.action == AgentOperationKind::BrowserEnrollment
                && fixed::<32>(&record.device_key_hash)? == fixed::<32>(&intent.device_key_hash)?
                && fixed::<20>(&record.build.user_op.sender)? == account,
            "saved operation belongs to another browser approval"
        );
        let response = agent_admin::agent_receipt(
            &chain.development,
            &options.broker_url,
            &session.session.session_jwt,
            &record,
        )
        .await
        .map_err(|_| incomplete(intent, &record.build.user_op_hash))?;
        return confirm(&chain, intent, &record.build, &response).await;
    }
    if active(&chain, intent).await? {
        return Ok(
            json!({"development_only":true,"complete":true,"already_approved":true,
            "account":intent.account,"device_key_hash":intent.device_key_hash,"origin":intent.origin}),
        );
    }
    let registry = chain.contract("SidecarRegistry")?;
    let mut nonce_call =
        agentkeys_core::audit::calldata::selector("operatorNonce(bytes32)").to_vec();
    nonce_call.extend_from_slice(&operator);
    let operator_nonce = chain.call(&registry, &nonce_call).await?;
    let signer = browser_enrollment::validate_intent(
        intent,
        &operator,
        &account,
        chain.profile.chain_id,
        &operator_nonce,
        now()?,
        std::slice::from_ref(&options.website_origin),
    )?;
    let prepared = broker
        .hosted_signer_prepare(&session.session.session_jwt, &request)
        .await
        .map_err(|_| anyhow!("local broker rejected the browser approval proofs"))?;
    ensure!(
        serde_json::to_value(&prepared.intent)? == serde_json::to_value(intent)?
            && fixed::<32>(&prepared.challenge)? == challenge,
        "broker changed the browser approval intent"
    );
    let new_device_hash = fixed::<32>(&intent.device_key_hash)?;
    let recovery = additional_master_challenge(
        &operator,
        &new_device_hash,
        HOSTED_SIGNER_CAP_MINT_ROLE,
        chain.profile.chain_id,
        &operator_nonce,
    );
    ensure!(
        fixed::<32>(&prepared.recovery_challenge)? == recovery
            && fixed::<32>(&request.enrollment.recovery_challenge)? == recovery,
        "browser recovery challenge differs from the requested registration"
    );
    let assertion = k11_webauthn::software_browser_assertion(
        &chain.development,
        &options.key_file,
        &hex_value(&recovery),
        "localhost",
        &master_cred_id_hash(&operator),
    )?;
    let parts = agentkeys_core::webauthn_assertion::decode_assertion_parts(&assertion)
        .map_err(anyhow::Error::msg)?;
    let owner_device_hash = fixed::<32>(&device_hash)?;
    let master = AdditionalMaster {
        device_key_hash: &new_device_hash,
        operator_omni: &operator,
        credential_hash: &signer.credential_hash,
        rp_id_hash: &signer.rp_id_hash,
        pub_x: &signer.pub_x,
        pub_y: &signer.pub_y,
        roles: HOSTED_SIGNER_CAP_MINT_ROLE,
        attesting_device_key_hash: &owner_device_hash,
        authenticator_data: &parts.authenticator_data,
        client_data_json: &parts.client_data_json,
        challenge_location: parts.challenge_location,
        r: &parts.r,
        s: &parts.s,
    };
    let expected = hosted_signer_batch_calldata(&account, &registry, &master);
    let build = broker
        .hosted_signer_build(
            &session.session.session_jwt,
            &HostedSignerBuildRequest {
                intent: intent.clone(),
                proof: request.proof,
                device_proof: request.device_proof,
                recovery_assertion: HostedRecoveryAssertion {
                    attesting_device_key_hash: device_hash.clone(),
                    assertion,
                },
            },
        )
        .await
        .map_err(|_| anyhow!("local broker refused the owner-approved browser build"))?;
    let nonce = chain
        .call(
            &chain.contract("EntryPoint")?,
            &entrypoint_nonce_calldata(&account),
        )
        .await?;
    validate_build(&chain.development, &build, &account, &nonce, &expected)?;
    let mut record = serde_json::to_value(&build)?;
    record["device_key_hash"] = json!(intent.device_key_hash);
    journal.save(AgentOperationKind::BrowserEnrollment, &record)?;
    let assertion = k11_webauthn::software_browser_assertion(
        &chain.development,
        &options.key_file,
        &build.user_op_hash,
        "localhost",
        &master_cred_id_hash(&operator),
    )?;
    let response = broker
        .hosted_signer_submit(
            &session.session.session_jwt,
            &SubmitAcceptUserOpRequest {
                user_op: build.user_op.clone(),
                assertion,
            },
        )
        .await
        .map_err(|_| incomplete(intent, &build.user_op_hash))?;
    confirm(&chain, intent, &build, &serde_json::to_value(response)?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_hash_cannot_hide_a_different_registration() {
        use agentkeys_core::chain_profile::{ChainProfile, ContractInfo};
        let mut profile = ChainProfile::load_builtin("anvil").unwrap();
        let entry_point = [2; 20];
        profile.contracts.push(ContractInfo {
            name: "EntryPoint".into(),
            address: hex_value(&entry_point),
            purpose: String::new(),
            deployed_at: String::new(),
        });
        let development =
            crate::development_signing::DevelopmentSigning::new(&profile, true, None).unwrap();
        let operation = PackedUserOp {
            sender: [1; 20],
            nonce: [0; 32],
            init_code: vec![],
            call_data: vec![1, 2, 3],
            account_gas_limits: [0; 32],
            pre_verification_gas: [0; 32],
            gas_fees: [0; 32],
            paymaster_and_data: vec![],
            signature: vec![],
        };
        let build = |operation: &PackedUserOp| BuildAcceptUserOpResponse {
            user_op: wire_user_op_from_packed(operation),
            user_op_hash: hex_value(&operation.user_op_hash(&entry_point, profile.chain_id)),
            entry_point: hex_value(&entry_point),
            chain_id: profile.chain_id,
        };
        assert!(validate_build(
            &development,
            &build(&operation),
            &operation.sender,
            &operation.nonce,
            &operation.call_data
        )
        .is_ok());
        for field in ["sender", "nonce", "call", "init", "signature", "paymaster"] {
            let mut changed = operation.clone();
            match field {
                "sender" => changed.sender[0] ^= 1,
                "nonce" => changed.nonce[31] = 1,
                "call" => changed.call_data.push(4),
                "init" => changed.init_code = vec![1; 20],
                "signature" => changed.signature = vec![1; 64],
                _ => changed.paymaster_and_data = vec![1; 52],
            }
            assert!(
                validate_build(
                    &development,
                    &build(&changed),
                    &operation.sender,
                    &operation.nonce,
                    &operation.call_data
                )
                .is_err(),
                "{field}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_operation_directory_serializes_approvals_and_rejects_links() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = lock_operations(directory.path()).unwrap();
        assert!(lock_operations(directory.path()).is_err());
        drop(held);
        assert!(lock_operations(directory.path()).is_ok());
        let linked = directory.path().join("linked");
        symlink(directory.path(), &linked).unwrap();
        assert!(lock_operations(&linked).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(lock_operations(directory.path()).is_err());
    }
}
