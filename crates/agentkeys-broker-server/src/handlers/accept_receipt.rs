use crate::{
    handlers::accept::{self, aerr, AcceptConfig},
    state::SharedState,
};
use agentkeys_protocol::console_apps::AcceptReceiptRequest;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

const RECEIPT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const RECEIPT_CACHE_CAPACITY: usize = 512;
const RECEIPT_LOOKBACK_BLOCKS: u64 = 8192;
const RECEIPT_QUERY_BLOCKS: u64 = 1024;
const MAX_CONTEXT_DOCS: usize = 16;
const MAX_CONTEXT_DOC_BYTES: usize = 64 * 1024;
#[derive(Default)]
pub struct ReceiptCache {
    completed: tokio::sync::Mutex<HashMap<String, (Instant, Value)>>,
    in_flight: tokio::sync::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
}
type ReceiptError = (StatusCode, Json<Value>);

pub async fn receipt(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<AcceptReceiptRequest>,
) -> Result<Json<Value>, ReceiptError> {
    let token = accept::bearer(&headers)?;
    let claims = crate::jwt::verify::verify_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &token,
    )
    .map_err(|_| aerr(StatusCode::UNAUTHORIZED, "master session invalid"))?;
    if claims.agentkeys.parent_omni.is_some()
        || claims.agentkeys.device_pubkey.is_some()
        || !matches!(claims.agentkeys.identity_type.as_str(), "evm" | "passkey")
    {
        return Err(aerr(StatusCode::FORBIDDEN, "master session required"));
    }
    let operator = accept::norm_omni(&claims.agentkeys.omni_account);
    state
        .config
        .login_access
        .require_omni(&state, &operator)
        .await
        .map_err(|error| aerr(StatusCode::FORBIDDEN, error.to_string()))?;
    let operator_bytes: [u8; 32] = hex::decode(&operator)
        .map_err(|error| aerr(StatusCode::BAD_REQUEST, error.to_string()))?
        .try_into()
        .map_err(|_| aerr(StatusCode::BAD_REQUEST, "invalid operator"))?;
    let (config, _) = accept::load_accept_config()
        .map_err(|error| aerr(StatusCode::SERVICE_UNAVAILABLE, error))?;
    let packed = accept::wire_to_packed(&request.user_op)
        .map_err(|error| aerr(StatusCode::BAD_REQUEST, error))?;
    let account = accept::call_operator_master_wallet(
        &state.http,
        &config.rpc_url,
        &config.registry,
        &operator,
    )
    .await
    .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
    if account == [0; 20] || packed.sender != account {
        return Err(aerr(
            StatusCode::FORBIDDEN,
            "operation sender is not this operator's master account",
        ));
    }
    validate_context_documents(
        &packed.call_data,
        &operator_bytes,
        crate::handlers::anchor::audit_contract(&config),
        &request.context_docs,
    )
    .map_err(|error| aerr(StatusCode::BAD_REQUEST, error))?;
    let hash = format!(
        "0x{}",
        hex::encode(packed.user_op_hash(&config.entry_point, config.chain_id))
    );
    let bundler = std::env::var("AGENTKEYS_BUNDLER_URL").map_err(|_| {
        aerr(
            StatusCode::SERVICE_UNAVAILABLE,
            "AGENTKEYS_BUNDLER_URL is required",
        )
    })?;
    let result = accept::bundler_rpc(
        &state.http,
        &bundler,
        "eth_getUserOperationReceipt",
        json!([hash]),
    )
    .await
    .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
    let result = if result.is_null() {
        match find_recent_transaction(
            &state.http,
            &config.rpc_url,
            &config.entry_point,
            &packed,
            &hash,
        )
        .await?
        {
            Some(transaction) => json!({"receipt": {"transactionHash": transaction}}),
            None => {
                return Ok(Json(
                    json!({"ok":true,"pending":true,"tx_hash":"","block_number":"","user_op_hash":hash}),
                ))
            }
        }
    } else {
        result
    };
    verified_finalization(
        &state,
        &config,
        operator_bytes,
        &packed,
        &hash,
        &result,
        Some((&headers, &request.context_docs)),
    )
    .await
    .map(Json)
}

fn operation_topics(
    operation: &crate::sponsor::PackedUserOp,
    hash: &str,
) -> Result<[String; 4], String> {
    let paymaster = match operation.paymaster_and_data.len() {
        0 => [0; 20],
        52.. => operation.paymaster_and_data[..20]
            .try_into()
            .map_err(|_| "invalid paymaster")?,
        _ => return Err("invalid operation paymaster data".into()),
    };
    Ok([
        format!(
            "0x{}",
            hex::encode(agentkeys_core::device_crypto::keccak256(
                b"UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"
            ))
        ),
        hash.to_owned(),
        format!("0x{}{}", "00".repeat(12), hex::encode(operation.sender)),
        format!("0x{}{}", "00".repeat(12), hex::encode(paymaster)),
    ])
}

fn matches_operation(log: &Value, entry_point: &[u8; 20], topics: &[String; 4]) -> bool {
    log.get("address")
        .and_then(Value::as_str)
        .is_some_and(|address| {
            address.eq_ignore_ascii_case(&format!("0x{}", hex::encode(entry_point)))
        })
        && log
            .get("topics")
            .and_then(Value::as_array)
            .is_some_and(|actual| {
                actual.len() == topics.len()
                    && actual.iter().zip(topics).all(|(actual, expected)| {
                        actual
                            .as_str()
                            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                    })
            })
}

fn hex_quantity(value: &Value) -> Result<u64, String> {
    value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .ok_or_else(|| "invalid chain quantity".into())
}

async fn find_recent_transaction(
    http: &reqwest::Client,
    rpc_url: &str,
    entry_point: &[u8; 20],
    operation: &crate::sponsor::PackedUserOp,
    hash: &str,
) -> Result<Option<String>, ReceiptError> {
    let latest = accept::bundler_rpc(http, rpc_url, "eth_blockNumber", json!([]))
        .await
        .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
    let mut end = hex_quantity(&latest).map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
    let floor = end.saturating_sub(RECEIPT_LOOKBACK_BLOCKS - 1);
    let topics =
        operation_topics(operation, hash).map_err(|error| aerr(StatusCode::BAD_REQUEST, error))?;
    loop {
        let start = end.saturating_sub(RECEIPT_QUERY_BLOCKS - 1).max(floor);
        let logs = accept::bundler_rpc(
            http,
            rpc_url,
            "eth_getLogs",
            json!([{
                "address":format!("0x{}", hex::encode(entry_point)), "topics":topics,
                "fromBlock":format!("0x{start:x}"), "toBlock":format!("0x{end:x}")
            }]),
        )
        .await
        .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
        let logs = logs.as_array().ok_or_else(|| {
            aerr(
                StatusCode::BAD_GATEWAY,
                "chain logs response is not an array",
            )
        })?;
        if logs.len() > 1 {
            return Err(aerr(
                StatusCode::BAD_GATEWAY,
                "multiple events for one operation",
            ));
        }
        if let Some(log) = logs.first() {
            let block = hex_quantity(&log["blockNumber"])
                .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
            if !matches_operation(log, entry_point, &topics)
                || log
                    .get("removed")
                    .is_some_and(|removed| removed != &json!(false))
                || !(start..=end).contains(&block)
            {
                return Err(aerr(
                    StatusCode::BAD_GATEWAY,
                    "chain log does not match requested operation range",
                ));
            }
            return log
                .get("transactionHash")
                .and_then(Value::as_str)
                .map(|hash| Some(hash.to_owned()))
                .ok_or_else(|| {
                    aerr(
                        StatusCode::BAD_GATEWAY,
                        "operation event has no transaction",
                    )
                });
        }
        if start == floor {
            return Ok(None);
        }
        end = start - 1;
    }
}

fn validate_context_documents(
    call_data: &[u8],
    operator: &[u8; 32],
    audit: Option<[u8; 20]>,
    documents: &[String],
) -> Result<(), String> {
    if documents.is_empty() {
        return Ok(());
    }
    if documents.len() > MAX_CONTEXT_DOCS
        || documents
            .iter()
            .any(|document| document.len() > MAX_CONTEXT_DOC_BYTES)
    {
        return Err("context recovery request exceeds its size limit".into());
    }
    let audit = audit.ok_or("no configured context seal contract")?;
    let calls = agentkeys_core::erc4337::decode_execute_batch(call_data)?;
    for document in documents {
        let context: agentkeys_protocol::DelegateContextDoc = serde_json::from_str(document)
            .map_err(|error| format!("invalid context document: {error}"))?;
        if context.schema != agentkeys_protocol::CONTEXT_DOC_SCHEMA || context.version == 0 {
            return Err("unsupported context document schema or version".into());
        }
        let seal = agentkeys_core::erc4337::append_root_calldata(
            operator,
            &agentkeys_core::device_crypto::keccak256(document.as_bytes()),
            context.version,
        );
        if !calls
            .iter()
            .any(|call| call.dest == audit && call.value == 0 && call.calldata == seal)
        {
            return Err("context document is not sealed by this exact signed operation".into());
        }
    }
    Ok(())
}

pub(crate) async fn verified_finalization(
    state: &SharedState,
    config: &AcceptConfig,
    operator: [u8; 32],
    packed: &crate::sponsor::PackedUserOp,
    hash: &str,
    bundler_receipt: &Value,
    recovery: Option<(&HeaderMap, &[String])>,
) -> Result<Value, ReceiptError> {
    let expected = format!(
        "0x{}",
        hex::encode(packed.user_op_hash(&config.entry_point, config.chain_id))
    );
    if !expected.eq_ignore_ascii_case(hash) {
        return Err(aerr(
            StatusCode::BAD_GATEWAY,
            "bundler returned a different user operation hash",
        ));
    }
    let transaction = bundler_receipt
        .pointer("/receipt/transactionHash")
        .and_then(Value::as_str)
        .ok_or_else(|| aerr(StatusCode::BAD_GATEWAY, "missing transaction receipt"))?;
    if hex::decode(transaction.strip_prefix("0x").unwrap_or(""))
        .map(|bytes| bytes.len())
        .ok()
        != Some(32)
    {
        return Err(aerr(StatusCode::BAD_GATEWAY, "invalid transaction hash"));
    }
    let chain_receipt = accept::bundler_rpc(
        &state.http,
        &config.rpc_url,
        "eth_getTransactionReceipt",
        json!([transaction]),
    )
    .await
    .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
    if !chain_receipt
        .get("transactionHash")
        .and_then(Value::as_str)
        .is_some_and(|actual| actual.eq_ignore_ascii_case(transaction))
    {
        return Err(aerr(
            StatusCode::BAD_GATEWAY,
            "chain receipt transaction differs from requested transaction",
        ));
    }
    if chain_receipt.get("status").and_then(Value::as_str) == Some("0x0") {
        return Err(aerr(
            StatusCode::BAD_GATEWAY,
            accept::handle_ops_revert_message(
                bundler_receipt.get("reason").and_then(Value::as_str),
                transaction,
            ),
        ));
    }
    verify_operation_event(&chain_receipt, &config.entry_point, packed, &expected)
        .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
    if let Some((_, documents)) = recovery {
        validate_context_documents(
            &packed.call_data,
            &operator,
            crate::handlers::anchor::audit_contract(config),
            documents,
        )
        .map_err(|error| aerr(StatusCode::BAD_REQUEST, error))?;
    }
    let cache_key = format!("{}:{expected}", hex::encode(operator));
    let operation_lock = {
        let mut in_flight = state.accept_receipts.in_flight.lock().await;
        in_flight.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = in_flight.get(&cache_key).and_then(Weak::upgrade) {
            lock
        } else {
            if in_flight.len() >= RECEIPT_CACHE_CAPACITY {
                return Err(aerr(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "too many receipt finalizations in progress",
                ));
            }
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            in_flight.insert(cache_key.clone(), Arc::downgrade(&lock));
            lock
        }
    };
    let _operation_guard = operation_lock.lock().await;
    {
        let mut completed = state.accept_receipts.completed.lock().await;
        completed.retain(|_, (at, _)| at.elapsed() < RECEIPT_CACHE_TTL);
        if let Some((_, response)) = completed.get(&cache_key) {
            return Ok(response.clone());
        }
    }
    if let Some((headers, documents)) = recovery {
        for document in documents {
            let _ = crate::handlers::anchor::rehydrate(
                State(state.clone()),
                headers.clone(),
                Json(agentkeys_protocol::console_apps::RehydrateRequest {
                    operator_omni: format!("0x{}", hex::encode(operator)),
                    context_doc: document.clone(),
                }),
            )
            .await?;
        }
    }
    let audit =
        crate::handlers::audit_emit::emit_for_confirmed_batch(operator, &packed.call_data).await;
    let lifecycle = current_lifecycle_calldata(state, config, operator, &packed.call_data).await?;
    crate::handlers::sandbox::teardown_for_confirmed_batch(state, operator, &lifecycle).await;
    let ceremony =
        crate::handlers::spawn::finalize_for_confirmed_batch(state, operator, &lifecycle).await;
    let mut response = json!({"ok":true,"tx_hash":transaction,"block_number":chain_receipt.get("blockNumber").and_then(Value::as_str).unwrap_or(""),"user_op_hash":expected,"audit_envelope_hashes":audit});
    if let Some(ceremony) = ceremony {
        response["ceremony"] = ceremony;
    }
    if !contains_finalization_error(&response["ceremony"]) {
        let mut completed = state.accept_receipts.completed.lock().await;
        if completed.len() >= RECEIPT_CACHE_CAPACITY {
            if let Some(oldest) = completed
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
            {
                completed.remove(&oldest);
            }
        }
        completed.insert(cache_key, (Instant::now(), response.clone()));
    }
    Ok(response)
}

fn contains_finalization_error(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            (key == "error" && !value.is_null() && value.as_str() != Some(""))
                || contains_finalization_error(value)
        }),
        Value::Array(items) => items.iter().any(contains_finalization_error),
        _ => false,
    }
}

fn verify_operation_event(
    receipt: &Value,
    entry_point: &[u8; 20],
    operation: &crate::sponsor::PackedUserOp,
    hash: &str,
) -> Result<(), String> {
    if receipt.get("status").and_then(Value::as_str) != Some("0x1") {
        return Err("operation transaction failed or remains unconfirmed".into());
    }
    let topics = operation_topics(operation, hash)?;
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or("transaction receipt has no event logs")?;
    let matching: Vec<_> = logs
        .iter()
        .filter(|log| matches_operation(log, entry_point, &topics))
        .collect();
    if matching.len() != 1 {
        return Err(
            "receipt must have exactly one event for this operation, sender and paymaster".into(),
        );
    }
    let log = matching[0];
    if log
        .get("removed")
        .is_some_and(|removed| removed != &json!(false))
    {
        return Err("operation event was removed".into());
    }
    for field in ["transactionHash", "blockHash", "blockNumber"] {
        if !receipt
            .get(field)
            .and_then(Value::as_str)
            .zip(log.get(field).and_then(Value::as_str))
            .is_some_and(|(receipt, log)| receipt.eq_ignore_ascii_case(log))
        {
            return Err(format!("operation event {field} differs from its receipt"));
        }
    }
    hex_quantity(&receipt["blockNumber"])?;
    let data = hex::decode(
        log.get("data")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim_start_matches("0x"),
    )
    .map_err(|_| "invalid operation event")?;
    if data.len() != 128 || data[..32] != operation.nonce {
        return Err("operation event nonce differs from requested operation".into());
    }
    if data[32..63].iter().any(|byte| *byte != 0) || data[63] != 1 {
        return Err("user operation reverted inside handleOps".into());
    }
    Ok(())
}

async fn current_lifecycle_calldata(
    state: &SharedState,
    config: &AcceptConfig,
    operator: [u8; 32],
    data: &[u8],
) -> Result<Vec<u8>, ReceiptError> {
    let calls = agentkeys_core::erc4337::decode_execute_batch(data)
        .map_err(|error| aerr(StatusCode::BAD_REQUEST, error))?;
    let mut current = Vec::new();
    for call in calls
        .into_iter()
        .filter(|call| call.dest == config.registry)
    {
        let Ok(decoded) = agentkeys_core::audit::calldata::decode_calldata(&call.calldata) else {
            continue;
        };
        if !matches!(
            decoded.function.as_str(),
            "registerDelegate" | "registerAgentDevice" | "revokeAgentDevice"
        ) {
            continue;
        }
        let hash = decoded
            .args
            .first()
            .and_then(|arg| arg.value.as_str())
            .ok_or_else(|| aerr(StatusCode::BAD_REQUEST, "lifecycle device hash missing"))?;
        let probe_data = format!(
            "0x{}{}",
            hex::encode(&agentkeys_core::device_crypto::keccak256(b"getDevice(bytes32)")[..4]),
            accept::norm_omni(hash)
        );
        let raw = accept::eth_call(&state.http, &config.rpc_url, &config.registry, &probe_data)
            .await
            .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
        let probe = crate::handlers::revoke::parse_device_probe(&raw)
            .map_err(|error| aerr(StatusCode::BAD_GATEWAY, error))?;
        if probe.operator_omni != operator || !probe.registered {
            continue;
        }
        let matching = if decoded.function == "revokeAgentDevice" {
            probe.revoked
        } else {
            !probe.revoked
                && decoded
                    .args
                    .get(2)
                    .and_then(|arg| arg.value.as_str())
                    .is_some_and(|actor| accept::norm_omni(actor) == hex::encode(probe.actor_omni))
        };
        if matching {
            current.push(call);
        }
    }
    Ok(agentkeys_core::erc4337::execute_batch_calldata(
        &current.iter().map(|call| call.dest).collect::<Vec<_>>(),
        &current.iter().map(|call| call.value).collect::<Vec<_>>(),
        &current
            .iter()
            .map(|call| call.calldata.clone())
            .collect::<Vec<_>>(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> crate::sponsor::PackedUserOp {
        crate::sponsor::PackedUserOp {
            sender: [1; 20],
            nonce: [2; 32],
            init_code: vec![],
            call_data: vec![],
            account_gas_limits: [0; 32],
            pre_verification_gas: [0; 32],
            gas_fees: [0; 32],
            paymaster_and_data: [vec![3; 20], vec![0; 32]].concat(),
            signature: vec![],
        }
    }

    fn receipt_fixture(operation: &crate::sponsor::PackedUserOp) -> Value {
        let mut data = vec![0u8; 128];
        data[..32].copy_from_slice(&operation.nonce);
        data[63] = 1;
        json!({"status":"0x1","transactionHash":format!("0x{}","aa".repeat(32)),"blockHash":format!("0x{}","bb".repeat(32)),"blockNumber":"0x10","logs":[{"address":format!("0x{}","04".repeat(20)),"transactionHash":format!("0x{}","aa".repeat(32)),"blockHash":format!("0x{}","bb".repeat(32)),"blockNumber":"0x10","removed":false,"topics":[format!("0x{}",hex::encode(agentkeys_core::device_crypto::keccak256(b"UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"))),format!("0x{}","05".repeat(32)),format!("0x{}{}","00".repeat(12),hex::encode(operation.sender)),format!("0x{}{}","00".repeat(12),"03".repeat(20))],"data":format!("0x{}",hex::encode(data))}]})
    }

    #[test]
    fn receipt_requires_exact_paymaster_and_nonremoved_log() {
        let operation = operation();
        let hash = format!("0x{}", "05".repeat(32));
        let mut receipt = receipt_fixture(&operation);
        assert!(verify_operation_event(&receipt, &[4; 20], &operation, &hash).is_ok());
        receipt["logs"][0]["topics"][3] = json!(format!("0x{}", "00".repeat(32)));
        assert!(verify_operation_event(&receipt, &[4; 20], &operation, &hash).is_err());
        let mut receipt = receipt_fixture(&operation);
        receipt["logs"][0]["removed"] = json!(true);
        assert!(verify_operation_event(&receipt, &[4; 20], &operation, &hash).is_err());
    }

    #[test]
    fn receipt_rejects_wrong_entrypoint_sender_hash_nonce_or_receipt_linkage() {
        let operation = operation();
        let hash = format!("0x{}", "05".repeat(32));
        let receipt = receipt_fixture(&operation);
        assert!(verify_operation_event(&receipt, &[9; 20], &operation, &hash).is_err());
        assert!(verify_operation_event(&receipt, &[4; 20], &operation, "0xwrong").is_err());
        let mut wrong_sender = operation.clone();
        wrong_sender.sender = [9; 20];
        assert!(verify_operation_event(&receipt, &[4; 20], &wrong_sender, &hash).is_err());
        let mut wrong_nonce = operation.clone();
        wrong_nonce.nonce = [9; 32];
        assert!(verify_operation_event(&receipt, &[4; 20], &wrong_nonce, &hash).is_err());
        for field in ["transactionHash", "blockHash", "blockNumber"] {
            let mut changed = receipt.clone();
            changed["logs"][0][field] = json!("0x99");
            assert!(
                verify_operation_event(&changed, &[4; 20], &operation, &hash).is_err(),
                "{field}"
            );
        }
        let mut duplicate = receipt.clone();
        duplicate["logs"]
            .as_array_mut()
            .unwrap()
            .push(receipt["logs"][0].clone());
        assert!(verify_operation_event(&duplicate, &[4; 20], &operation, &hash).is_err());
        let mut failed = receipt.clone();
        failed["status"] = json!("0x0");
        assert!(verify_operation_event(&failed, &[4; 20], &operation, &hash).is_err());
        let mut reverted = receipt;
        let mut data = hex::decode(
            reverted["logs"][0]["data"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        data[63] = 0;
        reverted["logs"][0]["data"] = json!(format!("0x{}", hex::encode(data)));
        assert!(verify_operation_event(&reverted, &[4; 20], &operation, &hash).is_err());
    }

    #[test]
    fn recovery_document_is_bound_to_exact_operator_contract_and_signed_bytes() {
        let document = json!({"schema":agentkeys_protocol::CONTEXT_DOC_SCHEMA,"version":1,"label":"chef","device_key_hash":"0xdevice","actor_omni":"0xactor","k10_address":"0xk10","preset_id":"chef","chat_channel_id":"chat","memory_ns":"app-chef","bound_channels":[],"availability":"always","memory_namespaces":"app-chef","tz_offset_minutes":0,"updated_at":1}).to_string();
        let seal = agentkeys_core::erc4337::append_root_calldata(
            &[1; 32],
            &agentkeys_core::device_crypto::keccak256(document.as_bytes()),
            1,
        );
        let batch = agentkeys_core::erc4337::execute_batch_calldata(&[[2; 20]], &[0], &[seal]);
        assert!(validate_context_documents(
            &batch,
            &[1; 32],
            Some([2; 20]),
            std::slice::from_ref(&document)
        )
        .is_ok());
        assert!(validate_context_documents(
            &batch,
            &[9; 32],
            Some([2; 20]),
            std::slice::from_ref(&document)
        )
        .is_err());
        assert!(validate_context_documents(
            &batch,
            &[1; 32],
            Some([9; 20]),
            std::slice::from_ref(&document)
        )
        .is_err());
        assert!(validate_context_documents(
            &batch,
            &[1; 32],
            None,
            std::slice::from_ref(&document)
        )
        .is_err());
        let changed = document.replace("app-chef", "unapproved-context");
        assert!(validate_context_documents(&batch, &[1; 32], Some([2; 20]), &[changed]).is_err());
        assert!(validate_context_documents(
            &batch,
            &[1; 32],
            Some([2; 20]),
            &[" ".repeat(MAX_CONTEXT_DOC_BYTES + 1)]
        )
        .is_err());
        assert!(validate_context_documents(
            &batch,
            &[1; 32],
            Some([2; 20]),
            &vec![document; MAX_CONTEXT_DOCS + 1]
        )
        .is_err());
    }

    #[test]
    fn transient_ceremony_errors_are_not_completed_cache_entries() {
        assert!(contains_finalization_error(
            &json!({"spawned":[{"context_recovered":false,"error":"missing context"}]})
        ));
        assert!(contains_finalization_error(
            &json!({"spawned":[{"gate":{"error":"try again"}}]})
        ));
        assert!(!contains_finalization_error(
            &json!({"spawned":[{"context_recovered":true,"gate":{"error":null},"sandbox":{"error":""}}]})
        ));
    }

    async fn mock_rpc(
        response: impl Fn(Value) -> Value + Send + Sync + 'static,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let response = Arc::new(response);
        let router = axum::Router::new().route(
            "/",
            axum::routing::post(move |Json(request): Json<Value>| {
                let response = response.clone();
                async move { Json(response(request)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{address}"), server)
    }

    #[tokio::test]
    async fn restart_lookup_is_bounded_and_filters_exact_entrypoint_operation() {
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = requests.clone();
        let (rpc, server) = mock_rpc(move |request| {
            captured.lock().unwrap().push(request.clone());
            json!({"jsonrpc":"2.0","id":request["id"],"result":if request["method"] == "eth_blockNumber" {json!("0x3000")} else {json!([])}})
        }).await;
        let operation = operation();
        let hash = format!("0x{}", "05".repeat(32));
        assert_eq!(
            find_recent_transaction(&reqwest::Client::new(), &rpc, &[4; 20], &operation, &hash)
                .await
                .unwrap(),
            None
        );
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            1 + (RECEIPT_LOOKBACK_BLOCKS / RECEIPT_QUERY_BLOCKS) as usize
        );
        let mut next_end = 0x3000;
        for request in &requests[1..] {
            assert_eq!(request["method"], "eth_getLogs");
            assert_eq!(
                request["params"][0]["address"],
                format!("0x{}", "04".repeat(20))
            );
            assert_eq!(
                request["params"][0]["topics"],
                json!(operation_topics(&operation, &hash).unwrap())
            );
            let start = hex_quantity(&request["params"][0]["fromBlock"]).unwrap();
            let end = hex_quantity(&request["params"][0]["toBlock"]).unwrap();
            assert_eq!(end, next_end);
            assert_eq!(end - start + 1, RECEIPT_QUERY_BLOCKS);
            next_end = start - 1;
        }
        assert_eq!(next_end, 0x3000 - RECEIPT_LOOKBACK_BLOCKS);
        server.abort();
    }

    #[tokio::test]
    async fn restart_lookup_propagates_rpc_errors_and_rejects_unrelated_logs() {
        let (rpc, server) = mock_rpc(|request| json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":"RPC unavailable"}})).await;
        let operation = operation();
        let hash = format!("0x{}", "05".repeat(32));
        assert!(find_recent_transaction(
            &reqwest::Client::new(),
            &rpc,
            &[4; 20],
            &operation,
            &hash
        )
        .await
        .is_err());
        server.abort();
        let mut log = receipt_fixture(&operation)["logs"][0].clone();
        log["blockNumber"] = json!("0x3000");
        log["address"] = json!(format!("0x{}", "09".repeat(20)));
        let (rpc, server) = mock_rpc(move |request| json!({"jsonrpc":"2.0","id":request["id"],"result":if request["method"] == "eth_blockNumber" {json!("0x3000")} else {json!([log])}})).await;
        assert!(find_recent_transaction(
            &reqwest::Client::new(),
            &rpc,
            &[4; 20],
            &operation,
            &hash
        )
        .await
        .is_err());
        server.abort();
    }
}
