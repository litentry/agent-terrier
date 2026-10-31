use serde_json::{json, Value};

pub fn operation_topics(
    operation: &crate::erc4337::PackedUserOp,
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
            hex::encode(crate::device_crypto::keccak256(
                b"UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"
            ))
        ),
        hash.to_owned(),
        format!("0x{}{}", "00".repeat(12), hex::encode(operation.sender)),
        format!("0x{}{}", "00".repeat(12), hex::encode(paymaster)),
    ])
}

pub fn matches_operation(log: &Value, entry_point: &[u8; 20], topics: &[String; 4]) -> bool {
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

pub fn hex_quantity(value: &Value) -> Result<u64, String> {
    value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .ok_or_else(|| "invalid chain quantity".into())
}

/// Verify the exact operation event independently of the outer transaction status.
pub fn execution_succeeded(
    receipt: &Value,
    entry_point: &[u8; 20],
    operation: &crate::erc4337::PackedUserOp,
    hash: &str,
) -> Result<bool, String> {
    if receipt.get("status").and_then(Value::as_str) == Some("0x0") {
        return Ok(false);
    }
    if receipt.get("status").and_then(Value::as_str) != Some("0x1") {
        return Err("operation transaction failed or remains unconfirmed".into());
    }
    let topics = operation_topics(operation, hash)?;
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or("transaction receipt has no UserOperationEvent logs")?;
    let matching: Vec<_> = logs
        .iter()
        .filter(|log| matches_operation(log, entry_point, &topics))
        .collect();
    if matching.len() != 1 {
        return Err(
            "receipt must have exactly one UserOperationEvent for this operation, sender and paymaster".into(),
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
    if data[32..63].iter().any(|byte| *byte != 0) || data[63] > 1 {
        return Err("invalid UserOperationEvent success encoding".into());
    }
    Ok(data[63] == 1)
}
