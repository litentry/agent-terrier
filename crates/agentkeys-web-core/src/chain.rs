use agentkeys_device_core::keccak256;
use futures_util::{stream, StreamExt, TryStreamExt};

const FLEET_READ_CONCURRENCY: usize = 8;
use agentkeys_protocol::console_chain::{
    ConsoleChainDevice, ConsoleChainScope, ConsoleFleet, ConsoleFleetEntry,
};

pub fn chain_word(raw: &[u8], index: usize) -> Result<[u8; 32], String> {
    let start = index.checked_mul(32).ok_or("ABI index overflow")?;
    let end = start.checked_add(32).ok_or("ABI index overflow")?;
    raw.get(start..end)
        .ok_or_else(|| format!("short ABI return at word {index}"))?
        .try_into()
        .map_err(|_| "invalid ABI word".into())
}

fn integer(raw: &[u8], index: usize) -> Result<usize, String> {
    let word = chain_word(raw, index)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err("ABI length overflow".into());
    }
    usize::try_from(u64::from_be_bytes(
        word[24..].try_into().map_err(|_| "ABI integer")?,
    ))
    .map_err(|_| "ABI integer overflow".into())
}

fn offset(raw: &[u8], index: usize) -> Result<usize, String> {
    let value = integer(raw, index)?;
    if value % 32 != 0 || value >= raw.len() {
        return Err("invalid ABI offset".into());
    }
    Ok(value / 32)
}

fn boolean(raw: &[u8], index: usize) -> Result<bool, String> {
    match integer(raw, index)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("invalid ABI bool".into()),
    }
}

pub fn chain_selector(signature: &str) -> String {
    hex::encode(&keccak256(signature.as_bytes())[..4])
}

pub fn parse_device_hashes(raw: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    let start = offset(raw, 0)?;
    if start != 1 {
        return Err("invalid device array head".into());
    }
    let count = integer(raw, start)?;
    if count > raw.len().saturating_sub((start + 1) * 32) / 32 {
        return Err("truncated device array".into());
    }
    (0..count)
        .map(|index| chain_word(raw, start + 1 + index))
        .collect()
}

pub fn parse_device_entry(
    raw: &[u8],
    device_key_hash: &[u8; 32],
) -> Result<ConsoleChainDevice, String> {
    let tier = u8::try_from(integer(raw, 6)?).map_err(|_| "invalid device tier")?;
    if !(1..=3).contains(&tier) {
        return Err("unknown device tier".into());
    }
    Ok(ConsoleChainDevice {
        device_key_hash: format!("0x{}", hex::encode(device_key_hash)),
        operator_omni: format!("0x{}", hex::encode(chain_word(raw, 0)?)),
        actor_omni: format!("0x{}", hex::encode(chain_word(raw, 1)?)),
        tier,
        revoked: boolean(raw, 10)?,
    })
}

pub fn parse_scope(raw: &[u8]) -> Result<ConsoleChainScope, String> {
    let start = offset(raw, 0)?;
    if start != 1 {
        return Err("invalid scope tuple head".into());
    }
    let services_offset = offset(raw, start)?;
    if services_offset < 8 {
        return Err("scope array overlaps tuple".into());
    }
    let array = start
        .checked_add(services_offset)
        .ok_or("scope offset overflow")?;
    let count = integer(raw, array)?;
    if count > raw.len().saturating_sub((array + 1) * 32) / 32 {
        return Err("truncated scope array".into());
    }
    let service_ids = (0..count)
        .map(|index| {
            chain_word(raw, array + 1 + index).map(|word| format!("0x{}", hex::encode(word)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let amount = |index| -> Result<String, String> {
        let word = chain_word(raw, index)?;
        if word[..16].iter().any(|byte| *byte != 0) {
            return Err("invalid scope amount".into());
        }
        Ok(u128::from_be_bytes(word[16..].try_into().map_err(|_| "scope amount")?).to_string())
    };
    Ok(ConsoleChainScope {
        service_ids,
        read_only: boolean(raw, start + 1)?,
        exists: boolean(raw, start + 7)?,
        per_tx: amount(start + 2)?,
        period_cap: amount(start + 3)?,
        max_total: amount(start + 4)?,
        period_seconds: u32::try_from(integer(raw, start + 5)?)
            .map_err(|_| "scope period overflow")?,
    })
}

pub fn parse_scope_return(raw: &[u8]) -> Result<(Vec<[u8; 32]>, bool, bool), String> {
    let scope = parse_scope(raw)?;
    let services = scope
        .service_ids
        .iter()
        .map(|value| decode_word(value))
        .collect::<Result<_, _>>()?;
    Ok((services, scope.read_only, scope.exists))
}

pub fn decode_word(value: &str) -> Result<[u8; 32], String> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "expected a 32-byte chain value".into())
}

pub async fn eth_call(
    http: &reqwest::Client,
    rpc: &str,
    to: &str,
    data: &str,
) -> Result<Vec<u8>, String> {
    let result: serde_json::Value = http
        .post(rpc)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{"to": to, "data": data}, "latest"]
        }))
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?
        .json()
        .await
        .map_err(|error| error.to_string())?;
    if result.get("error").is_some() {
        return Err(format!("chain read failed: {}", result["error"]));
    }
    hex::decode(
        result
            .get("result")
            .and_then(|value| value.as_str())
            .ok_or("chain result missing")?
            .strip_prefix("0x")
            .ok_or("chain result must be hex")?,
    )
    .map_err(|error| error.to_string())
}

pub async fn fetch_chain_fleet(
    rpc: &str,
    registry: &str,
    operator: &str,
) -> Result<Vec<ConsoleChainDevice>, String> {
    let http = reqwest::Client::new();
    read_devices(&http, rpc, registry, operator).await
}

async fn read_devices(
    http: &reqwest::Client,
    rpc: &str,
    registry: &str,
    operator: &str,
) -> Result<Vec<ConsoleChainDevice>, String> {
    let omni = decode_word(operator)?;
    let data = format!(
        "0x{}{}",
        chain_selector("getOperatorDevices(bytes32)"),
        hex::encode(omni)
    );
    let hashes = parse_device_hashes(&eth_call(http, rpc, registry, &data).await?)?;
    stream::iter(hashes)
        .map(|hash| async move {
            let data = format!(
                "0x{}{}",
                chain_selector("getDevice(bytes32)"),
                hex::encode(hash)
            );
            let device = parse_device_entry(&eth_call(http, rpc, registry, &data).await?, &hash)?;
            if decode_word(&device.operator_omni)? != omni {
                return Err("chain returned a foreign device".into());
            }
            Ok(device)
        })
        .buffered(FLEET_READ_CONCURRENCY)
        .try_collect()
        .await
}

pub async fn read_fleet(
    http: &reqwest::Client,
    rpc: &str,
    registry: &str,
    scope: &str,
    operator: &str,
) -> Result<ConsoleFleet, String> {
    let omni = decode_word(operator)?;
    let account_data = format!(
        "0x{}{}",
        chain_selector("operatorMasterWallet(bytes32)"),
        hex::encode(omni)
    );
    let account_word = chain_word(&eth_call(http, rpc, registry, &account_data).await?, 0)?;
    if account_word[..12].iter().any(|byte| *byte != 0) {
        return Err("invalid account address".into());
    }
    let account = format!("0x{}", hex::encode(&account_word[12..]));
    let entries = stream::iter(read_devices(http, rpc, registry, operator).await?)
        .map(|device| async move {
            let chain_scope = if device.tier == 1 || device.revoked {
                ConsoleChainScope::default()
            } else {
                let data = format!(
                    "0x{}{}{}",
                    chain_selector("getScope(bytes32,bytes32)"),
                    hex::encode(omni),
                    hex::encode(decode_word(&device.actor_omni)?)
                );
                parse_scope(&eth_call(http, rpc, scope, &data).await?)?
            };
            Ok::<_, String>(ConsoleFleetEntry {
                device,
                scope: chain_scope,
            })
        })
        .buffered(FLEET_READ_CONCURRENCY)
        .try_collect()
        .await?;
    Ok(ConsoleFleet {
        operator_omni: format!("0x{}", hex::encode(omni)),
        account,
        devices: entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn word(value: u64) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        bytes
    }
    #[tokio::test]
    async fn fleet_reads_overlap_without_losing_order_or_revoked_devices() {
        use axum::{extract::State, routing::post, Json, Router};
        use std::future::IntoFuture;
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };
        #[derive(Default)]
        struct Probe {
            active: AtomicUsize,
            peak: AtomicUsize,
            scope_reads: AtomicUsize,
            foreign_device: AtomicBool,
        }
        async fn rpc(
            State(probe): State<Arc<Probe>>,
            Json(body): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            let data = body["params"][0]["data"].as_str().unwrap();
            let raw = if data.starts_with(&format!(
                "0x{}",
                chain_selector("operatorMasterWallet(bytes32)")
            )) {
                word(9)
            } else if data.starts_with(&format!(
                "0x{}",
                chain_selector("getOperatorDevices(bytes32)")
            )) {
                [word(32), word(24), (1..=24).flat_map(word).collect()].concat()
            } else {
                let active = probe.active.fetch_add(1, Ordering::SeqCst) + 1;
                probe.peak.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                probe.active.fetch_sub(1, Ordering::SeqCst);
                if data.starts_with(&format!("0x{}", chain_selector("getDevice(bytes32)"))) {
                    let index = u64::from_str_radix(&data[data.len() - 16..], 16).unwrap();
                    let mut device = vec![0; 352];
                    let owner = if probe.foreign_device.load(Ordering::SeqCst) {
                        2
                    } else {
                        1
                    };
                    device[..32].copy_from_slice(&[owner; 32]);
                    device[32..64].copy_from_slice(&word(index));
                    device[6 * 32 + 31] = 2;
                    device[351] = u8::from(index % 3 != 0);
                    device
                } else {
                    assert!(data.starts_with(&format!(
                        "0x{}",
                        chain_selector("getScope(bytes32,bytes32)")
                    )));
                    probe.scope_reads.fetch_add(1, Ordering::SeqCst);
                    [
                        word(32),
                        word(256),
                        word(0),
                        word(0),
                        word(0),
                        word(0),
                        word(0),
                        word(0),
                        word(1),
                        word(0),
                    ]
                    .concat()
                }
            };
            Json(
                serde_json::json!({"jsonrpc":"2.0", "id":body["id"], "result":format!("0x{}", hex::encode(raw))}),
            )
        }
        let probe = Arc::new(Probe::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            axum::serve(
                listener,
                Router::new()
                    .route("/", post(rpc))
                    .with_state(probe.clone()),
            )
            .into_future(),
        );
        let fleet = read_fleet(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            "registry",
            "scope",
            &"01".repeat(32),
        )
        .await
        .unwrap();
        assert_eq!(fleet.devices.len(), 24);
        for (index, entry) in fleet.devices.iter().enumerate() {
            assert_eq!(
                entry.device.device_key_hash,
                format!("0x{}", hex::encode(word(index as u64 + 1)))
            );
            assert_eq!(entry.device.revoked, (index + 1) % 3 != 0);
        }
        assert_eq!(probe.scope_reads.load(Ordering::SeqCst), 8);
        assert!(
            probe.peak.load(Ordering::SeqCst) > 1,
            "fleet chain reads were serialized"
        );
        assert!(
            probe.peak.load(Ordering::SeqCst) <= FLEET_READ_CONCURRENCY,
            "fleet chain reads were unbounded"
        );
        probe.foreign_device.store(true, Ordering::SeqCst);
        let failure = read_fleet(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            "registry",
            "scope",
            &"01".repeat(32),
        )
        .await
        .unwrap_err();
        assert!(failure.contains("foreign device"));
        server.abort();
    }

    #[test]
    fn rejects_invalid_lengths_and_offsets_without_allocating() {
        for raw in [
            vec![],
            [word(33), word(0)].concat(),
            [word(32), vec![255; 32]].concat(),
        ] {
            assert!(parse_device_hashes(&raw).is_err());
        }
        assert!(chain_word(&[], usize::MAX).is_err());
        assert!(parse_device_hashes(&[word(32), word(1)].concat()).is_err());
        assert!(parse_scope(&[word(32), word(1)].concat()).is_err());
    }
    #[test]
    fn parses_scope_without_losing_unknown_grants_or_caps() {
        let raw = [
            word(32),
            word(256),
            word(0),
            word(5),
            word(20),
            word(3),
            word(3600),
            word(0),
            word(1),
            word(1),
            vec![7; 32],
        ]
        .concat();
        let scope = parse_scope(&raw).unwrap();
        assert_eq!(scope.service_ids, vec![format!("0x{}", "07".repeat(32))]);
        assert_eq!(scope.per_tx, "5");
        assert_eq!(scope.period_cap, "20");
        assert_eq!(scope.period_seconds, 3600);
        assert!(scope.exists);
    }
    #[test]
    fn rejects_non_boolean_revocation_and_invalid_tier() {
        let mut raw = vec![0; 352];
        raw[351] = 2;
        assert!(parse_device_entry(&raw, &[1; 32]).is_err());
        raw[351] = 0;
        raw[6 * 32 + 31] = 4;
        assert!(parse_device_entry(&raw, &[1; 32]).is_err());
        raw[6 * 32 + 31] = 1;
        raw[6 * 32 + 30] = 1;
        assert!(parse_device_entry(&raw, &[1; 32]).is_err());
    }
}
