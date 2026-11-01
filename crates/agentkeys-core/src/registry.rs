use anyhow::{ensure, Context, Result};

pub use agentkeys_protocol::chain_abi::DeviceRecord as DeviceProbe;

pub const TIER_MASTER: u8 = 1;
pub const TIER_AGENT: u8 = 2;
pub const TIER_DEVICE: u8 = 3;

pub fn device_probe_calldata(device_key_hash: &[u8; 32]) -> Vec<u8> {
    let mut data = crate::audit::calldata::selector("getDevice(bytes32)").to_vec();
    data.extend_from_slice(device_key_hash);
    data
}

pub fn parse_device_probe(raw: &str) -> Result<DeviceProbe> {
    let bytes = decode_hex(raw)?;
    agentkeys_protocol::chain_abi::decode_device_record(&bytes).map_err(anyhow::Error::msg)
}

pub fn parse_bool(raw: &str) -> Result<bool> {
    agentkeys_protocol::chain_abi::decode_bool(&decode_hex(raw)?).map_err(anyhow::Error::msg)
}

pub fn parse_u64(raw: &str) -> Result<u64> {
    agentkeys_protocol::chain_abi::decode_u64(&decode_hex(raw)?).map_err(anyhow::Error::msg)
}

fn decode_hex(raw: &str) -> Result<Vec<u8>> {
    hex::decode(raw.strip_prefix("0x").unwrap_or(raw)).context("invalid ABI hex encoding")
}

pub fn verify_agent_pop(device_key_hash: &str, signature: &str) -> Result<String> {
    let hash = hex::decode(
        device_key_hash
            .strip_prefix("0x")
            .unwrap_or(device_key_hash),
    )?;
    ensure!(hash.len() == 32, "device key hash must be 32 bytes");
    let canonical = format!("0x{}", hex::encode(hash));
    let address = crate::device_crypto::ecrecover_eip191(
        &crate::device_crypto::agent_pop_payload(&canonical),
        signature,
    )
    .context("invalid device proof of possession")?;
    ensure!(
        crate::device_crypto::device_key_hash(&address)? == canonical,
        "proof does not match device key hash"
    );
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_decoder_rejects_malformed_authority() {
        let mut record = vec![0; 11 * 32];
        record[8 * 32 + 31] = 1;
        assert!(parse_device_probe(&hex::encode(&record))
            .unwrap()
            .is_registered());
        record[10 * 32 + 31] = 2;
        assert!(parse_device_probe(&hex::encode(&record)).is_err());
        record[10 * 32 + 31] = 0;
        record[6 * 32] = 1;
        assert!(parse_device_probe(&hex::encode(&record)).is_err());
        assert!(parse_device_probe("0x00").is_err());
    }
}
