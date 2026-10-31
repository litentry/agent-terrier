use anyhow::{ensure, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceProbe {
    pub operator_omni: [u8; 32],
    pub actor_omni: [u8; 32],
    pub tier: u8,
    pub registered: bool,
    pub revoked: bool,
}

pub const TIER_AGENT: u8 = 2;
pub const TIER_DEVICE: u8 = 3;

pub fn device_probe_calldata(device_key_hash: &[u8; 32]) -> Vec<u8> {
    let mut data = crate::audit::calldata::selector("getDevice(bytes32)").to_vec();
    data.extend_from_slice(device_key_hash);
    data
}

pub fn parse_device_probe(raw: &str) -> Result<DeviceProbe> {
    let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(raw))?;
    ensure!(
        bytes.len() == 11 * 32,
        "getDevice requires eleven ABI words"
    );
    let word =
        |index: usize| -> [u8; 32] { bytes[index * 32..(index + 1) * 32].try_into().unwrap() };
    for (index, width) in [(6, 1), (7, 1), (8, 8), (9, 4), (10, 1)] {
        ensure!(
            word(index)[..32 - width].iter().all(|byte| *byte == 0),
            "getDevice has noncanonical integer padding"
        );
    }
    let revoked = word(10)[31];
    ensure!(revoked <= 1, "getDevice has an invalid boolean");
    Ok(DeviceProbe {
        operator_omni: word(0),
        actor_omni: word(1),
        tier: word(6)[31],
        registered: word(8) != [0; 32],
        revoked: revoked == 1,
    })
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
        assert!(
            parse_device_probe(&hex::encode(&record))
                .unwrap()
                .registered
        );
        record[10 * 32 + 31] = 2;
        assert!(parse_device_probe(&hex::encode(&record)).is_err());
        record[10 * 32 + 31] = 0;
        record[6 * 32] = 1;
        assert!(parse_device_probe(&hex::encode(&record)).is_err());
        assert!(parse_device_probe("0x00").is_err());
    }
}
