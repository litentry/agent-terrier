//! Canonical fixed-width return values used to authorize chain-backed requests.

pub const ABI_WORD_BYTES: usize = 32;
pub const DEVICE_RECORD_WORDS: usize = 11;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRecord {
    pub operator_omni: [u8; 32],
    pub actor_omni: [u8; 32],
    pub k11_cred_id: [u8; 32],
    pub k11_rp_id_hash: [u8; 32],
    pub k11_pub_x: [u8; 32],
    pub k11_pub_y: [u8; 32],
    pub tier: u8,
    pub roles: u8,
    pub registered_at: u64,
    pub last_sign_count: u32,
    pub revoked: bool,
}

impl DeviceRecord {
    pub fn is_registered(&self) -> bool {
        self.registered_at != 0
    }
}

pub fn decode_device_record(raw: &[u8]) -> Result<DeviceRecord, &'static str> {
    if raw.len() != DEVICE_RECORD_WORDS * ABI_WORD_BYTES {
        return Err("getDevice requires eleven ABI words");
    }
    let word = |index| &raw[index * ABI_WORD_BYTES..(index + 1) * ABI_WORD_BYTES];
    Ok(DeviceRecord {
        operator_omni: word(0).try_into().unwrap(),
        actor_omni: word(1).try_into().unwrap(),
        k11_cred_id: word(2).try_into().unwrap(),
        k11_rp_id_hash: word(3).try_into().unwrap(),
        k11_pub_x: word(4).try_into().unwrap(),
        k11_pub_y: word(5).try_into().unwrap(),
        tier: unsigned(word(6), 1)? as u8,
        roles: unsigned(word(7), 1)? as u8,
        registered_at: decode_u64(word(8))?,
        last_sign_count: unsigned(word(9), 4)? as u32,
        revoked: decode_bool(word(10))?,
    })
}

pub fn decode_u64(raw: &[u8]) -> Result<u64, &'static str> {
    unsigned(raw, 8)
}

pub fn decode_bool(raw: &[u8]) -> Result<bool, &'static str> {
    match unsigned(raw, 1)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("noncanonical ABI boolean"),
    }
}

fn unsigned(raw: &[u8], width: usize) -> Result<u64, &'static str> {
    if raw.len() != ABI_WORD_BYTES {
        return Err("expected exactly one ABI word");
    }
    if raw[..ABI_WORD_BYTES - width].iter().any(|byte| *byte != 0) {
        return Err("noncanonical ABI integer padding");
    }
    Ok(u64::from_be_bytes(
        raw[ABI_WORD_BYTES - 8..].try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_fields_round_trip_without_truncation() {
        let mut raw = [0; DEVICE_RECORD_WORDS * ABI_WORD_BYTES];
        raw[..32].fill(0x11);
        raw[32..64].fill(0x22);
        raw[6 * 32 + 31] = 3;
        raw[7 * 32 + 31] = 7;
        raw[8 * 32 + 24..9 * 32].copy_from_slice(&u64::MAX.to_be_bytes());
        raw[9 * 32 + 28..10 * 32].copy_from_slice(&u32::MAX.to_be_bytes());
        let record = decode_device_record(&raw).unwrap();
        assert_eq!(record.operator_omni, [0x11; 32]);
        assert_eq!(record.actor_omni, [0x22; 32]);
        assert_eq!(record.tier, 3);
        assert_eq!(record.roles, 7);
        assert_eq!(record.registered_at, u64::MAX);
        assert_eq!(record.last_sign_count, u32::MAX);
        assert!(record.is_registered());
        assert!(!record.revoked);
        raw[10 * 32 + 31] = 1;
        assert!(decode_device_record(&raw).unwrap().revoked);
        assert!(!DeviceRecord::default().is_registered());
    }

    #[test]
    fn malformed_authority_has_no_fallback_value() {
        let valid = [0; DEVICE_RECORD_WORDS * ABI_WORD_BYTES];
        assert!(decode_device_record(&valid).is_ok());
        for (index, width) in [(6, 1), (7, 1), (8, 8), (9, 4), (10, 1)] {
            let mut malformed = valid;
            malformed[index * 32 + 31 - width] = 1;
            assert!(decode_device_record(&malformed).is_err());
        }
        for byte in 2..=255 {
            let mut malformed = valid;
            malformed[10 * 32 + 31] = byte;
            assert!(decode_device_record(&malformed).is_err());
        }
        for length in 0..valid.len() {
            assert!(decode_device_record(&valid[..length]).is_err());
        }
        assert!(decode_device_record(&[0; DEVICE_RECORD_WORDS * 32 + 32]).is_err());
    }

    #[test]
    fn scope_and_epoch_require_canonical_scalar_words() {
        let mut word = [0; 32];
        assert_eq!(decode_bool(&word), Ok(false));
        word[31] = 1;
        assert_eq!(decode_bool(&word), Ok(true));
        word[31] = 17;
        assert!(decode_bool(&word).is_err());
        word[24..].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(decode_u64(&word), Ok(u64::MAX));
        word[23] = 1;
        assert!(decode_u64(&word).is_err());
        for malformed in [&[][..], &[1][..], &[0; 33][..], &[0; 64][..]] {
            assert!(decode_bool(malformed).is_err());
            assert!(decode_u64(malformed).is_err());
        }
    }
}
