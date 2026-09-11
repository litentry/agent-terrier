//! The browser-held DEVICE identity (#675, arch.md §6.4 "every machine is a
//! device actor"): one secp256k1 K10 per machine, generated IN the browser —
//! the page supplies `crypto.getRandomValues` entropy to [`DeviceIdentity::from_random_bytes`]
//! and keeps the secret (localStorage / IndexedDB); it never leaves the device
//! (§10.2 rule 1). The crypto is `agentkeys-device-core`, the single K10
//! source the daemon and the ESP32 link, so a browser device signs the SAME
//! PoP bytes the broker verifies for every other device kind.
//!
//! Native-tested against a `cast`-computed vector (secret `0x11` × 32); the
//! wasm layer (`wasm.rs`) only wraps these methods.

use agentkeys_device_core::{
    agent_pop_payload, cap_pop_payload, device_key_hash, eip191_sign, evm_address,
    signing_key_from_bytes,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("device secret must be 32 bytes of hex (a valid secp256k1 scalar)")]
    BadSecret,
    #[error("device crypto: {0}")]
    Crypto(String),
}

/// A K10 device key held by the page. Cloneable (the secret is copied, never
/// printed — `Debug` redacts it).
#[derive(Clone)]
pub struct DeviceIdentity {
    secret: [u8; 32],
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceIdentity({})", self.address())
    }
}

impl DeviceIdentity {
    /// Load a persisted secret (`0x` + 64 hex, as [`Self::secret_hex`] wrote it).
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, DeviceError> {
        let s = secret_hex.trim();
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        let raw = hex::decode(s).map_err(|_| DeviceError::BadSecret)?;
        Self::from_random_bytes(&raw)
    }

    /// Mint a new identity from 32 caller-supplied random bytes (the browser's
    /// `crypto.getRandomValues`); refuses anything that is not a valid scalar.
    pub fn from_random_bytes(bytes: &[u8]) -> Result<Self, DeviceError> {
        let secret: [u8; 32] = bytes.try_into().map_err(|_| DeviceError::BadSecret)?;
        signing_key_from_bytes(&secret).map_err(|_| DeviceError::BadSecret)?;
        Ok(Self { secret })
    }

    /// The persisted form: `0x` + 64 lowercase hex.
    pub fn secret_hex(&self) -> String {
        format!("0x{}", hex::encode(self.secret))
    }

    /// The device's EVM address = `device_pubkey` on the pairing wire.
    pub fn address(&self) -> String {
        let sk = signing_key_from_bytes(&self.secret).expect("validated at construction");
        evm_address(sk.verifying_key())
    }

    /// `keccak256(address bytes)` — the on-chain `SidecarRegistry` device key.
    pub fn device_key_hash(&self) -> Result<String, DeviceError> {
        device_key_hash(&self.address()).map_err(|e| DeviceError::Crypto(format!("{e:?}")))
    }

    /// The `pop_sig` of `/v1/agent/pairing/{request,poll}` and `/v1/agent/resolve`
    /// (EIP-191 over the agent-PoP payload; deterministic per key, so a fresh
    /// call per poll is free).
    pub fn agent_pop_sig(&self) -> Result<String, DeviceError> {
        let dkh = self.device_key_hash()?;
        self.sign(&agent_pop_payload(&dkh))
    }

    /// The optional #76 cap-mint proof of possession (`client_sig`).
    #[allow(clippy::too_many_arguments)]
    pub fn cap_pop_sig(
        &self,
        operator_omni: &str,
        actor_omni: &str,
        service: &str,
        op: &str,
        data_class: &str,
        client_nonce: &str,
        client_ts: u64,
    ) -> Result<String, DeviceError> {
        self.sign(&cap_pop_payload(
            operator_omni,
            actor_omni,
            service,
            op,
            data_class,
            client_nonce,
            client_ts,
        ))
    }

    fn sign(&self, message: &[u8]) -> Result<String, DeviceError> {
        let sk = signing_key_from_bytes(&self.secret)
            .map_err(|e| DeviceError::Crypto(format!("{e:?}")))?;
        eip191_sign(&sk, message).map_err(|e| DeviceError::Crypto(format!("{e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_device_core::ecrecover_eip191;

    // `cast wallet address / keccak / wallet sign` for secret 0x11 × 32
    // (scratchpad/tv.sh, 2026-09-10) — the broker verifies exactly these bytes.
    const SECRET: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const ADDRESS: &str = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
    const DKH: &str = "0x8dd832049319556c1cd22ed66ae790d07fea25830a6151c2f0a9879b3ef61305";
    const POP_SIG: &str = "0x548582e9b1db4a55358035e8d21361a0ced7f63d8f40796c3529fb8e64406aeb462e245c20389884eb4070cf2ac9ea75ece6a9f37483afc9745dc71998c1b63d1c";

    #[test]
    fn the_cast_vector_pins_address_key_hash_and_pop() {
        let d = DeviceIdentity::from_secret_hex(SECRET).unwrap();
        assert_eq!(d.address().to_lowercase(), ADDRESS);
        assert_eq!(d.device_key_hash().unwrap().to_lowercase(), DKH);
        assert_eq!(d.agent_pop_sig().unwrap().to_lowercase(), POP_SIG);
        assert_eq!(d.secret_hex(), SECRET);
        let d2 = DeviceIdentity::from_secret_hex(&SECRET[2..]).unwrap();
        assert_eq!(d2.address(), d.address());
    }

    #[test]
    fn the_pop_recovers_to_the_device_address() {
        let d = DeviceIdentity::from_secret_hex(SECRET).unwrap();
        let dkh = d.device_key_hash().unwrap();
        let sig = d.agent_pop_sig().unwrap();
        let signer = ecrecover_eip191(&agent_pop_payload(&dkh), &sig).unwrap();
        assert_eq!(signer.to_lowercase(), ADDRESS);
    }

    #[test]
    fn cap_pop_differs_per_service_and_recovers() {
        let d = DeviceIdentity::from_secret_hex(SECRET).unwrap();
        let a = d
            .cap_pop_sig(
                "0xop",
                "0xactor",
                "channel-sub:kitchen-display",
                "channel_subscribe",
                "channel",
                "n1",
                1,
            )
            .unwrap();
        let b = d
            .cap_pop_sig(
                "0xop",
                "0xactor",
                "channel-pub:kitchen-display",
                "channel_publish",
                "channel",
                "n1",
                1,
            )
            .unwrap();
        assert_ne!(a, b);
        let payload = cap_pop_payload(
            "0xop",
            "0xactor",
            "channel-sub:kitchen-display",
            "channel_subscribe",
            "channel",
            "n1",
            1,
        );
        assert_eq!(
            ecrecover_eip191(&payload, &a).unwrap().to_lowercase(),
            ADDRESS
        );
    }

    #[test]
    fn bad_secrets_are_refused() {
        assert!(matches!(
            DeviceIdentity::from_random_bytes(&[7u8; 31]),
            Err(DeviceError::BadSecret)
        ));
        assert!(matches!(
            DeviceIdentity::from_random_bytes(&[0u8; 32]),
            Err(DeviceError::BadSecret)
        ));
        assert!(matches!(
            DeviceIdentity::from_secret_hex("0xzz"),
            Err(DeviceError::BadSecret)
        ));
        assert!(DeviceIdentity::from_random_bytes(&[9u8; 32]).is_ok());
    }

    #[test]
    fn debug_redacts_the_secret() {
        let d = DeviceIdentity::from_secret_hex(SECRET).unwrap();
        let dbg = format!("{d:?}");
        assert!(dbg.contains("DeviceIdentity(0x"));
        assert!(!dbg.contains("1111111111"));
    }
}
