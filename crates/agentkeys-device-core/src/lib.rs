//! Shared device-key (K10) crypto for the §10.2 agent bootstrap (issue #144),
//! extracted to a `no_std` crate so the daemon and the ESP32 firmware run the
//! SAME secp256k1 / EIP-191 / keccak code byte-for-byte (issue #367 anti-drift).
//!
//! `agentkeys-core::device_crypto` re-exports every function here (wrapping the
//! fallible ones back into `anyhow::Result`), so the daemon / CLI / broker keep
//! importing `agentkeys_core::device_crypto::*` unchanged. The firmware links the
//! same crate as an xtensa staticlib (the `ffi` feature). There is ONE
//! implementation of the bytes the broker's `ecrecover` verifies.
//!
//! The proof-of-possession preimage is the **deployed** one —
//! `keccak256("agentkeys-agent-pop:" || device_key_hash_hex)` — matching
//! `scripts/heima-agent-create.sh` and the on-chain `registerAgentDevice` inputs.
//!
//! What is NOT here (it is platform-specific, lives in the std layer):
//! entropy acquisition (`OsRng` on the host, `esp_fill_random` on the device)
//! and key persistence (a `0600` file on the host, encrypted NVS on the device).
//! Everything cryptographic — every byte that has to match the broker — is here.

#![no_std]
// The pure-crypto build forbids unsafe outright; only the `ffi` build relaxes to
// `deny` so the C-ABI module can locally `allow(unsafe_code)` for raw pointers.
#![cfg_attr(not(feature = "ffi"), forbid(unsafe_code))]
#![cfg_attr(feature = "ffi", deny(unsafe_code))]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

#[cfg(feature = "ffi")]
mod ffi;

// The panic handler + global allocator that make the device staticlib
// self-contained. Only the firmware's `--features freestanding` staticlib build
// pulls these in; the workspace rlib relies on std's handlers.
#[cfg(feature = "freestanding")]
mod rt;

/// Errors from the device-key crypto. Implements [`core::error::Error`] (stable
/// since Rust 1.81) so the std re-export layer converts it into `anyhow::Error`
/// transparently — callers in an `anyhow` context keep using `?` unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCryptoError {
    /// A value that should be hex (address / omni / signature) is not.
    NotHex,
    /// An EVM address did not decode to exactly 20 bytes.
    BadAddressLen(usize),
    /// An omni did not decode to exactly 32 bytes.
    BadOmniLen(usize),
    /// A signature did not decode to exactly 65 bytes (`r‖s‖v`).
    BadSignatureLen(usize),
    /// The `v` recovery byte was not one of `{0,1,27,28}`.
    UnsupportedV(u8),
    /// The recovery id could not be constructed.
    BadRecoveryId,
    /// The 64-byte `r‖s` did not parse as a signature.
    BadSignature,
    /// `ecrecover` failed to recover a verifying key.
    Recover,
    /// Recoverable signing failed.
    Sign,
    /// The 32 bytes were not a valid secp256k1 scalar (≥ curve order / zero).
    BadKey,
    /// A delegation signature recovered to a key whose `keccak` ≠ the claimed
    /// `device_key_hash` — the delegation was not issued by that device (#369).
    DelegationMismatch,
}

impl core::fmt::Display for DeviceCryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DeviceCryptoError::NotHex => f.write_str("value is not hex"),
            DeviceCryptoError::BadAddressLen(n) => write!(f, "address must be 20 bytes, got {n}"),
            DeviceCryptoError::BadOmniLen(n) => write!(f, "omni must be 32 bytes, got {n}"),
            DeviceCryptoError::BadSignatureLen(n) => {
                write!(f, "signature must be 65 bytes, got {n}")
            }
            DeviceCryptoError::UnsupportedV(v) => write!(f, "unsupported v byte: {v}"),
            DeviceCryptoError::BadRecoveryId => f.write_str("bad recovery id"),
            DeviceCryptoError::BadSignature => f.write_str("bad signature bytes"),
            DeviceCryptoError::Recover => f.write_str("ecrecover failed"),
            DeviceCryptoError::Sign => f.write_str("recoverable signing failed"),
            DeviceCryptoError::BadKey => f.write_str("invalid secp256k1 device key"),
            DeviceCryptoError::DelegationMismatch => {
                f.write_str("delegation signer does not match device_key_hash")
            }
        }
    }
}

impl core::error::Error for DeviceCryptoError {}

/// Keccak-256 over `bytes`.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// EVM address (`0x` + 40 lowercase hex) = last 20 bytes of
/// keccak256(uncompressed pubkey x‖y).
pub fn evm_address(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(false);
    let xy = &point.as_bytes()[1..]; // drop the 0x04 SEC1 tag → 64 bytes
    let hash = keccak256(xy);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// `device_key_hash = keccak256(address_bytes)` as `0x` + 64 hex. `addr` may be
/// `0x`-prefixed and any case; the 20 raw address bytes are hashed (not ASCII).
pub fn device_key_hash(addr: &str) -> Result<String, DeviceCryptoError> {
    let addr_lc = addr.trim().to_lowercase();
    let hex_part = addr_lc.strip_prefix("0x").unwrap_or(&addr_lc);
    let addr_bytes = hex::decode(hex_part).map_err(|_| DeviceCryptoError::NotHex)?;
    if addr_bytes.len() != 20 {
        return Err(DeviceCryptoError::BadAddressLen(addr_bytes.len()));
    }
    Ok(format!("0x{}", hex::encode(keccak256(&addr_bytes))))
}

/// The MASTER device key hash, derived deterministically from the operator
/// omni: `device_key_hash = keccak256(operator_omni_bytes)` as `0x` + 64 hex.
///
/// Mirrors the web/#164 register convention `cast keccak "0x$OPERATOR_OMNI"`
/// (`cast keccak` over a `0x`-prefixed value hashes the 32 RAW omni bytes, not
/// the ASCII hex). Because the hash is derivable from the omni alone, the master
/// session needs no cached `device_key_hash` to resolve cap-mint after a restart
/// (issue #220). `omni` may be `0x`/`0X`-prefixed or bare; MUST decode to 32 bytes.
pub fn device_key_hash_from_omni(omni: &str) -> Result<String, DeviceCryptoError> {
    let trimmed = omni.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let omni_bytes = hex::decode(hex_part).map_err(|_| DeviceCryptoError::NotHex)?;
    if omni_bytes.len() != 32 {
        return Err(DeviceCryptoError::BadOmniLen(omni_bytes.len()));
    }
    Ok(format!("0x{}", hex::encode(keccak256(&omni_bytes))))
}

/// The agent proof-of-possession preimage:
/// `keccak256("agentkeys-agent-pop:" || device_key_hash_hex)`, where
/// `device_key_hash_hex` is the `0x`-prefixed string from [`device_key_hash`].
pub fn agent_pop_payload(device_key_hash_hex: &str) -> [u8; 32] {
    keccak256(format!("agentkeys-agent-pop:{device_key_hash_hex}").as_bytes())
}

/// Strip an optional `0x`/`0X` prefix, trim, and lowercase — the canonical hex
/// form the broker + worker agree on (used for omnis, addresses, and hashes
/// alike). Local to the PoP/delegation preimages so every side canonicalizes
/// identically regardless of the caller's `0x`/case.
fn strip0x_lower(s: &str) -> String {
    let t = s.trim().to_lowercase();
    t.strip_prefix("0x").unwrap_or(&t).to_string()
}

/// Canonicalize a delegation scope string for hashing: lowercase, then collapse
/// every internal whitespace run to a single space (so `"memory  Credentials"`
/// and `"memory credentials"` commit to the same bytes). The token *grammar*
/// (space-delimited `data_class`, or `service:op` patterns) is the protocol
/// layer's policy — this crate only fixes the bytes the signature covers.
fn norm_scope(scope: &str) -> String {
    let lc = scope.to_lowercase();
    lc.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The **per-request cap-mint** proof-of-possession preimage (issue #76 — the
/// real broker-SPOF fix). The client signs this with its K10 device key on
/// every cap-mint; the WORKER re-verifies the signature independently of the
/// broker against the on-chain device→omni binding
/// (`keccak(ecrecover(sig)) == device_key_hash`). The K10 private key never
/// reaches the broker, so a compromised broker cannot mint a usable cap.
///
/// Preimage (domain-separated, request-bound):
/// `keccak256("agentkeys-cap-pop:v1:" || operator || actor || keccak(service)
///  || op || data_class || client_nonce || client_ts)`.
///
/// `service` is hashed (it may contain `:`, e.g. `memory:travel`) so the `:`
/// field separator is unambiguous. `operator`/`actor` are canonicalized (strip
/// `0x`, lowercase) so the client and worker agree byte-for-byte.
pub fn cap_pop_payload(
    operator_omni: &str,
    actor_omni: &str,
    service: &str,
    op: &str,
    data_class: &str,
    client_nonce: &str,
    client_ts: u64,
) -> [u8; 32] {
    let operator = strip0x_lower(operator_omni);
    let actor = strip0x_lower(actor_omni);
    let service_hash = hex::encode(keccak256(service.trim().to_lowercase().as_bytes()));
    let preimage = format!(
        "agentkeys-cap-pop:v1:{operator}:{actor}:{service_hash}:{op}:{data_class}:{client_nonce}:{client_ts}"
    );
    keccak256(preimage.as_bytes())
}

/// The **device→sandbox delegation** preimage (issue #369). The device's K10
/// signs this ONCE per sandbox spawn to authorize the sandbox's OWN ephemeral
/// key `sandbox_key` to mint caps on the device's behalf, bounded by `scope` and
/// `expires_at`. So the K10 itself never leaves the device — the rejected
/// alternative (handing the sandbox the actual K10) collapses the #76 threat
/// model, since a compromised cloud sandbox could then mint any cap. This is the
/// RFC-8693-shaped single-hop "delegation_path" the ByteDance/ArkClaw read
/// (`docs/research/bytedance-code.md`, rec #1) calls for.
///
/// A worker that receives a cap whose cap-PoP ([`cap_pop_payload`]) is signed by
/// `sandbox_key` (NOT the device K10) re-verifies, independently of the broker:
///   1. `ecrecover(cap_sig) == sandbox_key`              (the cap is the sandbox's),
///   2. [`verify_delegation`] succeeds for `(device_key_hash, sandbox_key, scope,
///      expires_at, delegation_sig)`                     (the device authorized it),
///   3. `now < expires_at` AND the request is in `scope` (caller-side policy/clock),
///   4. `device_key_hash` is bound to operator/actor on-chain (the #76 check, unchanged).
///
/// Preimage (domain-separated, request-bound):
/// `keccak256("agentkeys-delegation:v1:" || device_key_hash || ":" || sandbox_key
///  || ":" || scope_hash || ":" || expires_at)`.
///
/// `device_key_hash` and `sandbox_key` are canonicalized (strip `0x`, lowercase)
/// and `scope` is whitespace-/case-normalized then hashed, so the device and the
/// worker commit to identical bytes regardless of input form.
pub fn delegation_payload(
    device_key_hash_hex: &str,
    sandbox_key: &str,
    scope: &str,
    expires_at: u64,
) -> [u8; 32] {
    let dkh = strip0x_lower(device_key_hash_hex);
    let sandbox = strip0x_lower(sandbox_key);
    let scope_hash = hex::encode(keccak256(norm_scope(scope).as_bytes()));
    let preimage = format!("agentkeys-delegation:v1:{dkh}:{sandbox}:{scope_hash}:{expires_at}");
    keccak256(preimage.as_bytes())
}

/// Does a cap for `(data_class, op, service)` fall within a device-signed
/// delegation `scope`? Tokens are space-delimited; each matches, in precedence:
///   1. the cap's exact `service` — e.g. `"memory:travel"` authorizes ONLY that
///      namespace (the per-namespace bound the #369 device→sandbox e2e relies on);
///   2. a bare `data_class` — e.g. `"memory"` authorizes any op + any namespace;
///   3. `data_class:op` — e.g. `"memory:canonical_fetch"` or `"memory:*"`.
///
/// Case-insensitive. This is the ONE owner of the delegation-scope policy (#203):
/// the broker's fast-fail cap-mint check AND the worker's authoritative re-verify
/// both call it, so they cannot diverge on what a delegation authorizes.
pub fn cap_in_scope(scope: &str, data_class: &str, op: &str, service: &str) -> bool {
    let dc = data_class.trim().to_lowercase();
    let op = op.trim().to_lowercase();
    let svc = service.trim().to_lowercase();
    scope.split_whitespace().any(|tok| {
        let tok = tok.to_lowercase();
        if tok == svc || tok == dc {
            return true;
        }
        match tok.split_once(':') {
            Some((d, o)) => d == dc && (o == op || o == "*"),
            None => false,
        }
    })
}

/// Verify a single-hop device→sandbox delegation (issue #369): recover the signer
/// from `delegation_sig` over [`delegation_payload`] and assert
/// `keccak(signer) == device_key_hash`. Returns the recovered device address
/// (`0x`-lowercase) on success, or [`DeviceCryptoError::DelegationMismatch`] if the
/// recovered key is not this device.
///
/// This crate is clock-free and policy-free: it proves ONLY that the signature
/// commits to exactly these bytes and was made by `device_key_hash`'s key. The
/// caller (the worker, with a clock + the on-chain scope) still enforces
/// `now < expires_at` and that the cap request falls within `scope`.
pub fn verify_delegation(
    device_key_hash_hex: &str,
    sandbox_key: &str,
    scope: &str,
    expires_at: u64,
    delegation_sig: &str,
) -> Result<String, DeviceCryptoError> {
    let payload = delegation_payload(device_key_hash_hex, sandbox_key, scope, expires_at);
    let recovered = ecrecover_eip191(&payload, delegation_sig)?;
    let recovered_hash = device_key_hash(&recovered)?;
    if strip0x_lower(&recovered_hash) != strip0x_lower(device_key_hash_hex) {
        return Err(DeviceCryptoError::DelegationMismatch);
    }
    Ok(recovered)
}

/// Build a secp256k1 [`SigningKey`] (K10) from 32 raw private-key bytes. The
/// platform supplies the entropy — `OsRng` on the host, `esp_fill_random` on the
/// device — and this validates it is a non-zero scalar below the curve order
/// (rejection probability ≈ 2⁻¹²⁸; the caller re-samples on the rare error).
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, DeviceCryptoError> {
    SigningKey::from_slice(bytes).map_err(|_| DeviceCryptoError::BadKey)
}

/// EIP-191 `personal_sign` over `message`, producing 65-byte `r‖s‖v` hex
/// (`v ∈ {27,28}`, low-s via k256). Matches the broker's ecrecover envelope.
pub fn eip191_sign(sk: &SigningKey, message: &[u8]) -> Result<String, DeviceCryptoError> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message);
    let digest = h.finalize();
    let (sig, recid): (Signature, RecoveryId) = sk
        .sign_prehash_recoverable(&digest)
        .map_err(|_| DeviceCryptoError::Sign)?;
    let mut out = sig.to_bytes().to_vec(); // 64 bytes r‖s
    out.push(27 + recid.to_byte());
    Ok(format!("0x{}", hex::encode(out)))
}

/// EIP-191 ecrecover: recover the `0x`-lowercase signer address from a 65-byte
/// `r‖s‖v` hex signature over `message`. `v ∈ {0,1,27,28}`.
pub fn ecrecover_eip191(message: &[u8], signature_hex: &str) -> Result<String, DeviceCryptoError> {
    let sig_hex = signature_hex.trim().trim_start_matches("0x");
    let sig_bytes: Vec<u8> = hex::decode(sig_hex).map_err(|_| DeviceCryptoError::NotHex)?;
    if sig_bytes.len() != 65 {
        return Err(DeviceCryptoError::BadSignatureLen(sig_bytes.len()));
    }
    let recovery_id_byte = match sig_bytes[64] {
        v @ (0 | 1) => v,
        v @ (27 | 28) => v - 27,
        other => return Err(DeviceCryptoError::UnsupportedV(other)),
    };
    let recovery_id =
        RecoveryId::try_from(recovery_id_byte).map_err(|_| DeviceCryptoError::BadRecoveryId)?;
    let signature =
        Signature::from_slice(&sig_bytes[..64]).map_err(|_| DeviceCryptoError::BadSignature)?;
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message);
    let digest = h.finalize();
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|_| DeviceCryptoError::Recover)?;
    Ok(evm_address(&vk))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed, valid secp256k1 scalar — deterministic tests with no RNG (keygen
    // from randomness is the std/device layer's job, not this crate's).
    fn fixed_key() -> SigningKey {
        signing_key_from_bytes(&[0x11u8; 32]).unwrap()
    }

    #[test]
    fn device_key_hash_from_omni_matches_cast_keccak() {
        // keccak256(32 zero bytes) is the well-known constant.
        let zero_omni = format!("0x{}", "00".repeat(32));
        assert_eq!(
            device_key_hash_from_omni(&zero_omni).unwrap(),
            "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
        );
    }

    #[test]
    fn device_key_hash_from_omni_ignores_prefix_and_case() {
        let bare = "11".repeat(32);
        let h = device_key_hash_from_omni(&bare).unwrap();
        assert_eq!(h, device_key_hash_from_omni(&format!("0x{bare}")).unwrap());
        assert_eq!(h, device_key_hash_from_omni(&format!("0X{bare}")).unwrap());
        assert!(h.starts_with("0x") && h.len() == 66);
    }

    #[test]
    fn device_key_hash_from_omni_rejects_wrong_length() {
        let addr = format!("0x{}", "ab".repeat(20));
        assert!(device_key_hash_from_omni(&addr).is_err());
    }

    #[test]
    fn eip191_round_trip_recovers_signer() {
        let sk = fixed_key();
        let addr = evm_address(sk.verifying_key());
        let msg = b"hello agentkeys";
        let sig = eip191_sign(&sk, msg).unwrap();
        assert_eq!(ecrecover_eip191(msg, &sig).unwrap(), addr);
    }

    #[test]
    fn pop_sig_recovers_to_device_address() {
        // The redeem-critical match: recover the device address from pop_sig over
        // agent_pop_payload(device_key_hash) and check it equals the K10 address.
        let sk = fixed_key();
        let addr = evm_address(sk.verifying_key());
        let dkh = device_key_hash(&addr).unwrap();
        let pop = eip191_sign(&sk, &agent_pop_payload(&dkh)).unwrap();
        assert_eq!(
            ecrecover_eip191(&agent_pop_payload(&dkh), &pop).unwrap(),
            addr
        );
    }

    #[test]
    fn cap_pop_sig_recovers_to_device_and_matches_hash() {
        // The worker-critical match: recover the signer from a cap-PoP sig and
        // check keccak(address) == device_key_hash.
        let sk = fixed_key();
        let addr = evm_address(sk.verifying_key());
        let (operator, actor, service, op, dc, nonce, ts) = (
            "0xAABB",
            "ccdd",
            "memory:travel",
            "store",
            "memory",
            "0011223344556677",
            1_767_300_000u64,
        );
        let preimage = cap_pop_payload(operator, actor, service, op, dc, nonce, ts);
        let sig = eip191_sign(&sk, &preimage).unwrap();
        let recovered = ecrecover_eip191(&preimage, &sig).unwrap();
        assert_eq!(recovered, addr);
        assert_eq!(
            device_key_hash(&recovered).unwrap(),
            device_key_hash(&addr).unwrap()
        );
    }

    #[test]
    fn cap_pop_payload_canonicalizes_omni_prefix_and_case() {
        let a = cap_pop_payload(
            "0xABCD",
            "0xEF01",
            "openrouter",
            "fetch",
            "credentials",
            "ab",
            9,
        );
        let b = cap_pop_payload(
            "abcd",
            "ef01",
            "openrouter",
            "fetch",
            "credentials",
            "ab",
            9,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn cap_pop_payload_binds_op_and_data_class() {
        let base = cap_pop_payload("a", "b", "s", "store", "credentials", "n", 1);
        assert_ne!(
            base,
            cap_pop_payload("a", "b", "s", "fetch", "credentials", "n", 1)
        );
        assert_ne!(
            base,
            cap_pop_payload("a", "b", "s", "store", "memory", "n", 1)
        );
    }

    #[test]
    fn device_key_hash_is_0x_64_hex() {
        let h = device_key_hash("0x0000000000000000000000000000000000000000").unwrap();
        assert!(h.starts_with("0x"));
        assert_eq!(h.len(), 66);
    }

    #[test]
    fn ecrecover_rejects_wrong_length() {
        assert!(ecrecover_eip191(b"x", "0x00").is_err());
    }

    // The pinned golden vectors for entropy 0x11*32 — identical to ctest/ffi_smoke.c
    // and what the broker's ecrecover expects. Any silent change to the K10
    // derivation (address / hash / signature) fails here, on BOTH the daemon and
    // the device, since they are this one crate.
    #[test]
    fn golden_vectors_for_fixed_entropy() {
        let sk = fixed_key();
        let addr = evm_address(sk.verifying_key());
        assert_eq!(addr, "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a");
        let dkh = device_key_hash(&addr).unwrap();
        assert_eq!(
            dkh,
            "0x8dd832049319556c1cd22ed66ae790d07fea25830a6151c2f0a9879b3ef61305"
        );
        let sig = eip191_sign(&sk, &agent_pop_payload(&dkh)).unwrap();
        assert_eq!(
            sig,
            "0x548582e9b1db4a55358035e8d21361a0ced7f63d8f40796c3529fb8e64406aeb\
             462e245c20389884eb4070cf2ac9ea75ece6a9f37483afc9745dc71998c1b63d1c"
        );
    }

    // The fixed device→sandbox delegation vector (#369), shared with the C smoke
    // harness. Device key = 0x11*32; sandbox key = 0x22*32 (address only — the
    // sandbox's private key never matters to the delegation, only its pubkey).
    const DELEG_SCOPE: &str = "memory:get memory:put";
    const DELEG_EXPIRES: u64 = 1_767_300_000;

    fn sandbox_addr() -> String {
        evm_address(
            signing_key_from_bytes(&[0x22u8; 32])
                .unwrap()
                .verifying_key(),
        )
    }

    #[test]
    fn delegation_round_trip_recovers_device_and_rejects_others() {
        let sk = fixed_key();
        let addr = evm_address(sk.verifying_key());
        let dkh = device_key_hash(&addr).unwrap();
        let sandbox = sandbox_addr();

        let payload = delegation_payload(&dkh, &sandbox, DELEG_SCOPE, DELEG_EXPIRES);
        let sig = eip191_sign(&sk, &payload).unwrap();

        // The worker's check: verify_delegation recovers the DEVICE (not the sandbox)
        // and confirms keccak(signer) == device_key_hash.
        let recovered =
            verify_delegation(&dkh, &sandbox, DELEG_SCOPE, DELEG_EXPIRES, &sig).unwrap();
        assert_eq!(recovered, addr);

        // A delegation signed by the SANDBOX key (self-delegation forgery) must NOT
        // verify against the device's hash.
        let sandbox_sk = signing_key_from_bytes(&[0x22u8; 32]).unwrap();
        let forged = eip191_sign(&sandbox_sk, &payload).unwrap();
        assert_eq!(
            verify_delegation(&dkh, &sandbox, DELEG_SCOPE, DELEG_EXPIRES, &forged),
            Err(DeviceCryptoError::DelegationMismatch)
        );
    }

    #[test]
    fn delegation_payload_binds_every_field() {
        let dkh = "0x8dd832049319556c1cd22ed66ae790d07fea25830a6151c2f0a9879b3ef61305";
        let sandbox = sandbox_addr();
        let base = delegation_payload(dkh, &sandbox, DELEG_SCOPE, DELEG_EXPIRES);
        // A different sandbox key, scope, or expiry → a different signed statement.
        assert_ne!(
            base,
            delegation_payload(
                dkh,
                "0x0000000000000000000000000000000000000001",
                DELEG_SCOPE,
                DELEG_EXPIRES
            )
        );
        assert_ne!(
            base,
            delegation_payload(dkh, &sandbox, "memory:get", DELEG_EXPIRES)
        );
        assert_ne!(
            base,
            delegation_payload(dkh, &sandbox, DELEG_SCOPE, DELEG_EXPIRES + 1)
        );
        // 0x/case on the device_key_hash + sandbox_key, and whitespace/case on the
        // scope, must NOT change the bytes (device and worker may hold them differently).
        assert_eq!(
            base,
            delegation_payload(
                &dkh.to_uppercase().replace("0X", "0x"),
                &sandbox.to_uppercase(),
                "  MEMORY:get   memory:PUT ",
                DELEG_EXPIRES
            )
        );
    }

    // The pinned golden delegation signature for the fixed vector — the exact bytes
    // a worker ecrecovers. Shared with ctest/ffi_smoke.c so the device staticlib and
    // the native rlib are proven byte-identical on the delegation path too.
    #[test]
    fn golden_delegation_sig_for_fixed_vector() {
        let sk = fixed_key();
        let dkh = device_key_hash(&evm_address(sk.verifying_key())).unwrap();
        let sandbox = sandbox_addr();
        assert_eq!(sandbox, "0x1563915e194d8cfba1943570603f7606a3115508");
        let payload = delegation_payload(&dkh, &sandbox, DELEG_SCOPE, DELEG_EXPIRES);
        let sig = eip191_sign(&sk, &payload).unwrap();
        assert_eq!(
            sig,
            "0xbbd09776536fb12816a0067f97deee22dbe2cfebf67b24450991aa8f7394f762\
             0250d27d15c32efaeadbb111f4b128bde385e019a6c36ef504d7dd1ea8688de71b"
        );
    }
}
