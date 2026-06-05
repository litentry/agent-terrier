//! #1 Stage A — broker-sponsored ERC-4337 register: the verifiable encoding +
//! co-sign core for a `VerifyingPaymaster`-sponsored UserOp (zero-gas master
//! onboarding, #164 E6/E7). **Pure functions, no chain client.**
//!
//! Division of labour in the sponsored register:
//!   - the **browser** passkey-signs the `userOpHash` (the account signature);
//!   - the **broker** EIP-191-co-signs the paymaster `getHash` (the sponsorship
//!     approval — the Sybil gate, only for an authenticated J1 session);
//!   - **submission** (`EntryPoint.handleOps`) is Stage B (needs an EVM client).
//!
//! Everything here is byte-exact with the live contracts and verified read-only
//! (zero gas): `user_op_hash` ≡ `EntryPoint.getUserOpHash`, `paymaster_get_hash`
//! ≡ `VerifyingPaymaster.getHash`, and `broker_cosign` recovers to `brokerSigner`
//! under `VerifyingPaymaster._recover(_ethSignedHash(getHash), sig)`.
//!
//! ERC-4337 v0.7 `PackedUserOperation` — see
//! `crates/agentkeys-chain/src/IERC4337.sol` + `VerifyingPaymaster.sol`.

use agentkeys_core::device_crypto::{eip191_sign, keccak256};
use anyhow::{anyhow, Result};
use k256::ecdsa::SigningKey;

/// v0.7 `PackedUserOperation`. Fixed-word fields are stored as raw big-endian
/// bytes so the ABI encoding is unambiguous (uint256 → 32-byte word; the address
/// → 20 bytes; the packed gas pairs → their on-chain 32-byte form).
#[derive(Clone, Debug)]
pub struct PackedUserOp {
    pub sender: [u8; 20],
    pub nonce: [u8; 32],
    pub init_code: Vec<u8>,
    pub call_data: Vec<u8>,
    /// verificationGasLimit(16) ‖ callGasLimit(16)
    pub account_gas_limits: [u8; 32],
    pub pre_verification_gas: [u8; 32],
    /// maxPriorityFeePerGas(16) ‖ maxFeePerGas(16)
    pub gas_fees: [u8; 32],
    pub paymaster_and_data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Left-pad a 20-byte address into a 32-byte ABI word.
fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// A `u64` as a 32-byte ABI word (covers chainId + the uint48 validity fields).
fn u64_word(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

impl PackedUserOp {
    /// `userOpHash` per EntryPoint v0.7:
    /// `keccak( keccak(abi.encode(packed)) ‖ entryPoint ‖ chainId )`.
    /// `paymaster_and_data` MUST already carry the broker sponsorship signature
    /// (the account signs over the complete op).
    pub fn user_op_hash(&self, entry_point: &[u8; 20], chain_id: u64) -> [u8; 32] {
        let mut packed = Vec::with_capacity(8 * 32);
        packed.extend_from_slice(&addr_word(&self.sender));
        packed.extend_from_slice(&self.nonce);
        packed.extend_from_slice(&keccak256(&self.init_code));
        packed.extend_from_slice(&keccak256(&self.call_data));
        packed.extend_from_slice(&self.account_gas_limits);
        packed.extend_from_slice(&self.pre_verification_gas);
        packed.extend_from_slice(&self.gas_fees);
        packed.extend_from_slice(&keccak256(&self.paymaster_and_data));
        let inner = keccak256(&packed);

        let mut outer = Vec::with_capacity(3 * 32);
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(&addr_word(entry_point));
        outer.extend_from_slice(&u64_word(chain_id));
        keccak256(&outer)
    }

    /// `paymasterAndData[20:52]` (the gas limits the broker approved), or zero
    /// when shorter — matches `VerifyingPaymaster.getHash`'s guard.
    fn paymaster_gas_word(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        if self.paymaster_and_data.len() >= 52 {
            w.copy_from_slice(&self.paymaster_and_data[20..52]);
        }
        w
    }

    /// `VerifyingPaymaster.getHash(userOp, validUntil, validAfter)` — the digest
    /// the broker EIP-191-signs. Excludes the paymaster signature (no circularity)
    /// but binds every other field + chainId + paymaster + brokerSigner + window.
    pub fn paymaster_get_hash(
        &self,
        valid_until: u64,
        valid_after: u64,
        paymaster: &[u8; 20],
        broker_signer: &[u8; 20],
        chain_id: u64,
    ) -> [u8; 32] {
        let mut e = Vec::with_capacity(13 * 32);
        e.extend_from_slice(&addr_word(&self.sender));
        e.extend_from_slice(&self.nonce);
        e.extend_from_slice(&keccak256(&self.init_code));
        e.extend_from_slice(&keccak256(&self.call_data));
        e.extend_from_slice(&self.account_gas_limits);
        e.extend_from_slice(&self.pre_verification_gas);
        e.extend_from_slice(&self.gas_fees);
        e.extend_from_slice(&self.paymaster_gas_word());
        e.extend_from_slice(&u64_word(chain_id));
        e.extend_from_slice(&addr_word(paymaster));
        e.extend_from_slice(&addr_word(broker_signer));
        e.extend_from_slice(&u64_word(valid_until));
        e.extend_from_slice(&u64_word(valid_after));
        keccak256(&e)
    }
}

/// Broker EIP-191 co-sign over the paymaster `getHash` → 65-byte `r‖s‖v` hex.
/// `VerifyingPaymaster._recover(_ethSignedHash(getHash), sig)` recovers
/// `brokerSigner` from exactly this.
pub fn broker_cosign(get_hash: &[u8; 32], broker_sk: &SigningKey) -> Result<String> {
    eip191_sign(broker_sk, get_hash).map_err(|e| anyhow!("broker co-sign: {e}"))
}

/// Assemble `paymasterAndData`: `paymaster(20) ‖ verificationGasLimit(16) ‖
/// postOpGasLimit(16) ‖ validUntil(6) ‖ validAfter(6) ‖ signature(65)`.
/// `valid_until`/`valid_after` are uint48 (their low 6 bytes are taken).
pub fn assemble_paymaster_and_data(
    paymaster: &[u8; 20],
    verification_gas_limit: u128,
    post_op_gas_limit: u128,
    valid_until: u64,
    valid_after: u64,
    broker_sig_hex: &str,
) -> Result<Vec<u8>> {
    let sig = hex::decode(broker_sig_hex.trim().trim_start_matches("0x"))
        .map_err(|e| anyhow!("broker sig hex: {e}"))?;
    if sig.len() != 65 {
        return Err(anyhow!("broker sig must be 65 bytes, got {}", sig.len()));
    }
    let mut out = Vec::with_capacity(20 + 16 + 16 + 6 + 6 + 65);
    out.extend_from_slice(paymaster);
    out.extend_from_slice(&verification_gas_limit.to_be_bytes()); // 16 (u128)
    out.extend_from_slice(&post_op_gas_limit.to_be_bytes()); // 16
    out.extend_from_slice(&valid_until.to_be_bytes()[2..]); // low 6 of u64
    out.extend_from_slice(&valid_after.to_be_bytes()[2..]); // low 6
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Pack `(verificationGasLimit, callGasLimit)` into the on-chain
/// `accountGasLimits` word (each 16 bytes, hi ‖ lo). Also used for `gasFees`.
pub fn pack_u128_pair(hi: u128, lo: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..16].copy_from_slice(&hi.to_be_bytes());
    w[16..].copy_from_slice(&lo.to_be_bytes());
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::device_crypto::{ecrecover_eip191, evm_address};
    use k256::ecdsa::VerifyingKey;

    fn sample_op() -> PackedUserOp {
        PackedUserOp {
            sender: [0x11; 20],
            nonce: {
                let mut n = [0u8; 32];
                n[31] = 7;
                n
            },
            init_code: vec![],
            call_data: vec![0xde, 0xad, 0xbe, 0xef],
            account_gas_limits: pack_u128_pair(200_000, 100_000),
            pre_verification_gas: u64_word(60_000),
            gas_fees: pack_u128_pair(1_000_000_000, 2_000_000_000),
            paymaster_and_data: vec![],
            signature: vec![],
        }
    }

    #[test]
    fn word_helpers_left_pad() {
        let a = addr_word(&[0xab; 20]);
        assert_eq!(&a[..12], &[0u8; 12]);
        assert_eq!(&a[12..], &[0xab; 20]);
        assert_eq!(u64_word(0x010203)[24..], [0, 0, 0, 0, 0, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn pack_pair_is_hi_lo() {
        let w = pack_u128_pair(1, 2);
        assert_eq!(w[15], 1); // hi's last byte
        assert_eq!(w[31], 2); // lo's last byte
    }

    #[test]
    fn user_op_hash_is_deterministic_and_paymaster_sensitive() {
        let ep = [0x66; 20];
        let mut op = sample_op();
        let h1 = op.user_op_hash(&ep, 212_013);
        assert_eq!(h1, op.user_op_hash(&ep, 212_013));
        // Changing chainId or any field changes the hash.
        assert_ne!(h1, op.user_op_hash(&ep, 1));
        op.paymaster_and_data = vec![0u8; 80];
        assert_ne!(h1, op.user_op_hash(&ep, 212_013));
    }

    // The load-bearing property: the broker co-sign recovers to brokerSigner under
    // the SAME EIP-191(getHash) envelope the VerifyingPaymaster checks on-chain.
    #[test]
    fn broker_cosign_recovers_to_broker_signer() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_addr = evm_address(&VerifyingKey::from(&sk));
        let broker_bytes: [u8; 20] = {
            let h = hex::decode(broker_addr.trim_start_matches("0x")).unwrap();
            h.try_into().unwrap()
        };
        let op = sample_op();
        let paymaster = [0x55; 20];
        let get_hash = op.paymaster_get_hash(9_999_999_999, 0, &paymaster, &broker_bytes, 212_013);
        let sig = broker_cosign(&get_hash, &sk).unwrap();
        // The contract recovers from _ethSignedHash(getHash) == EIP-191(getHash).
        let recovered = ecrecover_eip191(&get_hash, &sig).unwrap();
        assert_eq!(recovered, broker_addr);
        assert_eq!(sig.trim_start_matches("0x").len(), 130); // 65 bytes
    }

    // Live cross-check vector (run: `cargo test -p agentkeys-broker-server --lib
    // sponsor::tests::print_crosscheck_vector -- --ignored --nocapture`). The bash
    // side feeds the SAME printed field bytes to the live EntryPoint.getUserOpHash
    // and to `cast abi-encode | cast keccak` (= VerifyingPaymaster.getHash).
    #[test]
    #[ignore = "prints a fixed vector for the zero-gas live cross-check"]
    fn print_crosscheck_vector() {
        let entry_point: [u8; 20] = hex::decode("6672E1b315332167aBA12E0B1d3532a7e9B1ADE9")
            .unwrap()
            .try_into()
            .unwrap();
        let paymaster = [0x55u8; 20];
        let broker_signer = [0x77u8; 20];
        let chain_id = 212_013u64;
        let op = sample_op();
        println!("SENDER=0x{}", hex::encode(op.sender));
        println!("NONCE=0x{}", hex::encode(op.nonce));
        println!("AGL=0x{}", hex::encode(op.account_gas_limits));
        println!("PVG=0x{}", hex::encode(op.pre_verification_gas));
        println!("GASFEES=0x{}", hex::encode(op.gas_fees));
        println!("PAYMASTER=0x{}", hex::encode(paymaster));
        println!("BROKER_SIGNER=0x{}", hex::encode(broker_signer));
        println!(
            "RUST_USEROP_HASH=0x{}",
            hex::encode(op.user_op_hash(&entry_point, chain_id))
        );
        println!(
            "RUST_GET_HASH=0x{}",
            hex::encode(op.paymaster_get_hash(
                9_999_999_999,
                0,
                &paymaster,
                &broker_signer,
                chain_id
            ))
        );
    }

    #[test]
    fn paymaster_and_data_layout() {
        let pm = [0x55; 20];
        let sig = format!("0x{}", "ab".repeat(65));
        let pad =
            assemble_paymaster_and_data(&pm, 50_000, 40_000, 0xffff_ffff_ffff, 0, &sig).unwrap();
        assert_eq!(pad.len(), 20 + 16 + 16 + 6 + 6 + 65);
        assert_eq!(&pad[0..20], &pm);
        // validUntil low-6 of 0xffffffffffff = all 0xff.
        assert_eq!(&pad[52..58], &[0xff; 6]);
    }
}
