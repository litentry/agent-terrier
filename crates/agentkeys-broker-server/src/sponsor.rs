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

use anyhow::{anyhow, Result};
use k256::ecdsa::SigningKey;

// The packed-op shape, `userOpHash`, `paymaster_get_hash`, the gas-pair packing,
// and the `handleOps` calldata moved to `agentkeys_core::erc4337` (#230) so the
// broker and the in-house bundler (`agentkeys-bundler`) share one owner.
// Re-exported so existing `crate::sponsor::*` paths keep compiling.
use agentkeys_core::device_crypto::eip191_sign;
pub use agentkeys_core::erc4337::{pack_u128_pair, unpack_u128_pair, PackedUserOp};

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

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::device_crypto::{ecrecover_eip191, evm_address};
    use k256::ecdsa::VerifyingKey;

    fn u64_word(n: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    }

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

    // (word-helper + userOpHash unit tests moved to agentkeys-core::erc4337 with
    // the PackedUserOp itself, #230.)

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
