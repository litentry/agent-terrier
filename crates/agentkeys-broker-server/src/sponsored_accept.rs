//! #225 / #164 E7 — assemble the **sponsored agent-accept UserOp**.
//!
//! Ties the two halves that already exist into one complete, ready-to-sign
//! `PackedUserOperation`:
//!   - the **intent** — `agentkeys_core::erc4337::accept_batch_calldata` (the atomic
//!     `executeBatch([registerAgentDevice, setScope])`, P.2 + P.3);
//!   - the **sponsorship** — the broker EIP-191 co-signs the `VerifyingPaymaster`
//!     `getHash` (the J1-gated Sybil gate = gas-free), via [`crate::sponsor`].
//!
//! Output: the op with `paymasterAndData` filled, plus the `userOpHash` the master
//! passkey (K11) signs and the `getHash` the broker signed. **Pure** (takes the
//! broker key, no chain I/O): the caller fetches the on-chain 2D nonce + gas/fee
//! params and supplies them; submission (`EntryPoint.handleOps`) is the I/O step
//! that consumes [`AssembledAcceptUserOp::user_op`] once the account signature is
//! attached.
//!
//! Division of labour (unchanged from #200): browser/daemon K11-signs the
//! `userOpHash`; the broker co-signs the paymaster `getHash`; submission is Stage B.

use crate::sponsor::{assemble_paymaster_and_data, broker_cosign, pack_u128_pair, PackedUserOp};
use agentkeys_core::erc4337::{
    accept_batch_calldata, register_batch_calldata, AgentRegister, RegisterFirstMaster, ScopeGrant,
};
use anyhow::Result;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Everything the composer needs that isn't the broker key. Chain-derived values
/// (nonce, gas, fees, validity window, addresses) are inputs — nothing hardcoded;
/// the caller reads them on-chain and passes them in.
pub struct AcceptUserOpParams<'a> {
    pub entry_point: [u8; 20],
    pub chain_id: u64,

    /// The operator's ERC-4337 P-256 master account (the `sender`).
    pub master_account: [u8; 20],
    /// `SidecarRegistry` (target of the `registerAgentDevice` inner call).
    pub registry: [u8; 20],
    /// `AgentKeysScope` (target of the `setScope` inner call).
    pub scope: [u8; 20],
    /// EntryPoint v0.7 2D nonce for `master_account` (read on-chain by the caller).
    pub nonce: [u8; 32],

    /// `verificationGasLimit(16) ‖ callGasLimit(16)` — use [`pack_u128_pair`].
    pub account_gas_limits: [u8; 32],
    pub pre_verification_gas: [u8; 32],
    /// `maxPriorityFeePerGas(16) ‖ maxFeePerGas(16)` — use [`pack_u128_pair`].
    pub gas_fees: [u8; 32],

    /// `Some` = sponsored (VerifyingPaymaster co-signed); `None` = **unsponsored**
    /// direct `handleOps` (empty `paymasterAndData`; gas from the account's
    /// EntryPoint deposit, the submitter EOA fronts the outer tx + is the
    /// beneficiary). The unsponsored path mirrors the mainnet-proven
    /// `e2e/scripts/erc4337-register-master.sh`.
    pub paymaster: Option<[u8; 20]>,
    pub paymaster_verification_gas_limit: u128,
    pub paymaster_post_op_gas_limit: u128,
    pub valid_until: u64,
    pub valid_after: u64,
    /// The broker EOA: sponsored → the signer the `VerifyingPaymaster` trusts
    /// (recovers from the co-sign); unsponsored → the `handleOps` beneficiary.
    pub broker_signer: [u8; 20],

    pub register: &'a AgentRegister,
    pub grant: &'a ScopeGrant,
}

/// The assembled op + the two digests. `user_op.signature` is still empty — the
/// account (K11) signs `user_op_hash` and the caller sets it before submit.
pub struct AssembledAcceptUserOp {
    pub user_op: PackedUserOp,
    /// The account (master passkey / K11) signs THIS — `EntryPoint.getUserOpHash`.
    pub user_op_hash: [u8; 32],
    /// The broker signed THIS — `VerifyingPaymaster.getHash` (returned for audit).
    pub paymaster_get_hash: [u8; 32],
}

/// Assemble the sponsored accept UserOp: build the batch callData, co-sign the
/// paymaster, fill `paymasterAndData`, and compute the `userOpHash`.
pub fn assemble_accept_userop(
    p: &AcceptUserOpParams,
    broker_sk: &SigningKey,
) -> Result<AssembledAcceptUserOp> {
    let call_data = accept_batch_calldata(&p.registry, &p.scope, p.register, p.grant);
    assemble_userop_with_calldata(p, call_data, Vec::new(), broker_sk)
}

/// **The #278 D6 sibling** — assemble the ONE sponsored master-register UserOp:
/// `initCode` (counterfactual `P256AccountFactory.createAccount` deploy) +
/// `executeBatch([registerFirstMasterDevice])`. Unlike accept/scope/revoke the
/// account does NOT exist yet, so `init_code` is non-empty (the 184-byte factory
/// call from [`agentkeys_core::erc4337::p256_account_factory_init_code`]) and
/// `p.master_account` MUST be the `factory.getAddress(...)` predicted sender.
/// Like [`assemble_revoke_userop`] this uses only `p.registry` + the explicit
/// `register` intent; `p.register`/`p.grant`/`p.scope` are unused.
pub fn assemble_register_userop(
    p: &AcceptUserOpParams,
    init_code: Vec<u8>,
    register: &RegisterFirstMaster,
    broker_sk: &SigningKey,
) -> Result<AssembledAcceptUserOp> {
    let call_data = register_batch_calldata(&p.registry, register);
    assemble_userop_with_calldata(p, call_data, init_code, broker_sk)
}

/// **The #248 sibling** — assemble the scope-only re-grant UserOp
/// (`executeBatch([setScope])`, no register; the device binding already exists).
/// `p.register` supplies only the omni pair (`operator_omni` + `actor_omni`);
/// its device fields are unused, and `p.registry` is never called.
pub fn assemble_scope_userop(
    p: &AcceptUserOpParams,
    broker_sk: &SigningKey,
) -> Result<AssembledAcceptUserOp> {
    let call_data = agentkeys_core::erc4337::scope_batch_calldata(
        &p.scope,
        &p.register.operator_omni,
        &p.register.actor_omni,
        p.grant,
    );
    assemble_userop_with_calldata(p, call_data, Vec::new(), broker_sk)
}

/// **The unpair sibling** — assemble the agent-revoke UserOp
/// (`executeBatch([revokeAgentDevice × N])`; one hash = the single unpair, many
/// = the #260 master-reset fleet teardown, ONE Touch ID). The registry enforces
/// `msg.sender == operatorMasterWallet[device.operatorOmni]`, so the master
/// `P256Account` MUST be the sender (no EOA can sign this — the deployer-signed
/// script path reverts `NotAuthorized` for account-master operators). Only
/// `device_key_hashes` + `p.registry` feed the callData; `p.grant`, the
/// register fields, and `p.scope` are unused. Hashes MUST be pre-filtered to
/// active, deduplicated, operator-owned agent devices — `revokeAgentDevice`
/// reverts on already-revoked/unregistered entries, dooming the whole batch.
pub fn assemble_revoke_userop(
    p: &AcceptUserOpParams,
    device_key_hashes: &[[u8; 32]],
    broker_sk: &SigningKey,
) -> Result<AssembledAcceptUserOp> {
    let call_data = agentkeys_core::erc4337::revoke_batch_calldata(&p.registry, device_key_hashes);
    assemble_userop_with_calldata(p, call_data, Vec::new(), broker_sk)
}

/// Shared envelope assembly: wrap `call_data` in the master-account UserOp,
/// co-sign the paymaster, fill `paymasterAndData`, compute the `userOpHash`.
///
/// The paymaster `getHash` commits `paymasterAndData[20:52]` (the gas limits), so
/// we set those bytes BEFORE hashing — a provisional `paymaster ‖ gasWord` — then
/// rebuild `paymasterAndData` with the real broker signature appended. The two
/// always agree on the gas word, which is what the on-chain `getHash` re-derives.
///
/// `init_code` is empty for accept/scope/revoke (the master account already
/// exists) and the 184-byte factory call for the #278 D6 register (the account
/// is deployed counterfactually in the same op). It is hashed into BOTH the
/// `userOpHash` and the paymaster `getHash`, so the master + broker sign over it.
fn assemble_userop_with_calldata(
    p: &AcceptUserOpParams,
    call_data: Vec<u8>,
    init_code: Vec<u8>,
    broker_sk: &SigningKey,
) -> Result<AssembledAcceptUserOp> {
    let mut user_op = PackedUserOp {
        sender: p.master_account,
        nonce: p.nonce,
        init_code,
        call_data,
        account_gas_limits: p.account_gas_limits,
        pre_verification_gas: p.pre_verification_gas,
        gas_fees: p.gas_fees,
        paymaster_and_data: Vec::new(),
        signature: Vec::new(),
    };

    // `paymaster_get_hash` is [0;32] in the unsponsored path (nothing co-signed).
    let paymaster_get_hash = match p.paymaster {
        // Sponsored: provisional paymasterAndData = paymaster(20) ‖ gasWord(32)
        // exposes [20:52] (the gas word) so paymaster_get_hash reads the limits
        // the broker is approving; then rebuild with the real co-signature.
        Some(paymaster) => {
            let gas_word = pack_u128_pair(
                p.paymaster_verification_gas_limit,
                p.paymaster_post_op_gas_limit,
            );
            let mut provisional = Vec::with_capacity(52);
            provisional.extend_from_slice(&paymaster);
            provisional.extend_from_slice(&gas_word);
            user_op.paymaster_and_data = provisional;

            let get_hash = user_op.paymaster_get_hash(
                p.valid_until,
                p.valid_after,
                &paymaster,
                &p.broker_signer,
                p.chain_id,
            );
            let broker_sig = broker_cosign(&get_hash, broker_sk)?;
            user_op.paymaster_and_data = assemble_paymaster_and_data(
                &paymaster,
                p.paymaster_verification_gas_limit,
                p.paymaster_post_op_gas_limit,
                p.valid_until,
                p.valid_after,
                &broker_sig,
            )?;
            get_hash
        }
        // Unsponsored: empty paymasterAndData. Gas is paid from the account's
        // EntryPoint deposit; the submitter EOA fronts the outer `handleOps` tx
        // and is reimbursed as the beneficiary. No broker co-sign. This is the
        // mainnet-proven path (erc4337-register-master.sh).
        None => {
            user_op.paymaster_and_data = Vec::new();
            [0u8; 32]
        }
    };

    let user_op_hash = user_op.user_op_hash(&p.entry_point, p.chain_id);

    Ok(AssembledAcceptUserOp {
        user_op,
        user_op_hash,
        paymaster_get_hash,
    })
}

/// Broker-side mirror of `agentkeys_backend_client::protocol::WireUserOp` — the
/// hex-encoded ERC-4337 `PackedUserOperation` on the `/v1/accept/*` wire. The
/// broker doesn't depend on `backend-client`; the frozen key-set test there + the
/// one below pin the two shapes together (same discipline as `BrokerCapRequest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireUserOp {
    pub sender: String,
    pub nonce: String,
    pub init_code: String,
    pub call_data: String,
    pub account_gas_limits: String,
    pub pre_verification_gas: String,
    pub gas_fees: String,
    pub paymaster_and_data: String,
    pub signature: String,
}

impl WireUserOp {
    pub fn from_packed(op: &PackedUserOp) -> Self {
        Self {
            sender: hex0x(&op.sender),
            nonce: hex0x(&op.nonce),
            init_code: hex0x(&op.init_code),
            call_data: hex0x(&op.call_data),
            account_gas_limits: hex0x(&op.account_gas_limits),
            pre_verification_gas: hex0x(&op.pre_verification_gas),
            gas_fees: hex0x(&op.gas_fees),
            paymaster_and_data: hex0x(&op.paymaster_and_data),
            signature: hex0x(&op.signature),
        }
    }
}

/// Broker-side mirror of `BuildAcceptUserOpResponse` — the `/v1/accept/build` body
/// the daemon receives, then K11-signs `user_op_hash` and returns the filled
/// `user_op` to `/v1/accept/submit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAcceptResponse {
    pub user_op: WireUserOp,
    pub user_op_hash: String,
    pub entry_point: String,
    pub chain_id: u64,
}

impl AssembledAcceptUserOp {
    /// Shape the assembled op into the `/v1/accept/build` response body.
    pub fn into_build_response(
        &self,
        entry_point: &[u8; 20],
        chain_id: u64,
    ) -> BuildAcceptResponse {
        BuildAcceptResponse {
            user_op: WireUserOp::from_packed(&self.user_op),
            user_op_hash: hex0x(&self.user_op_hash),
            entry_point: hex0x(entry_point),
            chain_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::device_crypto::{ecrecover_eip191, evm_address};
    use k256::ecdsa::VerifyingKey;

    fn b32(x: u8) -> [u8; 32] {
        [x; 32]
    }

    fn sample_register() -> AgentRegister {
        AgentRegister {
            device_key_hash: b32(0x11),
            operator_omni: b32(0x22),
            actor_omni: b32(0x33),
            link_code_redemption: hex::decode("deadbeef").unwrap(),
            agent_pop_sig: vec![0x55; 65],
        }
    }

    fn sample_grant() -> ScopeGrant {
        ScopeGrant {
            services: vec![b32(0xaa), b32(0xbb)],
            read_only: true,
            max_per_call: 1000,
            max_per_period: 2000,
            max_total: 0,
            period_seconds: 86400,
        }
    }

    fn params<'a>(
        reg: &'a AgentRegister,
        grant: &'a ScopeGrant,
        broker_signer: [u8; 20],
    ) -> AcceptUserOpParams<'a> {
        AcceptUserOpParams {
            entry_point: [0x66; 20],
            chain_id: 212_013,
            master_account: [0x99; 20],
            registry: {
                let mut a = [0u8; 20];
                a[19] = 0xa1;
                a
            },
            scope: {
                let mut a = [0u8; 20];
                a[19] = 0xa2;
                a
            },
            nonce: {
                let mut n = [0u8; 32];
                n[31] = 7;
                n
            },
            account_gas_limits: pack_u128_pair(300_000, 200_000),
            pre_verification_gas: {
                let mut w = [0u8; 32];
                w[28..].copy_from_slice(&60_000u32.to_be_bytes());
                w
            },
            gas_fees: pack_u128_pair(1_000_000_000, 2_000_000_000),
            paymaster: Some([0x55; 20]),
            paymaster_verification_gas_limit: 80_000,
            paymaster_post_op_gas_limit: 40_000,
            valid_until: 9_999_999_999,
            valid_after: 0,
            broker_signer,
            register: reg,
            grant,
        }
    }

    #[test]
    fn calldata_is_the_accept_batch_and_sender_is_the_master() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_addr = evm_address(&VerifyingKey::from(&sk));
        let broker_bytes: [u8; 20] = hex::decode(broker_addr.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        let reg = sample_register();
        let grant = sample_grant();
        let p = params(&reg, &grant, broker_bytes);
        let out = assemble_accept_userop(&p, &sk).unwrap();

        assert_eq!(out.user_op.sender, p.master_account);
        // The callData is exactly the atomic accept batch.
        assert_eq!(
            out.user_op.call_data,
            accept_batch_calldata(&p.registry, &p.scope, &reg, &grant)
        );
        // Signature is left for the account (K11) to fill.
        assert!(out.user_op.signature.is_empty());
        // userOpHash is deterministic.
        assert_eq!(
            out.user_op_hash,
            out.user_op.user_op_hash(&p.entry_point, p.chain_id)
        );
    }

    #[test]
    fn paymaster_and_data_carries_a_broker_cosign_over_the_get_hash() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_addr = evm_address(&VerifyingKey::from(&sk));
        let broker_bytes: [u8; 20] = hex::decode(broker_addr.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        let reg = sample_register();
        let grant = sample_grant();
        let p = params(&reg, &grant, broker_bytes);
        let out = assemble_accept_userop(&p, &sk).unwrap();

        // Layout: paymaster(20) ‖ vgl(16) ‖ postOp(16) ‖ validUntil(6) ‖ validAfter(6) ‖ sig(65).
        let pad = &out.user_op.paymaster_and_data;
        assert_eq!(pad.len(), 20 + 16 + 16 + 6 + 6 + 65);
        assert_eq!(&pad[0..20], &p.paymaster.unwrap());
        // The trailing 65 bytes are the broker co-sign; it recovers to the broker
        // EOA under the SAME EIP-191(getHash) the VerifyingPaymaster checks.
        // Layout offsets: paymaster 0..20, vgl 20..36, postOp 36..52,
        // validUntil 52..58, validAfter 58..64, sig 64..129.
        let sig_hex = format!("0x{}", hex::encode(&pad[64..129]));
        let recovered = ecrecover_eip191(&out.paymaster_get_hash, &sig_hex).unwrap();
        assert_eq!(recovered, broker_addr);
    }

    #[test]
    fn unsponsored_leaves_paymaster_and_data_empty_and_no_cosign() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_addr = evm_address(&VerifyingKey::from(&sk));
        let broker_bytes: [u8; 20] = hex::decode(broker_addr.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        let reg = sample_register();
        let grant = sample_grant();
        let mut p = params(&reg, &grant, broker_bytes);
        p.paymaster = None; // unsponsored direct handleOps
        let out = assemble_accept_userop(&p, &sk).unwrap();

        // No paymaster ⇒ empty paymasterAndData + a zero get-hash (nothing co-signed).
        assert!(out.user_op.paymaster_and_data.is_empty());
        assert_eq!(out.paymaster_get_hash, [0u8; 32]);
        // The batch callData + sender are unchanged; the account still K11-signs userOpHash.
        assert_eq!(out.user_op.sender, p.master_account);
        assert_eq!(
            out.user_op.call_data,
            accept_batch_calldata(&p.registry, &p.scope, &reg, &grant)
        );
        assert!(out.user_op.signature.is_empty());
        // userOpHash is deterministic over the empty-paymaster op.
        assert_eq!(
            out.user_op_hash,
            out.user_op.user_op_hash(&p.entry_point, p.chain_id)
        );
        // …and differs from the sponsored hash (paymasterAndData is part of the hash).
        let sponsored = assemble_accept_userop(&params(&reg, &grant, broker_bytes), &sk)
            .unwrap()
            .user_op_hash;
        assert_ne!(out.user_op_hash, sponsored);
    }

    #[test]
    fn scope_userop_carries_only_the_set_scope_batch() {
        // #248: same envelope (sender, paymaster co-sign, hash discipline), but the
        // callData is the scope-only batch — no registerAgentDevice inside.
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_addr = evm_address(&VerifyingKey::from(&sk));
        let broker_bytes: [u8; 20] = hex::decode(broker_addr.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        let reg = sample_register();
        let grant = sample_grant();
        let p = params(&reg, &grant, broker_bytes);
        let out = assemble_scope_userop(&p, &sk).unwrap();

        assert_eq!(out.user_op.sender, p.master_account);
        assert_eq!(
            out.user_op.call_data,
            agentkeys_core::erc4337::scope_batch_calldata(
                &p.scope,
                &reg.operator_omni,
                &reg.actor_omni,
                &grant,
            )
        );
        // Scope-only ≠ accept batch (no register half) ⇒ different intent ⇒ different hash.
        let accept = assemble_accept_userop(&p, &sk).unwrap();
        assert_ne!(out.user_op.call_data, accept.user_op.call_data);
        assert_ne!(out.user_op_hash, accept.user_op_hash);
        assert_eq!(
            out.user_op_hash,
            out.user_op.user_op_hash(&p.entry_point, p.chain_id)
        );
        assert!(out.user_op.signature.is_empty());
    }

    #[test]
    fn changing_the_grant_changes_the_user_op_hash() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_addr = evm_address(&VerifyingKey::from(&sk));
        let broker_bytes: [u8; 20] = hex::decode(broker_addr.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        let reg = sample_register();
        let grant_a = sample_grant();
        let mut grant_b = sample_grant();
        grant_b.read_only = false; // a different scope ⇒ different intent ⇒ different hash.

        let h_a = assemble_accept_userop(&params(&reg, &grant_a, broker_bytes), &sk)
            .unwrap()
            .user_op_hash;
        let h_b = assemble_accept_userop(&params(&reg, &grant_b, broker_bytes), &sk)
            .unwrap()
            .user_op_hash;
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn register_userop_carries_initcode_and_the_register_batch() {
        // #278 D6: the master register is the only op with a non-empty initCode —
        // the counterfactual P256AccountFactory deploy — plus executeBatch([
        // registerFirstMasterDevice]). Same paymaster co-sign + hash discipline.
        use agentkeys_core::erc4337::{p256_account_factory_init_code, register_batch_calldata};
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_addr = evm_address(&VerifyingKey::from(&sk));
        let broker_bytes: [u8; 20] = hex::decode(broker_addr.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        let reg = sample_register();
        let grant = sample_grant();
        // params' register/grant/scope are unused by the register composer.
        let p = params(&reg, &grant, broker_bytes);

        let register = RegisterFirstMaster {
            device_key_hash: b32(0x11),
            operator_omni: b32(0x22),
            actor_omni: b32(0x22),
            cred_id_hash: b32(0x44),
            rpid_hash: b32(0x55),
            pub_x: b32(0x66),
            pub_y: b32(0x77),
            roles: 2,
        };
        let factory = {
            let mut a = [0u8; 20];
            a[19] = 0xfa;
            a
        };
        let init_code = p256_account_factory_init_code(
            &factory,
            &register.cred_id_hash,
            &register.pub_x,
            &register.pub_y,
            &register.rpid_hash,
            &b32(0x88),
        );

        let out = assemble_register_userop(&p, init_code.clone(), &register, &sk).unwrap();

        // sender is the predicted account (the handler sets master_account = getAddress).
        assert_eq!(out.user_op.sender, p.master_account);
        // initCode is the 184-byte counterfactual deploy — the register-only carrier.
        assert_eq!(out.user_op.init_code, init_code);
        assert_eq!(out.user_op.init_code.len(), 184);
        // callData is exactly the register batch.
        assert_eq!(
            out.user_op.call_data,
            register_batch_calldata(&p.registry, &register)
        );
        // signature left for the master (K11) to fill.
        assert!(out.user_op.signature.is_empty());
        // sponsored: the broker co-sign over getHash recovers to the broker EOA.
        let pad = &out.user_op.paymaster_and_data;
        assert_eq!(pad.len(), 20 + 16 + 16 + 6 + 6 + 65);
        let sig_hex = format!("0x{}", hex::encode(&pad[64..129]));
        assert_eq!(
            ecrecover_eip191(&out.paymaster_get_hash, &sig_hex).unwrap(),
            broker_addr
        );
        // userOpHash deterministic, and ≠ the accept op (initCode + callData differ;
        // accept never carries an initCode).
        assert_eq!(
            out.user_op_hash,
            out.user_op.user_op_hash(&p.entry_point, p.chain_id)
        );
        let accept = assemble_accept_userop(&p, &sk).unwrap();
        assert!(accept.user_op.init_code.is_empty());
        assert_ne!(out.user_op_hash, accept.user_op_hash);
    }

    fn assembled() -> (AssembledAcceptUserOp, [u8; 20], u64, Vec<u8>) {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let broker_addr = evm_address(&VerifyingKey::from(&sk));
        let broker_bytes: [u8; 20] = hex::decode(broker_addr.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap();
        let reg = sample_register();
        let grant = sample_grant();
        let p = params(&reg, &grant, broker_bytes);
        let expected_calldata = accept_batch_calldata(&p.registry, &p.scope, &reg, &grant);
        let out = assemble_accept_userop(&p, &sk).unwrap();
        (out, p.entry_point, p.chain_id, expected_calldata)
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.trim_start_matches("0x")).unwrap()
    }

    #[test]
    fn wire_user_op_round_trips_every_field() {
        let (out, _, _, _) = assembled();
        let w = WireUserOp::from_packed(&out.user_op);
        assert_eq!(unhex(&w.sender), out.user_op.sender);
        assert_eq!(unhex(&w.nonce), out.user_op.nonce);
        assert_eq!(unhex(&w.init_code), out.user_op.init_code);
        assert_eq!(unhex(&w.call_data), out.user_op.call_data);
        assert_eq!(unhex(&w.account_gas_limits), out.user_op.account_gas_limits);
        assert_eq!(
            unhex(&w.pre_verification_gas),
            out.user_op.pre_verification_gas
        );
        assert_eq!(unhex(&w.gas_fees), out.user_op.gas_fees);
        assert_eq!(unhex(&w.paymaster_and_data), out.user_op.paymaster_and_data);
        assert_eq!(unhex(&w.signature), out.user_op.signature);
    }

    #[test]
    fn build_response_carries_the_batch_calldata_and_hash() {
        let (out, entry_point, chain_id, expected_calldata) = assembled();
        let resp = out.into_build_response(&entry_point, chain_id);
        assert_eq!(unhex(&resp.user_op.call_data), expected_calldata);
        assert_eq!(unhex(&resp.user_op_hash), out.user_op_hash);
        assert_eq!(unhex(&resp.entry_point), entry_point);
        assert_eq!(resp.chain_id, chain_id);
    }

    #[test]
    fn wire_user_op_keys_match_backend_client_shape() {
        // Server-side half of the #204 pin: a broker-side rename trips here, the
        // backend-client `wire_user_op_keys_frozen` test catches the client side.
        let (out, _, _, _) = assembled();
        let v = serde_json::to_value(WireUserOp::from_packed(&out.user_op)).unwrap();
        let mut keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "account_gas_limits",
                "call_data",
                "gas_fees",
                "init_code",
                "nonce",
                "paymaster_and_data",
                "pre_verification_gas",
                "sender",
                "signature",
            ]
        );
    }
}
