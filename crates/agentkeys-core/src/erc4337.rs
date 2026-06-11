//! ERC-4337 accept-UserOp callData builders (#225 / #164 E7).
//!
//! Pure ABI encoders for the inner calls of the **agent-accept batch** — the
//! single `executeBatch` UserOp that lands the device binding (P.2) and the scope
//! grant (P.3) atomically, in one block, gated by ONE master passkey (K11)
//! signature over the `userOpHash`:
//!
//! ```text
//!   P256Account.executeBatch(
//!     [SidecarRegistry,            AgentKeysScope ],
//!     [0,                          0              ],
//!     [registerAgentDevice(...),   setScope(...)  ])
//! ```
//!
//! These functions produce the raw bytes that become [`sponsor::PackedUserOp`]'s
//! `call_data` (the broker owns the sponsored-UserOp envelope; this owns the
//! inner intent). They are byte-exact with the deployed contracts
//! (`crates/agentkeys-chain/src/{SidecarRegistry,AgentKeysScope,P256Account}.sol`)
//! and golden-tested against `cast calldata` (see `tests`).
//!
//! Why a hand-rolled encoder (no `alloy`/`ethabi`): the repo keeps the EVM
//! surface dependency-free and byte-explicit — mirroring
//! `agentkeys-broker-server/src/sponsor.rs` and `audit/calldata.rs`, whose public
//! [`selector`] this reuses so selectors never drift.

use crate::audit::calldata::selector;
use crate::device_crypto::keccak256;

const WORD: usize = 32;

/// Prefix of the master-account credential-id preimage (see [`master_cred_id_hash`]).
/// **Terminology source-of-truth:** the bash literal in
/// `harness/scripts/erc4337-register-master.sh` (`cast keccak
/// "agentkeys-register-cred:0x$omni"`) MUST match this exactly.
pub const MASTER_CRED_ID_PREFIX: &str = "agentkeys-register-cred:0x";

/// The synthetic credential-id hash that keys a master's `P256Account` signer:
/// `keccak256("agentkeys-register-cred:0x" + lowercase_hex(operator_omni))`.
///
/// This is the value `erc4337-register-master.sh` creates the account with (the
/// on-chain `signers[credIdHash]` entry + the CREATE2 salt input), so the
/// accept-submit UserOp signature MUST carry the SAME hash — `P256Account` looks
/// the signer up by it (reverts `UnknownSigner` otherwise). The browser's raw
/// credential id is NOT the key; this operator-derived value is.
pub fn master_cred_id_hash(operator_omni: &[u8; 32]) -> [u8; 32] {
    let preimage = format!("{MASTER_CRED_ID_PREFIX}{}", hex::encode(operator_omni));
    keccak256(preimage.as_bytes())
}

/// Args for `SidecarRegistry.registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)`
/// — the P.2 device binding. `actor_omni` is also the agent's omni for the P.3
/// scope grant, so [`accept_batch_calldata`] threads it into both calls.
#[derive(Clone, Debug)]
pub struct AgentRegister {
    pub device_key_hash: [u8; 32],
    pub operator_omni: [u8; 32],
    pub actor_omni: [u8; 32],
    pub link_code_redemption: Vec<u8>,
    pub agent_pop_sig: Vec<u8>,
}

/// Args for `AgentKeysScope.setScope(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32)`
/// — the P.3 scope grant. `services` are the signed `bytes32` service ids
/// (`memory:<ns>` / `cred:<service>`); the caps mirror the on-chain `Scope`.
#[derive(Clone, Debug)]
pub struct ScopeGrant {
    pub services: Vec<[u8; 32]>,
    pub read_only: bool,
    pub max_per_call: u128,
    pub max_per_period: u128,
    pub max_total: u128,
    pub period_seconds: u32,
}

fn word_u128(n: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}

fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn bool_word(b: bool) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = b as u8;
    w
}

/// ABI `bytes`: `len(32) ‖ data ‖ zero-pad to a 32-byte multiple`.
fn enc_bytes(b: &[u8]) -> Vec<u8> {
    let pad = (WORD - (b.len() % WORD)) % WORD;
    let mut out = Vec::with_capacity(WORD + b.len() + pad);
    out.extend_from_slice(&word_u128(b.len() as u128));
    out.extend_from_slice(b);
    out.resize(out.len() + pad, 0);
    out
}

/// `registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)` calldata (P.2).
pub fn register_agent_device_calldata(r: &AgentRegister) -> Vec<u8> {
    let sel = selector("registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)");
    let enc_link = enc_bytes(&r.link_code_redemption);
    let enc_pop = enc_bytes(&r.agent_pop_sig);
    // Head: dkh, op, actor (inline bytes32) + 2 offsets for the dynamic `bytes`.
    let head = 5 * WORD;
    let off_link = head;
    let off_pop = head + enc_link.len();

    let mut out = Vec::with_capacity(4 + head + enc_link.len() + enc_pop.len());
    out.extend_from_slice(&sel);
    out.extend_from_slice(&r.device_key_hash);
    out.extend_from_slice(&r.operator_omni);
    out.extend_from_slice(&r.actor_omni);
    out.extend_from_slice(&word_u128(off_link as u128));
    out.extend_from_slice(&word_u128(off_pop as u128));
    out.extend_from_slice(&enc_link);
    out.extend_from_slice(&enc_pop);
    out
}

/// `setScope(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32)` calldata (P.3).
pub fn set_scope_calldata(
    operator_omni: &[u8; 32],
    agent_omni: &[u8; 32],
    g: &ScopeGrant,
) -> Vec<u8> {
    let sel = selector("setScope(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32)");
    // Head is 8 words; `services` is the only dynamic arg, its data follows the head.
    let off_services = 8 * WORD;

    let mut out = Vec::new();
    out.extend_from_slice(&sel);
    out.extend_from_slice(operator_omni);
    out.extend_from_slice(agent_omni);
    out.extend_from_slice(&word_u128(off_services as u128));
    out.extend_from_slice(&bool_word(g.read_only));
    out.extend_from_slice(&word_u128(g.max_per_call));
    out.extend_from_slice(&word_u128(g.max_per_period));
    out.extend_from_slice(&word_u128(g.max_total));
    out.extend_from_slice(&word_u128(g.period_seconds as u128));
    // Tail: services array — len ‖ each bytes32 element.
    out.extend_from_slice(&word_u128(g.services.len() as u128));
    for s in &g.services {
        out.extend_from_slice(s);
    }
    out
}

/// `executeBatch(address[],uint256[],bytes[])` calldata for [`P256Account`] — runs
/// each `(dest[i], values[i], func[i])` call atomically (any inner revert reverts
/// the whole batch). `values` are wei (u128 covers every realistic call value; the
/// accept batch uses 0).
pub fn execute_batch_calldata(dest: &[[u8; 20]], values: &[u128], func: &[Vec<u8>]) -> Vec<u8> {
    let sel = selector("executeBatch(address[],uint256[],bytes[])");

    // address[] dest: len ‖ each address word.
    let mut enc_dest = Vec::with_capacity(WORD * (1 + dest.len()));
    enc_dest.extend_from_slice(&word_u128(dest.len() as u128));
    for a in dest {
        enc_dest.extend_from_slice(&addr_word(a));
    }

    // uint256[] values: len ‖ each value word.
    let mut enc_value = Vec::with_capacity(WORD * (1 + values.len()));
    enc_value.extend_from_slice(&word_u128(values.len() as u128));
    for n in values {
        enc_value.extend_from_slice(&word_u128(*n));
    }

    // bytes[] func: len ‖ offset words (relative to AFTER the len word) ‖ each bytes elem.
    let elems: Vec<Vec<u8>> = func.iter().map(|f| enc_bytes(f)).collect();
    let mut enc_func = Vec::new();
    enc_func.extend_from_slice(&word_u128(func.len() as u128));
    let mut running = func.len() * WORD;
    for e in &elems {
        enc_func.extend_from_slice(&word_u128(running as u128));
        running += e.len();
    }
    for e in &elems {
        enc_func.extend_from_slice(e);
    }

    // Head: 3 offsets (dest, values, func), each relative to the args start.
    let head = 3 * WORD;
    let off_dest = head;
    let off_value = head + enc_dest.len();
    let off_func = head + enc_dest.len() + enc_value.len();

    let mut out = Vec::with_capacity(4 + head + enc_dest.len() + enc_value.len() + enc_func.len());
    out.extend_from_slice(&sel);
    out.extend_from_slice(&word_u128(off_dest as u128));
    out.extend_from_slice(&word_u128(off_value as u128));
    out.extend_from_slice(&word_u128(off_func as u128));
    out.extend_from_slice(&enc_dest);
    out.extend_from_slice(&enc_value);
    out.extend_from_slice(&enc_func);
    out
}

/// **The #225 headline** — the atomic accept batch as one `executeBatch` callData.
///
/// Composes `registerAgentDevice` (P.2) + `setScope` (P.3) into a single
/// [`execute_batch_calldata`] over `[registry, scope]`. The agent's `actor_omni`
/// from the register IS the `agentOmni` of the scope grant, threaded here by
/// construction so the two inner calls can never disagree on which agent they
/// bind. The result is signed once (K11) as the master UserOp's `call_data`.
pub fn accept_batch_calldata(
    registry: &[u8; 20],
    scope: &[u8; 20],
    reg: &AgentRegister,
    grant: &ScopeGrant,
) -> Vec<u8> {
    let register_cd = register_agent_device_calldata(reg);
    let scope_cd = set_scope_calldata(&reg.operator_omni, &reg.actor_omni, grant);
    execute_batch_calldata(
        &[*registry, *scope],
        &[0u128, 0u128],
        &[register_cd, scope_cd],
    )
}

/// **The #248 sibling** — the scope-only re-grant as one `executeBatch` callData.
///
/// For an ALREADY-bound agent: a single-call batch over `[scope]` carrying just
/// `setScope` (set-replace — `grant.services` is the FULL new list; empty
/// revokes everything). Same master-UserOp posture as [`accept_batch_calldata`],
/// minus the register — the device binding exists, only the grant changes.
pub fn scope_batch_calldata(
    scope: &[u8; 20],
    operator_omni: &[u8; 32],
    agent_omni: &[u8; 32],
    grant: &ScopeGrant,
) -> Vec<u8> {
    let scope_cd = set_scope_calldata(operator_omni, agent_omni, grant);
    execute_batch_calldata(&[*scope], &[0u128], &[scope_cd])
}

/// `revokeAgentDevice(bytes32)` calldata — the unpair.
pub fn revoke_agent_device_calldata(device_key_hash: &[u8; 32]) -> Vec<u8> {
    let sel = selector("revokeAgentDevice(bytes32)");
    let mut out = Vec::with_capacity(4 + WORD);
    out.extend_from_slice(&sel);
    out.extend_from_slice(device_key_hash);
    out
}

/// The unpair as one `executeBatch` callData: a single-call batch over
/// `[registry]` carrying `revokeAgentDevice`. The registry enforces
/// `msg.sender == operatorMasterWallet[device.operatorOmni]`, so this MUST run
/// as the master `P256Account` UserOp (no EOA — incl. the deployer — can sign
/// it; `NotAuthorized(caller, master)` otherwise, the real 2026-06-11 unpair
/// incident).
pub fn revoke_batch_calldata(registry: &[u8; 20], device_key_hash: &[u8; 32]) -> Vec<u8> {
    execute_batch_calldata(
        &[*registry],
        &[0u128],
        &[revoke_agent_device_calldata(device_key_hash)],
    )
}

/// `abi.encode(bytes32 credIdHash, bytes authenticatorData, bytes clientDataJSON,
/// uint256 challengeLocation, uint256 r, uint256 s)` — the **P256Account UserOp
/// signature** (`P256Account.sol::validateUserOp`, identical to the byte spec the
/// CLI's `k11 webauthn-userop-sign` + `harness/erc4337-master-e8.sh` produce). The
/// browser's WebAuthn assertion (`navigator.credentials.get()` over the userOpHash)
/// is encoded into this so `EntryPoint.handleOps` accepts the op. Golden-tested.
pub fn encode_webauthn_signature(
    cred_id_hash: &[u8; 32],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    challenge_location: u128,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Vec<u8> {
    let enc_auth = enc_bytes(authenticator_data);
    let head = 6 * WORD;
    let off_auth = head;
    let off_cdj = head + enc_auth.len();

    let mut out = Vec::with_capacity(head + enc_auth.len() + WORD + client_data_json.len());
    out.extend_from_slice(cred_id_hash);
    out.extend_from_slice(&word_u128(off_auth as u128));
    out.extend_from_slice(&word_u128(off_cdj as u128));
    out.extend_from_slice(&word_u128(challenge_location));
    out.extend_from_slice(r);
    out.extend_from_slice(s);
    out.extend_from_slice(&enc_auth);
    out.extend_from_slice(&enc_bytes(client_data_json));
    out
}

// ─── v0.7 PackedUserOperation + EntryPoint envelope (#230) ───────────────────
//
// Moved here from `agentkeys-broker-server::sponsor` so the broker AND the
// in-house bundler (`agentkeys-bundler`) share ONE owner of the packed shape,
// the `userOpHash`, and the `handleOps` calldata — the same single-owner
// discipline as the rest of this module (issue #203 applied to the 4337 layer).

/// A `u64` as a 32-byte ABI word (covers chainId + the uint48 validity fields).
fn u64_word(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

/// Pack `(verificationGasLimit, callGasLimit)` into the on-chain
/// `accountGasLimits` word (each 16 bytes, hi ‖ lo). Also used for `gasFees`
/// (`maxPriorityFeePerGas ‖ maxFeePerGas`).
pub fn pack_u128_pair(hi: u128, lo: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..16].copy_from_slice(&hi.to_be_bytes());
    w[16..].copy_from_slice(&lo.to_be_bytes());
    w
}

/// Split a packed `hi(16) ‖ lo(16)` word back into its two u128 halves —
/// the inverse of [`pack_u128_pair`] (the bundler/broker RPC boundary uses
/// the standard *unpacked* v0.7 JSON fields).
pub fn unpack_u128_pair(w: &[u8; 32]) -> (u128, u128) {
    let hi = u128::from_be_bytes(w[..16].try_into().expect("16 bytes"));
    let lo = u128::from_be_bytes(w[16..].try_into().expect("16 bytes"));
    (hi, lo)
}

/// v0.7 `PackedUserOperation`. Fixed-word fields are stored as raw big-endian
/// bytes so the ABI encoding is unambiguous (uint256 → 32-byte word; the address
/// → 20 bytes; the packed gas pairs → their on-chain 32-byte form).
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// ABI-encode this op as one element of the `PackedUserOperation[]` array —
    /// a dynamic tuple: 9-word head (offsets relative to the struct start) +
    /// the four `bytes` tails in field order.
    fn abi_encode_struct(&self) -> Vec<u8> {
        let enc_init = enc_bytes(&self.init_code);
        let enc_call = enc_bytes(&self.call_data);
        let enc_pmd = enc_bytes(&self.paymaster_and_data);
        let enc_sig = enc_bytes(&self.signature);

        let head = 9 * WORD;
        let off_init = head;
        let off_call = off_init + enc_init.len();
        let off_pmd = off_call + enc_call.len();
        let off_sig = off_pmd + enc_pmd.len();

        let mut out = Vec::with_capacity(off_sig + enc_sig.len());
        out.extend_from_slice(&addr_word(&self.sender));
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&word_u128(off_init as u128));
        out.extend_from_slice(&word_u128(off_call as u128));
        out.extend_from_slice(&self.account_gas_limits);
        out.extend_from_slice(&self.pre_verification_gas);
        out.extend_from_slice(&self.gas_fees);
        out.extend_from_slice(&word_u128(off_pmd as u128));
        out.extend_from_slice(&word_u128(off_sig as u128));
        out.extend_from_slice(&enc_init);
        out.extend_from_slice(&enc_call);
        out.extend_from_slice(&enc_pmd);
        out.extend_from_slice(&enc_sig);
        out
    }
}

// ─── standard v0.7 `eth_sendUserOperation` wire shape (#230) ────────────────
//
// The broker→bundler boundary speaks the CANONICAL unpacked v0.7 JSON userOp
// (what eth-infinitism / rundler / Pimlico accept), so swapping the in-house
// bundler for a third-party one needs no broker code change. One owner here;
// the broker serializes, the bundler deserializes.

/// Hex quantity (`0x`-minimal) from a u128 — eth JSON-RPC quantity style.
fn qty(n: u128) -> String {
    format!("0x{n:x}")
}

fn parse_qty(s: &str, name: &str) -> Result<u128, String> {
    let t = s.trim().trim_start_matches("0x");
    if t.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(t, 16).map_err(|e| format!("{name}: {e}"))
}

fn parse_hex(s: &str, name: &str) -> Result<Vec<u8>, String> {
    let t = s.trim().trim_start_matches("0x");
    let padded = if t.len() % 2 == 1 {
        format!("0{t}")
    } else {
        t.to_string()
    };
    hex::decode(&padded).map_err(|e| format!("{name} hex: {e}"))
}

fn parse_addr(s: &str, name: &str) -> Result<[u8; 20], String> {
    parse_hex(s, name)?
        .try_into()
        .map_err(|_| format!("{name} must be a 20-byte address"))
}

/// The standard ERC-4337 v0.7 JSON userOp (unpacked fields, camelCase) as sent
/// to `eth_sendUserOperation`. Quantities are `0x`-hex strings; optional
/// factory/paymaster groups are omitted when absent.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcUserOp {
    pub sender: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_data: Option<String>,
    pub call_data: String,
    pub call_gas_limit: String,
    pub verification_gas_limit: String,
    pub pre_verification_gas: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_verification_gas_limit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_post_op_gas_limit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_data: Option<String>,
    pub signature: String,
}

impl RpcUserOp {
    /// Unpack a [`PackedUserOp`] into the standard RPC shape (broker side).
    pub fn from_packed(op: &PackedUserOp) -> Self {
        let (verification_gas, call_gas) = unpack_u128_pair(&op.account_gas_limits);
        let (max_priority_fee, max_fee) = unpack_u128_pair(&op.gas_fees);
        let pvg = {
            let (hi, lo) = unpack_u128_pair(&op.pre_verification_gas);
            debug_assert_eq!(hi, 0, "preVerificationGas over u128 is unrealistic");
            lo
        };
        let (factory, factory_data) = if op.init_code.len() >= 20 {
            (
                Some(format!("0x{}", hex::encode(&op.init_code[..20]))),
                Some(format!("0x{}", hex::encode(&op.init_code[20..]))),
            )
        } else {
            (None, None)
        };
        let (paymaster, pm_vgl, pm_pogl, pm_data) = if op.paymaster_and_data.len() >= 52 {
            let p = &op.paymaster_and_data;
            let vgl = u128::from_be_bytes(p[20..36].try_into().expect("16 bytes"));
            let pogl = u128::from_be_bytes(p[36..52].try_into().expect("16 bytes"));
            (
                Some(format!("0x{}", hex::encode(&p[..20]))),
                Some(qty(vgl)),
                Some(qty(pogl)),
                Some(format!("0x{}", hex::encode(&p[52..]))),
            )
        } else {
            (None, None, None, None)
        };
        let (nonce_hi, nonce_lo) = unpack_u128_pair(&op.nonce);
        let nonce = if nonce_hi == 0 {
            qty(nonce_lo)
        } else {
            format!("0x{}", hex::encode(op.nonce))
        };
        Self {
            sender: format!("0x{}", hex::encode(op.sender)),
            nonce,
            factory,
            factory_data,
            call_data: format!("0x{}", hex::encode(&op.call_data)),
            call_gas_limit: qty(call_gas),
            verification_gas_limit: qty(verification_gas),
            pre_verification_gas: qty(pvg),
            max_fee_per_gas: qty(max_fee),
            max_priority_fee_per_gas: qty(max_priority_fee),
            paymaster,
            paymaster_verification_gas_limit: pm_vgl,
            paymaster_post_op_gas_limit: pm_pogl,
            paymaster_data: pm_data,
            signature: format!("0x{}", hex::encode(&op.signature)),
        }
    }

    /// Re-pack the standard RPC shape into the on-chain [`PackedUserOp`]
    /// (bundler side). Lossless inverse of [`Self::from_packed`].
    pub fn to_packed(&self) -> Result<PackedUserOp, String> {
        let nonce: [u8; 32] = {
            let raw = parse_hex(&self.nonce, "nonce")?;
            if raw.len() > 32 {
                return Err("nonce over 32 bytes".into());
            }
            let mut w = [0u8; 32];
            w[32 - raw.len()..].copy_from_slice(&raw);
            w
        };
        let init_code = match (&self.factory, &self.factory_data) {
            (Some(f), fd) => {
                let mut v = parse_addr(f, "factory")?.to_vec();
                if let Some(fd) = fd {
                    v.extend_from_slice(&parse_hex(fd, "factoryData")?);
                }
                v
            }
            (None, _) => Vec::new(),
        };
        let paymaster_and_data = match &self.paymaster {
            Some(p) => {
                let mut v = parse_addr(p, "paymaster")?.to_vec();
                let vgl = parse_qty(
                    self.paymaster_verification_gas_limit
                        .as_deref()
                        .unwrap_or("0x0"),
                    "paymasterVerificationGasLimit",
                )?;
                let pogl = parse_qty(
                    self.paymaster_post_op_gas_limit.as_deref().unwrap_or("0x0"),
                    "paymasterPostOpGasLimit",
                )?;
                v.extend_from_slice(&vgl.to_be_bytes());
                v.extend_from_slice(&pogl.to_be_bytes());
                if let Some(pd) = &self.paymaster_data {
                    v.extend_from_slice(&parse_hex(pd, "paymasterData")?);
                }
                v
            }
            None => Vec::new(),
        };
        Ok(PackedUserOp {
            sender: parse_addr(&self.sender, "sender")?,
            nonce,
            init_code,
            call_data: parse_hex(&self.call_data, "callData")?,
            account_gas_limits: pack_u128_pair(
                parse_qty(&self.verification_gas_limit, "verificationGasLimit")?,
                parse_qty(&self.call_gas_limit, "callGasLimit")?,
            ),
            pre_verification_gas: word_u128(parse_qty(
                &self.pre_verification_gas,
                "preVerificationGas",
            )?),
            gas_fees: pack_u128_pair(
                parse_qty(&self.max_priority_fee_per_gas, "maxPriorityFeePerGas")?,
                parse_qty(&self.max_fee_per_gas, "maxFeePerGas")?,
            ),
            paymaster_and_data,
            signature: parse_hex(&self.signature, "signature")?,
        })
    }
}

/// `EntryPoint.handleOps(PackedUserOperation[] ops, address payable beneficiary)`
/// calldata — what the bundler's outer tx carries. Golden-tested vs `cast calldata`.
pub fn handle_ops_calldata(ops: &[PackedUserOp], beneficiary: &[u8; 20]) -> Vec<u8> {
    let sel = selector(
        "handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)",
    );
    let elems: Vec<Vec<u8>> = ops.iter().map(PackedUserOp::abi_encode_struct).collect();

    // ops array tail: len ‖ per-element offsets (relative to after the len word) ‖ elems.
    let mut enc_ops = Vec::new();
    enc_ops.extend_from_slice(&word_u128(ops.len() as u128));
    let mut running = ops.len() * WORD;
    for e in &elems {
        enc_ops.extend_from_slice(&word_u128(running as u128));
        running += e.len();
    }
    for e in &elems {
        enc_ops.extend_from_slice(e);
    }

    // Head: offset-to-ops (2 words of head) + beneficiary.
    let mut out = Vec::with_capacity(4 + 2 * WORD + enc_ops.len());
    out.extend_from_slice(&sel);
    out.extend_from_slice(&word_u128((2 * WORD) as u128));
    out.extend_from_slice(&addr_word(beneficiary));
    out.extend_from_slice(&enc_ops);
    out
}

// ─── EntryPoint revert decoding (#247) ───────────────────────────────────────
//
// When `handleOps` reverts, the EntryPoint encodes WHY as a custom error —
// `FailedOp(uint256 opIndex, string reason)` carrying the canonical `AAxx ...`
// string (selector `0x220266b6`). Replaying the failed tx's calldata as an
// `eth_call` returns those bytes, so the bundler/broker can surface the REAL
// reason ("AA31 paymaster deposit too low") instead of guessing "wrong passkey"
// (the 2026-06-10 incident). Decoders live here next to the encoders so the
// 4337 ABI surface keeps one owner.

/// Read the dynamic ABI value (`string`/`bytes`) whose offset word sits at
/// 0-based `arg_idx` of `args` (the data AFTER the 4-byte selector). Revert
/// blobs are untrusted input — any malformed offset/length yields `None`.
fn abi_dynamic_at(args: &[u8], arg_idx: usize) -> Option<Vec<u8>> {
    let word_usize = |w: &[u8]| -> Option<usize> {
        if w[..WORD - 8].iter().any(|b| *b != 0) {
            return None; // offsets/lengths beyond u64 are never legitimate
        }
        usize::try_from(u64::from_be_bytes(w[WORD - 8..].try_into().ok()?)).ok()
    };
    let off = word_usize(args.get(arg_idx * WORD..(arg_idx + 1) * WORD)?)?;
    let data_start = off.checked_add(WORD)?;
    let len = word_usize(args.get(off..data_start)?)?;
    args.get(data_start..data_start.checked_add(len)?)
        .map(<[u8]>::to_vec)
}

/// Decode a standard `Error(string)` revert blob (selector `0x08c379a0`).
fn decode_error_string(data: &[u8]) -> Option<String> {
    let args = data.strip_prefix(&selector("Error(string)")[..])?;
    String::from_utf8(abi_dynamic_at(args, 0)?).ok()
}

/// Decode an EntryPoint v0.7 revert blob into its human-readable reason:
///
/// - `FailedOp(uint256,string)` → the verbatim `AAxx ...` reason
/// - `FailedOpWithRevert(uint256,string,bytes)` → reason + the inner revert
///   (decoded when it is `Error(string)`, raw hex otherwise)
/// - `Error(string)` → the message
///
/// `None` for anything else — callers surface the raw hex instead of guessing.
pub fn decode_entrypoint_revert(data: &[u8]) -> Option<String> {
    if let Some(args) = data.strip_prefix(&selector("FailedOp(uint256,string)")[..]) {
        return String::from_utf8(abi_dynamic_at(args, 1)?).ok();
    }
    if let Some(args) = data.strip_prefix(&selector("FailedOpWithRevert(uint256,string,bytes)")[..])
    {
        let reason = String::from_utf8(abi_dynamic_at(args, 1)?).ok()?;
        let inner = abi_dynamic_at(args, 2)?;
        let inner_text =
            decode_error_string(&inner).unwrap_or_else(|| format!("0x{}", hex::encode(&inner)));
        return Some(format!("{reason} (inner revert: {inner_text})"));
    }
    decode_error_string(data)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn addr(last: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = last;
        a
    }

    // Golden vectors produced by foundry `cast calldata` for the exact same inputs
    // (the authoritative ABI encoder); see the commit message for the commands.
    fn norm(s: &str) -> String {
        s.trim().trim_start_matches("0x").to_string()
    }
    const GOLDEN_REGISTER: &str = include_str!("testdata/erc4337_register.hex");
    const GOLDEN_SET_SCOPE: &str = include_str!("testdata/erc4337_set_scope.hex");
    const GOLDEN_EXECUTE_BATCH: &str = include_str!("testdata/erc4337_execute_batch.hex");

    #[test]
    fn register_agent_device_matches_cast() {
        let got = hex::encode(register_agent_device_calldata(&sample_register()));
        assert_eq!(got, norm(GOLDEN_REGISTER));
    }

    #[test]
    fn set_scope_matches_cast() {
        let got = hex::encode(set_scope_calldata(&b32(0x22), &b32(0x33), &sample_grant()));
        assert_eq!(got, norm(GOLDEN_SET_SCOPE));
    }

    #[test]
    fn accept_batch_matches_cast() {
        // dest = [registry 0x..a1, scope 0x..a2], values = [0,0],
        // func  = [registerAgentDevice(...), setScope(...)] — the atomic P.2+P.3 batch.
        let got = hex::encode(accept_batch_calldata(
            &addr(0xa1),
            &addr(0xa2),
            &sample_register(),
            &sample_grant(),
        ));
        assert_eq!(got, norm(GOLDEN_EXECUTE_BATCH));
    }

    #[test]
    fn batch_is_atomic_pair_of_the_two_inner_calls() {
        // The batch's func[] is exactly [register_cd, set_scope_cd] — the property the
        // one-block win relies on (no third call can sneak in; both bind the same agent).
        let reg = sample_register();
        let grant = sample_grant();
        let register_cd = register_agent_device_calldata(&reg);
        let scope_cd = set_scope_calldata(&reg.operator_omni, &reg.actor_omni, &grant);
        let batch = accept_batch_calldata(&addr(0xa1), &addr(0xa2), &reg, &grant);
        // both inner callDatas appear verbatim inside the batch bytes.
        assert!(find_subslice(&batch, &register_cd).is_some());
        assert!(find_subslice(&batch, &scope_cd).is_some());
        // setScope's agentOmni is the register's actor_omni (threaded by construction).
        assert_eq!(&scope_cd[4 + 32..4 + 64], &reg.actor_omni);
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn revoke_batch_is_a_single_call_batch_of_revoke_agent_device() {
        // selector pinned via `cast sig "revokeAgentDevice(bytes32)"`.
        let inner = revoke_agent_device_calldata(&b32(0x11));
        assert_eq!(hex::encode(&inner[..4]), "b269f9fb");
        assert_eq!(&inner[4..36], &b32(0x11));
        assert_eq!(inner.len(), 36);

        let batch = revoke_batch_calldata(&addr(0xa1), &b32(0x11));
        assert_eq!(
            batch,
            execute_batch_calldata(&[addr(0xa1)], &[0u128], std::slice::from_ref(&inner))
        );
        assert_eq!(hex::encode(&batch[..4]), "47e1da2a"); // executeBatch
        assert!(find_subslice(&batch[4..], &inner).is_some());
    }

    #[test]
    fn scope_batch_is_a_single_call_batch_of_set_scope() {
        // #248: the scope-only batch is executeBatch over [scope] with exactly the
        // setScope callData — byte-identical to composing the encoders by hand, so
        // a panel re-grant writes the SAME wire bytes as the accept's P.3 half.
        let grant = sample_grant();
        let scope_cd = set_scope_calldata(&b32(0x22), &b32(0x33), &grant);
        let batch = scope_batch_calldata(&addr(0xa2), &b32(0x22), &b32(0x33), &grant);
        assert_eq!(
            batch,
            execute_batch_calldata(&[addr(0xa2)], &[0u128], std::slice::from_ref(&scope_cd))
        );
        assert!(find_subslice(&batch, &scope_cd).is_some());
        // executeBatch selector — the same entry the golden-tested accept batch uses.
        assert_eq!(hex::encode(&batch[..4]), "47e1da2a");
        // no registerAgentDevice inside (scope-only, the binding already exists).
        let register_sel = selector("registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)");
        assert!(find_subslice(&batch[4..], &register_sel).is_none());
    }

    #[test]
    fn webauthn_signature_matches_cast() {
        // cast abi-encode "x(bytes32,bytes,bytes,uint256,uint256,uint256)"
        //   0xcc..cc 0xdead 0xbeef 13 7 9
        let golden = include_str!("testdata/erc4337_webauthn_sig.hex")
            .trim()
            .trim_start_matches("0x")
            .to_string();
        let mut r = [0u8; 32];
        r[31] = 7;
        let mut s = [0u8; 32];
        s[31] = 9;
        let got = hex::encode(encode_webauthn_signature(
            &[0xcc; 32],
            &hex::decode("dead").unwrap(),
            &hex::decode("beef").unwrap(),
            13,
            &r,
            &s,
        ));
        assert_eq!(got, golden);
    }

    fn sample_packed_op() -> PackedUserOp {
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
            pre_verification_gas: {
                let mut w = [0u8; 32];
                w[24..].copy_from_slice(&60_000u64.to_be_bytes());
                w
            },
            gas_fees: pack_u128_pair(1_000_000_000, 2_000_000_000),
            paymaster_and_data: vec![],
            signature: vec![0xab; 65],
        }
    }

    #[test]
    fn handle_ops_calldata_matches_cast() {
        // cast calldata "handleOps((address,uint256,bytes,bytes,bytes32,uint256,
        //   bytes32,bytes,bytes)[],address)" "[(0x11…11,7,0x,0xdeadbeef,<agl>,
        //   60000,<fees>,0x,0xab×65)]" 0x77…77 — the authoritative ABI encoder.
        let golden = norm(include_str!("testdata/erc4337_handle_ops.hex"));
        let got = hex::encode(handle_ops_calldata(&[sample_packed_op()], &[0x77; 20]));
        assert_eq!(got, golden);
    }

    #[test]
    fn rpc_user_op_roundtrips_packed_form() {
        // sponsored op (paymasterAndData = pm ‖ vgl ‖ pogl ‖ sig) survives the
        // unpack → standard-RPC-JSON → re-pack roundtrip byte-exactly.
        let mut op = sample_packed_op();
        let mut pmd = vec![0x55; 20];
        pmd.extend_from_slice(&200_000u128.to_be_bytes());
        pmd.extend_from_slice(&50_000u128.to_be_bytes());
        pmd.extend_from_slice(&[0xcd; 77]); // window(12) + sig(65)
        op.paymaster_and_data = pmd;
        let rpc = RpcUserOp::from_packed(&op);
        assert_eq!(rpc.verification_gas_limit, "0x30d40");
        assert_eq!(rpc.call_gas_limit, "0x186a0");
        assert_eq!(
            rpc.paymaster.as_deref(),
            Some("0x5555555555555555555555555555555555555555")
        );
        assert!(rpc.factory.is_none());
        assert_eq!(rpc.to_packed().unwrap(), op);

        // unsponsored (empty paymasterAndData) roundtrips too.
        let bare = sample_packed_op();
        let rpc2 = RpcUserOp::from_packed(&bare);
        assert!(rpc2.paymaster.is_none());
        assert_eq!(rpc2.to_packed().unwrap(), bare);

        // serde wire shape is camelCase (the standard bundler RPC field names).
        let v = serde_json::to_value(&rpc).unwrap();
        assert!(v.get("callGasLimit").is_some());
        assert!(v.get("maxFeePerGas").is_some());
        assert!(v.get("factory").is_none());
    }

    #[test]
    fn pack_unpack_u128_pair_roundtrips() {
        let w = pack_u128_pair(1_500_000, 2_000_000);
        assert_eq!(unpack_u128_pair(&w), (1_500_000, 2_000_000));
    }

    #[test]
    fn user_op_hash_is_deterministic_and_field_sensitive() {
        let ep = [0x66; 20];
        let mut op = sample_packed_op();
        let h1 = op.user_op_hash(&ep, 212_013);
        assert_eq!(h1, op.user_op_hash(&ep, 212_013));
        assert_ne!(h1, op.user_op_hash(&ep, 1));
        op.paymaster_and_data = vec![0u8; 80];
        assert_ne!(h1, op.user_op_hash(&ep, 212_013));
    }

    // ── decode_entrypoint_revert (#247) ──────────────────────────────────────
    // Golden args produced by `cast abi-encode` (the authoritative ABI encoder):
    //   cast abi-encode "f(uint256,string)" 0 "AA31 paymaster deposit too low"
    //   cast abi-encode "f(string)" "P256 verify failed"
    //   cast abi-encode "f(uint256,string,bytes)" 0 "AA23 reverted (or OOG)" <Error(string) blob>

    fn hex_blob(selector_hex: &str, cast_args: &str) -> Vec<u8> {
        hex::decode(format!(
            "{selector_hex}{}",
            cast_args.trim_start_matches("0x")
        ))
        .unwrap()
    }

    const FAILED_OP_AA31_ARGS: &str = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001e41413331207061796d6173746572206465706f73697420746f6f206c6f770000";
    const ERROR_STRING_ARGS: &str = "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000125032353620766572696679206661696c65640000000000000000000000000000";
    const FAILED_OP_WITH_REVERT_ARGS: &str = "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000164141323320726576657274656420286f72204f4f472900000000000000000000000000000000000000000000000000000000000000000000000000000000006408c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000125032353620766572696679206661696c6564000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn entrypoint_revert_selectors_pin_cast_ground_truth() {
        // cast sig "FailedOp(uint256,string)" / "FailedOpWithRevert(uint256,string,bytes)"
        // / "Error(string)" — drift here would silently break the decode.
        use crate::audit::calldata::selector_hex;
        assert_eq!(selector_hex("FailedOp(uint256,string)"), "0x220266b6");
        assert_eq!(
            selector_hex("FailedOpWithRevert(uint256,string,bytes)"),
            "0x65c8fd4d"
        );
        assert_eq!(selector_hex("Error(string)"), "0x08c379a0");
    }

    #[test]
    fn decodes_failed_op_to_the_verbatim_aa_reason() {
        let blob = hex_blob("220266b6", FAILED_OP_AA31_ARGS);
        assert_eq!(
            decode_entrypoint_revert(&blob).as_deref(),
            Some("AA31 paymaster deposit too low")
        );
    }

    #[test]
    fn decodes_failed_op_with_revert_including_inner_error_string() {
        let blob = hex_blob("65c8fd4d", FAILED_OP_WITH_REVERT_ARGS);
        assert_eq!(
            decode_entrypoint_revert(&blob).as_deref(),
            Some("AA23 reverted (or OOG) (inner revert: P256 verify failed)")
        );
    }

    #[test]
    fn decodes_plain_error_string() {
        let blob = hex_blob("08c379a0", ERROR_STRING_ARGS);
        assert_eq!(
            decode_entrypoint_revert(&blob).as_deref(),
            Some("P256 verify failed")
        );
    }

    #[test]
    fn rejects_unknown_truncated_and_malformed_revert_blobs() {
        // unknown selector
        assert_eq!(decode_entrypoint_revert(&[0xde, 0xad, 0xbe, 0xef]), None);
        // empty / shorter than a selector
        assert_eq!(decode_entrypoint_revert(&[]), None);
        assert_eq!(decode_entrypoint_revert(&[0x22]), None);
        // right selector, truncated args (offset word only)
        let truncated = hex_blob("220266b6", &FAILED_OP_AA31_ARGS[..2 + 64]);
        assert_eq!(decode_entrypoint_revert(&truncated), None);
        // offset pointing past the end of the blob
        let mut bad_offset = hex_blob("220266b6", FAILED_OP_AA31_ARGS);
        bad_offset[4 + 63] = 0xff;
        assert_eq!(decode_entrypoint_revert(&bad_offset), None);
        // offset word = u64::MAX — must yield None, never overflow-panic
        let mut huge_offset = hex_blob("220266b6", FAILED_OP_AA31_ARGS);
        for b in &mut huge_offset[4 + 32 + 24..4 + 64] {
            *b = 0xff;
        }
        assert_eq!(decode_entrypoint_revert(&huge_offset), None);
        // length word claiming more bytes than present
        let mut bad_len = hex_blob("220266b6", FAILED_OP_AA31_ARGS);
        bad_len[4 + 64 + 31] = 0xff;
        assert_eq!(decode_entrypoint_revert(&bad_len), None);
        // non-utf8 reason bytes
        let mut bad_utf8 = hex_blob("220266b6", FAILED_OP_AA31_ARGS);
        bad_utf8[4 + 96] = 0xff;
        bad_utf8[4 + 97] = 0xfe;
        assert_eq!(decode_entrypoint_revert(&bad_utf8), None);
    }

    #[test]
    fn master_cred_id_hash_pins_the_register_convention() {
        // Pins the EXACT preimage erc4337-register-master.sh hashes:
        //   keccak256("agentkeys-register-cred:0x" + lowercase-hex(omni)),
        // with NO `0x` on the omni and NO uppercase. A drift here = an
        // on-chain `UnknownSigner` at accept time.
        let omni = [0x22u8; 32];
        let expected = keccak256(
            b"agentkeys-register-cred:0x2222222222222222222222222222222222222222222222222222222222222222",
        );
        assert_eq!(master_cred_id_hash(&omni), expected);
        assert_eq!(MASTER_CRED_ID_PREFIX, "agentkeys-register-cred:0x");
        assert_ne!(
            master_cred_id_hash(&[0x22; 32]),
            master_cred_id_hash(&[0x33; 32])
        );
    }
}
