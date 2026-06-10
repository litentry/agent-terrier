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
