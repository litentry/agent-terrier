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
