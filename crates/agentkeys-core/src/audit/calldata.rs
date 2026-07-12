//! EVM calldata decode for the stage-1 AgentKeys contracts (issue #153).
//!
//! The parent-control web UI's step-9 audit view must decode every action's
//! Heima transaction — real selector + typed args against the verified ABIs,
//! not a hand-maintained kind→signature mock. This module is the real decoder:
//!
//! 1. [`selector`] — the canonical 4-byte selector = `keccak256(signature)[..4]`
//!    (via `sha3`, already a dep — no ethabi/alloy pulled in).
//! 2. [`REGISTRY`] — the audit-relevant functions of the four deployed
//!    contracts (`CredentialAudit`, `SidecarRegistry`, `AgentKeysScope`,
//!    `K3EpochCounter`), each with ABI-accurate param names + types. The
//!    selectors are asserted against `cast`-derived ground truth in tests so
//!    drift between this table and the on-chain ABIs fails CI.
//! 3. [`decode_calldata`] — head/tail ABI decode of real calldata into typed
//!    JSON args the UI renders directly.
//!
//! Supported ABI types cover every param in the registry: `bytes32`,
//! `uint8/32/64/128/256`, `address`, `bool`, `bytes`, `bytes32[]`. A trailing
//! `tuple` (the WebAuthn assertion struct on the scope/master calls) is left
//! undecoded with an explicit note rather than guessed — the selector, name,
//! and all leading typed args are still surfaced.

use serde::Serialize;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// The 4-byte function selector for a Solidity signature
/// (`keccak256(signature)[..4]`). `signature` is the canonical form with no
/// spaces and no param names, e.g. `append(bytes32,bytes32,bytes32,uint8,bytes32)`.
pub fn selector(signature: &str) -> [u8; 4] {
    let digest = Keccak256::digest(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

/// `0x`-prefixed hex of [`selector`].
pub fn selector_hex(signature: &str) -> String {
    format!("0x{}", hex::encode(selector(signature)))
}

/// Is this ABI type a tuple/struct we decode opaquely? Either the bare `tuple`
/// placeholder or an expanded canonical struct type like
/// `(bytes32,bytes,bytes,uint256,uint256,uint256)`. The expanded form is what
/// makes the selector come out right (a struct param's selector uses the
/// expanded tuple, not the literal word `tuple`).
fn is_tuple(ty: &str) -> bool {
    ty == "tuple" || ty == "tuple[]" || ty.starts_with('(')
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CalldataError {
    #[error("calldata too short: need ≥4 selector bytes, got {0}")]
    TooShort(usize),

    #[error("unknown selector 0x{0}: not a stage-1 AgentKeys contract function")]
    UnknownSelector(String),

    #[error("malformed hex: {0}")]
    Hex(String),

    #[error("truncated calldata: arg '{0}' word out of range")]
    Truncated(String),
}

/// One parameter of a registered function: ABI type + the ABI param name.
#[derive(Debug, Clone, Copy)]
pub struct Param {
    pub name: &'static str,
    pub ty: &'static str,
}

/// A function the audit view can encounter on-chain. The `signature` is derived
/// from `name` + the param types, so it never drifts from `params`.
#[derive(Debug, Clone, Copy)]
pub struct FnDef {
    pub contract: &'static str,
    pub name: &'static str,
    pub params: &'static [Param],
}

impl FnDef {
    /// Canonical Solidity signature, e.g. `appendRoot(bytes32,bytes32,uint64)`.
    pub fn signature(&self) -> String {
        let types: Vec<&str> = self.params.iter().map(|p| p.ty).collect();
        format!("{}({})", self.name, types.join(","))
    }

    pub fn selector(&self) -> [u8; 4] {
        selector(&self.signature())
    }
}

macro_rules! params {
    ($(($n:literal, $t:literal)),* $(,)?) => {
        &[$(Param { name: $n, ty: $t }),*]
    };
}

/// The audit-relevant functions of the four deployed stage-1 contracts. Param
/// names + types mirror `crates/agentkeys-chain/out/<C>.sol/<C>.json` exactly;
/// `selector_matches_cast_ground_truth` pins the derived selectors.
pub const REGISTRY: &[FnDef] = &[
    // ── CredentialAudit ──────────────────────────────────────────────
    FnDef {
        contract: "CredentialAudit",
        name: "append",
        params: params![
            ("operatorOmni", "bytes32"),
            ("actorOmni", "bytes32"),
            ("serviceHash", "bytes32"),
            ("opType", "uint8"),
            ("payloadHash", "bytes32"),
        ],
    },
    FnDef {
        contract: "CredentialAudit",
        name: "appendV2",
        params: params![
            ("operatorOmni", "bytes32"),
            ("actorOmni", "bytes32"),
            ("opKind", "uint8"),
            ("envelopeHash", "bytes32"),
        ],
    },
    FnDef {
        contract: "CredentialAudit",
        name: "appendRoot",
        params: params![
            ("operatorOmni", "bytes32"),
            ("merkleRoot", "bytes32"),
            ("batchEntryCount", "uint64"),
        ],
    },
    FnDef {
        contract: "CredentialAudit",
        name: "appendRootV2",
        params: params![
            ("operatorOmni", "bytes32"),
            ("merkleRoot", "bytes32"),
            ("opKindBitmap", "bytes32"),
            ("batchEntryCount", "uint64"),
        ],
    },
    // ── SidecarRegistry ──────────────────────────────────────────────
    FnDef {
        contract: "SidecarRegistry",
        name: "registerAgentDevice",
        params: params![
            ("deviceKeyHash", "bytes32"),
            ("operatorOmni", "bytes32"),
            ("actorOmni", "bytes32"),
            ("linkCodeRedemption", "bytes"),
            ("agentPopSig", "bytes"),
        ],
    },
    // #427: the slot-consuming delegate-spawn entrypoint (same shape as the
    // device leg; only the selector differs — 0xf3a09c45).
    FnDef {
        contract: "SidecarRegistry",
        name: "registerDelegate",
        params: params![
            ("deviceKeyHash", "bytes32"),
            ("operatorOmni", "bytes32"),
            ("actorOmni", "bytes32"),
            ("linkCodeRedemption", "bytes"),
            ("agentPopSig", "bytes"),
        ],
    },
    FnDef {
        contract: "SidecarRegistry",
        name: "revokeAgentDevice",
        params: params![("deviceKeyHash", "bytes32")],
    },
    // ── AgentKeysScope ───────────────────────────────────────────────
    FnDef {
        contract: "AgentKeysScope",
        name: "setScopeWithWebauthn",
        params: params![
            ("operatorOmni", "bytes32"),
            ("agentOmni", "bytes32"),
            ("services", "bytes32[]"),
            ("readOnly", "bool"),
            ("maxPerCall", "uint128"),
            ("maxPerPeriod", "uint128"),
            ("maxTotal", "uint128"),
            ("periodSeconds", "uint32"),
            ("assertion", "(bytes32,bytes,bytes,uint256,uint256,uint256)"),
        ],
    },
    FnDef {
        contract: "AgentKeysScope",
        name: "revokeScope",
        params: params![
            ("operatorOmni", "bytes32"),
            ("agentOmni", "bytes32"),
            ("assertion", "(bytes32,bytes,bytes,uint256,uint256,uint256)"),
        ],
    },
    // Account-auth cutover landed 2026-06-08 (#164 E3 / #225): the LIVE
    // AgentKeysScope (address in the chain profile) is now the no-tuple `setScope`
    // (sel 0xd8e9e3c6) / `revokeScope(bytes32,bytes32)` (sel 0xdcff8c5b) form
    // below — authorization moved upstream to the 4337 account's
    // validateUserOp. The pre-cutover tuple forms
    // `setScopeWithWebauthn(...,K11Assertion)` / `revokeScope(...,K11Assertion)`
    // (selectors 0x864ae93c / 0x6f37dd80) are retained here — distinct
    // selectors, no collision — ONLY so this decoder can still resolve orphaned
    // pre-cutover calldata at the old address 0xd44b375…. The daemon's LIVE
    // scope.grant mapping (audit_decode::onchain_fn) points at `setScope`.
    FnDef {
        contract: "AgentKeysScope",
        name: "setScope",
        params: params![
            ("operatorOmni", "bytes32"),
            ("agentOmni", "bytes32"),
            ("services", "bytes32[]"),
            ("readOnly", "bool"),
            ("maxPerCall", "uint128"),
            ("maxPerPeriod", "uint128"),
            ("maxTotal", "uint128"),
            ("periodSeconds", "uint32"),
        ],
    },
    FnDef {
        contract: "AgentKeysScope",
        name: "revokeScope",
        params: params![("operatorOmni", "bytes32"), ("agentOmni", "bytes32")],
    },
    // ── K3EpochCounter ───────────────────────────────────────────────
    FnDef {
        contract: "K3EpochCounter",
        name: "advanceEpoch",
        params: params![],
    },
];

/// Look up a registered function by its 4-byte selector.
pub fn lookup(sel: &[u8; 4]) -> Option<&'static FnDef> {
    REGISTRY.iter().find(|f| &f.selector() == sel)
}

/// One decoded argument: ABI name + type + the decoded JSON value. Dynamic
/// values render as `0x…` hex (bytes) or arrays; small ints as JSON numbers,
/// wide ints as decimal strings (JS-safe).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DecodedArg {
    pub name: String,
    pub ty: String,
    pub value: Value,
}

/// The result of decoding one transaction's calldata.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DecodedCall {
    pub contract: String,
    pub function: String,
    pub signature: String,
    pub selector: String,
    pub args: Vec<DecodedArg>,
    /// Set when some args could not be decoded (e.g. a trailing `tuple`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Decode `0x`-prefixed (or bare) hex calldata.
pub fn decode_calldata_hex(calldata_hex: &str) -> Result<DecodedCall, CalldataError> {
    let trimmed = calldata_hex
        .trim()
        .strip_prefix("0x")
        .unwrap_or(calldata_hex);
    let bytes = hex::decode(trimmed).map_err(|e| CalldataError::Hex(e.to_string()))?;
    decode_calldata(&bytes)
}

/// Decode raw calldata: `selector(4) || head/tail-encoded args`.
pub fn decode_calldata(calldata: &[u8]) -> Result<DecodedCall, CalldataError> {
    if calldata.len() < 4 {
        return Err(CalldataError::TooShort(calldata.len()));
    }
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&calldata[..4]);
    let def = lookup(&sel).ok_or_else(|| CalldataError::UnknownSelector(hex::encode(sel)))?;

    let args_region = &calldata[4..];
    let mut args = Vec::with_capacity(def.params.len());
    let mut note: Option<String> = None;

    for (i, param) in def.params.iter().enumerate() {
        let head_at = i * 32;
        let head = read_word(args_region, head_at)
            .ok_or_else(|| CalldataError::Truncated(param.name.to_string()))?;

        let value = match param.ty {
            t if is_tuple(t) => {
                note.get_or_insert_with(|| {
                    "tuple args (WebAuthn assertion) shown raw — not ABI-expanded".to_string()
                });
                Value::Null
            }
            "bytes" => decode_dynamic_bytes(args_region, &head)?,
            "bytes32[]" => decode_bytes32_array(args_region, &head)?,
            "bool" => Value::Bool(word_is_nonzero(&head)),
            "address" => Value::String(format!("0x{}", hex::encode(&head[12..32]))),
            "bytes32" => Value::String(format!("0x{}", hex::encode(head))),
            t if t.starts_with("uint") => word_to_uint_value(&head),
            _ => {
                note.get_or_insert_with(|| format!("unsupported arg type '{}'", param.ty));
                Value::String(format!("0x{}", hex::encode(head)))
            }
        };

        args.push(DecodedArg {
            name: param.name.to_string(),
            ty: param.ty.to_string(),
            value,
        });
    }

    Ok(DecodedCall {
        contract: def.contract.to_string(),
        function: def.name.to_string(),
        signature: def.signature(),
        selector: format!("0x{}", hex::encode(sel)),
        args,
        note,
    })
}

/// Encode a registered call into calldata: `selector || head/tail args`. The
/// inverse of [`decode_calldata`] — the daemon uses it to build the exact
/// on-chain calldata for an audit action so the decode endpoint genuinely
/// round-trips real bytes (#153) rather than fabricating a decoded view.
///
/// `args` must match `def.params` in order, each value shaped like
/// [`decode_calldata`]'s output: `bytes32`/`address`/`bytes` as `0x` hex,
/// `uintN` as a JSON number or decimal string, `bool` as a JSON bool,
/// `bytes32[]` as an array of hex strings. A `tuple` param consumes one zero
/// head word (the daemon never submits a decoded tuple; the decoder notes it).
pub fn encode_calldata(def: &FnDef, args: &[Value]) -> Result<Vec<u8>, CalldataError> {
    if args.len() != def.params.len() {
        return Err(CalldataError::Hex(format!(
            "expected {} args, got {}",
            def.params.len(),
            args.len()
        )));
    }
    let head_len = def.params.len() * 32;
    let mut head: Vec<u8> = Vec::with_capacity(head_len);
    let mut tail: Vec<u8> = Vec::new();

    for (param, value) in def.params.iter().zip(args) {
        match param.ty {
            t if is_tuple(t) => head.extend_from_slice(&[0u8; 32]),
            "bytes" => {
                head.extend_from_slice(&usize_word(head_len + tail.len()));
                let raw = hex_arg(value, param.name)?;
                tail.extend_from_slice(&usize_word(raw.len()));
                tail.extend_from_slice(&raw);
                let pad = (32 - tail.len() % 32) % 32; // right-pad to a 32-byte boundary
                tail.resize(tail.len() + pad, 0);
            }
            "bytes32[]" => {
                head.extend_from_slice(&usize_word(head_len + tail.len()));
                let arr = value
                    .as_array()
                    .ok_or_else(|| CalldataError::Hex(format!("{} expects array", param.name)))?;
                tail.extend_from_slice(&usize_word(arr.len()));
                for elem in arr {
                    tail.extend_from_slice(&bytes32_word(elem, param.name)?);
                }
            }
            "bool" => head.extend_from_slice(&usize_word(if value.as_bool().unwrap_or(false) {
                1
            } else {
                0
            })),
            "address" => head.extend_from_slice(&address_word(value, param.name)?),
            "bytes32" => head.extend_from_slice(&bytes32_word(value, param.name)?),
            t if t.starts_with("uint") => head.extend_from_slice(&uint_word(value, param.name)?),
            other => return Err(CalldataError::Hex(format!("cannot encode type '{other}'"))),
        }
    }

    let mut out = Vec::with_capacity(4 + head.len() + tail.len());
    out.extend_from_slice(&def.selector());
    out.extend_from_slice(&head);
    out.extend_from_slice(&tail);
    Ok(out)
}

fn usize_word(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&(n as u64).to_be_bytes());
    w
}

fn hex_arg(v: &Value, name: &str) -> Result<Vec<u8>, CalldataError> {
    let s = v
        .as_str()
        .ok_or_else(|| CalldataError::Hex(format!("{name} expects hex string")))?;
    let t = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(t).map_err(|e| CalldataError::Hex(format!("{name}: {e}")))
}

fn bytes32_word(v: &Value, name: &str) -> Result<[u8; 32], CalldataError> {
    let raw = hex_arg(v, name)?;
    if raw.len() > 32 {
        return Err(CalldataError::Hex(format!("{name}: bytes32 > 32 bytes")));
    }
    let mut w = [0u8; 32];
    w[..raw.len()].copy_from_slice(&raw); // bytes32 is left-aligned
    Ok(w)
}

fn address_word(v: &Value, name: &str) -> Result<[u8; 32], CalldataError> {
    let raw = hex_arg(v, name)?;
    if raw.len() > 20 {
        return Err(CalldataError::Hex(format!("{name}: address > 20 bytes")));
    }
    let mut w = [0u8; 32];
    w[32 - raw.len()..].copy_from_slice(&raw); // address is right-aligned
    Ok(w)
}

fn uint_word(v: &Value, name: &str) -> Result<[u8; 32], CalldataError> {
    let n: u128 = match v {
        Value::Number(num) => num.as_u64().map(u128::from).ok_or_else(|| {
            CalldataError::Hex(format!("{name}: uint not a non-negative integer"))
        })?,
        Value::String(s) => s
            .parse::<u128>()
            .map_err(|e| CalldataError::Hex(format!("{name}: {e}")))?,
        _ => {
            return Err(CalldataError::Hex(format!(
                "{name}: uint expects number/string"
            )))
        }
    };
    let mut w = [0u8; 32];
    w[16..32].copy_from_slice(&n.to_be_bytes());
    Ok(w)
}

/// Read the 32-byte word at `offset` from `data`, or `None` if out of range.
pub(crate) fn read_word(data: &[u8], offset: usize) -> Option<[u8; 32]> {
    let end = offset.checked_add(32)?;
    if end > data.len() {
        return None;
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&data[offset..end]);
    Some(w)
}

fn word_is_nonzero(word: &[u8; 32]) -> bool {
    word.iter().any(|&b| b != 0)
}

/// Decode an unsigned int word: small values (fit u64) as a JSON number, wider
/// values (fit u128) as a decimal string, anything larger as `0x…` hex —
/// always JS-precision-safe.
fn word_to_uint_value(word: &[u8; 32]) -> Value {
    if word[..16].iter().all(|&b| b == 0) {
        let mut low = [0u8; 16];
        low.copy_from_slice(&word[16..32]);
        let n = u128::from_be_bytes(low);
        if n <= u64::MAX as u128 {
            return json!(n as u64);
        }
        return Value::String(n.to_string());
    }
    Value::String(format!("0x{}", hex::encode(word)))
}

/// `head` is a 32-byte offset (from the start of the args region) to a dynamic
/// `bytes`: `[len word][len bytes…]`.
fn decode_dynamic_bytes(args: &[u8], head: &[u8; 32]) -> Result<Value, CalldataError> {
    let off = word_to_usize(head).ok_or_else(|| CalldataError::Truncated("bytes.offset".into()))?;
    let len_word =
        read_word(args, off).ok_or_else(|| CalldataError::Truncated("bytes.len".into()))?;
    let len =
        word_to_usize(&len_word).ok_or_else(|| CalldataError::Truncated("bytes.len".into()))?;
    let start = off + 32;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= args.len())
        .ok_or_else(|| CalldataError::Truncated("bytes.body".into()))?;
    Ok(Value::String(format!(
        "0x{}",
        hex::encode(&args[start..end])
    )))
}

/// `head` is a 32-byte offset to a `bytes32[]`: `[count word][count × 32-byte words]`.
fn decode_bytes32_array(args: &[u8], head: &[u8; 32]) -> Result<Value, CalldataError> {
    let off =
        word_to_usize(head).ok_or_else(|| CalldataError::Truncated("bytes32[].offset".into()))?;
    let count_word =
        read_word(args, off).ok_or_else(|| CalldataError::Truncated("bytes32[].len".into()))?;
    let count = word_to_usize(&count_word)
        .ok_or_else(|| CalldataError::Truncated("bytes32[].len".into()))?;
    // Bound the whole array body BEFORE allocating — a crafted length word
    // (e.g. 0xffff…) must not drive a huge `Vec::with_capacity` / OOM before
    // we've confirmed the elements actually exist in the calldata.
    let end = off
        .checked_add(32)
        .and_then(|v| count.checked_mul(32).and_then(|n| v.checked_add(n)))
        .ok_or_else(|| CalldataError::Truncated("bytes32[].size-overflow".into()))?;
    if end > args.len() {
        return Err(CalldataError::Truncated("bytes32[].body".into()));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = off + 32 + i * 32;
        let w =
            read_word(args, at).ok_or_else(|| CalldataError::Truncated("bytes32[].elem".into()))?;
        out.push(Value::String(format!("0x{}", hex::encode(w))));
    }
    Ok(Value::Array(out))
}

/// Interpret a 32-byte word as a usize offset/length; `None` if it exceeds usize.
pub(crate) fn word_to_usize(word: &[u8; 32]) -> Option<usize> {
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&word[24..32]);
    usize::try_from(u64::from_be_bytes(low)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derived selectors MUST match `cast sig`-computed ground truth (run
    /// 2026-06-04 against the committed ABIs). If a contract ABI changes, this
    /// table must be updated in lockstep — that's the point of the pin.
    #[test]
    fn selector_matches_cast_ground_truth() {
        let ground: &[(&str, &str)] = &[
            ("append(bytes32,bytes32,bytes32,uint8,bytes32)", "0xc1bf0e32"),
            ("appendV2(bytes32,bytes32,uint8,bytes32)", "0x1a213f0e"),
            ("appendRoot(bytes32,bytes32,uint64)", "0x28d3a294"),
            ("appendRootV2(bytes32,bytes32,bytes32,uint64)", "0xbcfe3f8d"),
            ("registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)", "0x9847ca95"),
            // #427 delegate-spawn entrypoint (cast sig, 2026-07-12).
            ("registerDelegate(bytes32,bytes32,bytes32,bytes,bytes)", "0xf3a09c45"),
            ("revokeAgentDevice(bytes32)", "0xb269f9fb"),
            // DEPLOYED stage-1 scope forms — struct param expands in the
            // selector (verified present in mainnet bytecode at 0xd44b375…).
            (
                "setScopeWithWebauthn(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32,(bytes32,bytes,bytes,uint256,uint256,uint256))",
                "0x864ae93c",
            ),
            (
                "revokeScope(bytes32,bytes32,(bytes32,bytes,bytes,uint256,uint256,uint256))",
                "0x6f37dd80",
            ),
            // current-source (#164, post-redeploy) scope forms — forward-compat
            (
                "setScope(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32)",
                "0xd8e9e3c6",
            ),
            ("revokeScope(bytes32,bytes32)", "0xdcff8c5b"),
            ("advanceEpoch()", "0x3cf80e6c"),
        ];
        for (sig, want) in ground {
            assert_eq!(&selector_hex(sig), want, "selector drift for {sig}");
        }
    }

    /// Every REGISTRY entry's derived signature must round-trip through the
    /// selector lookup — guards against a name/param edit that desyncs.
    #[test]
    fn every_registry_fn_is_self_consistent() {
        for f in REGISTRY {
            let sel = f.selector();
            let found = lookup(&sel).expect("registry fn must look up by its own selector");
            assert_eq!(found.name, f.name);
            assert_eq!(found.contract, f.contract);
        }
    }

    fn word32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn decodes_append_root_all_static() {
        // appendRoot(operatorOmni, merkleRoot, batchEntryCount=7)
        let mut cd = String::from("0x28d3a294");
        cd.push_str(&word32(0xaa)); // operatorOmni
        cd.push_str(&word32(0xbb)); // merkleRoot
        cd.push_str(&format!("{:064x}", 7u64)); // batchEntryCount
        let dec = decode_calldata_hex(&cd).unwrap();
        assert_eq!(dec.contract, "CredentialAudit");
        assert_eq!(dec.function, "appendRoot");
        assert_eq!(dec.selector, "0x28d3a294");
        assert_eq!(dec.args.len(), 3);
        assert_eq!(dec.args[0].value, json!(format!("0x{}", word32(0xaa))));
        assert_eq!(dec.args[2].name, "batchEntryCount");
        assert_eq!(dec.args[2].value, json!(7u64));
        assert!(dec.note.is_none());
    }

    #[test]
    fn decodes_append_with_uint8() {
        // append(op, actor, service, opType=2, payloadHash)
        let mut cd = String::from("0xc1bf0e32");
        cd.push_str(&word32(0x11));
        cd.push_str(&word32(0x22));
        cd.push_str(&word32(0x33));
        cd.push_str(&format!("{:064x}", 2u8));
        cd.push_str(&word32(0x44));
        let dec = decode_calldata_hex(&cd).unwrap();
        assert_eq!(dec.function, "append");
        assert_eq!(dec.args[3].name, "opType");
        assert_eq!(dec.args[3].value, json!(2u64));
        assert_eq!(dec.args[4].value, json!(format!("0x{}", word32(0x44))));
    }

    #[test]
    fn decodes_register_agent_device_with_trailing_dynamic_bytes() {
        // registerAgentDevice(deviceKeyHash, operatorOmni, actorOmni, linkCodeRedemption, agentPopSig)
        // 3 static bytes32 + 2 dynamic bytes. Build head/tail by hand.
        let link = vec![0xde, 0xad, 0xbe, 0xef];
        let pop = vec![0x01, 0x02];
        // head: 3 words (static) + 2 offset words = 5 words = 160 bytes
        let off_link = 160usize; // tail starts right after head
                                 // link tail = len word + padded data (1 word)
        let link_tail_len = 32 + 32;
        let off_pop = off_link + link_tail_len;

        let mut cd = String::from("0x9847ca95");
        cd.push_str(&word32(0x01)); // deviceKeyHash
        cd.push_str(&word32(0x02)); // operatorOmni
        cd.push_str(&word32(0x03)); // actorOmni
        cd.push_str(&format!("{off_link:064x}"));
        cd.push_str(&format!("{off_pop:064x}"));
        // link tail
        cd.push_str(&format!("{:064x}", link.len()));
        cd.push_str(&format!("{:0<64}", hex::encode(&link)));
        // pop tail
        cd.push_str(&format!("{:064x}", pop.len()));
        cd.push_str(&format!("{:0<64}", hex::encode(&pop)));

        let dec = decode_calldata_hex(&cd).unwrap();
        assert_eq!(dec.function, "registerAgentDevice");
        assert_eq!(dec.args[3].name, "linkCodeRedemption");
        assert_eq!(dec.args[3].value, json!("0xdeadbeef"));
        assert_eq!(dec.args[4].value, json!("0x0102"));
        assert!(dec.note.is_none());
    }

    #[test]
    fn tuple_arg_is_noted_not_guessed() {
        // setScopeWithWebauthn (deployed selector 0x864ae93c): decode leading
        // static args, note the K11Assertion tuple.
        let mut cd = String::from("0x864ae93c");
        cd.push_str(&word32(0xaa)); // operatorOmni
        cd.push_str(&word32(0xbb)); // agentOmni
        cd.push_str(&format!("{:064x}", 0x120u64)); // services offset (unused in assert)
        cd.push_str(&format!("{:064x}", 1u64)); // readOnly = true
        cd.push_str(&format!("{:064x}", 5u64)); // maxPerCall
        cd.push_str(&format!("{:064x}", 6u64)); // maxPerPeriod
        cd.push_str(&format!("{:064x}", 7u64)); // maxTotal
        cd.push_str(&format!("{:064x}", 86400u64)); // periodSeconds
        cd.push_str(&word32(0x00)); // assertion (tuple) head slot
                                    // services tail at 0x120 (offset within args region): count=0
                                    // pad up to offset 0x120 = 288 bytes from args start; we have 9 words = 288. good.
        cd.push_str(&format!("{:064x}", 0u64)); // services count = 0
        let dec = decode_calldata_hex(&cd).unwrap();
        assert_eq!(dec.function, "setScopeWithWebauthn");
        assert_eq!(dec.args[3].name, "readOnly");
        assert_eq!(dec.args[3].value, json!(true));
        assert_eq!(dec.args[7].value, json!(86400u64));
        assert_eq!(dec.args[2].value, json!([])); // empty services array
        assert!(dec.note.is_some(), "tuple must be noted");
        assert_eq!(dec.args[8].value, Value::Null);
    }

    #[test]
    fn unknown_selector_errors() {
        let err = decode_calldata_hex("0xdeadbeef").unwrap_err();
        assert!(matches!(err, CalldataError::UnknownSelector(_)));
    }

    #[test]
    fn too_short_errors() {
        let err = decode_calldata_hex("0xc1bf").unwrap_err();
        assert!(matches!(err, CalldataError::TooShort(_)));
    }

    /// codex review #153: a crafted `bytes32[]` length word must NOT drive a
    /// giant Vec::with_capacity / OOM. It must error (Truncated), not panic.
    /// Uses `setScope` (8 static-head params; head = 256 bytes = 0x100) so the
    /// `services` offset cleanly points at the crafted length word.
    fn craft_setscope_with_services_len(len_word_hex: &str) -> String {
        let mut cd = String::from("0xd8e9e3c6"); // setScope selector
        cd.push_str(&word32(0xaa)); // operatorOmni
        cd.push_str(&word32(0xbb)); // agentOmni
        cd.push_str(&format!("{:064x}", 0x100u64)); // services offset = end of head
        for _ in 0..5 {
            cd.push_str(&format!("{:064x}", 0u64)); // readOnly..periodSeconds
        }
        cd.push_str(len_word_hex); // services length word; no elements follow
        cd
    }

    #[test]
    fn bytes32_array_with_huge_count_errors_not_ooms() {
        // (a) length = 2^256-1 → exceeds usize → Truncated (word_to_usize None).
        let err =
            decode_calldata_hex(&craft_setscope_with_services_len(&"f".repeat(64))).unwrap_err();
        assert!(matches!(err, CalldataError::Truncated(_)), "got {err:?}");

        // (b) length fits usize (65536) but no body → the new bounds guard must
        // reject BEFORE Vec::with_capacity allocates ~2MB.
        let err = decode_calldata_hex(&craft_setscope_with_services_len(&format!(
            "{:064x}",
            0x10000u64
        )))
        .unwrap_err();
        assert!(matches!(err, CalldataError::Truncated(_)), "got {err:?}");
    }

    #[test]
    fn both_scope_abi_forms_are_registered() {
        // The deployed (tuple) form and the current-source (no-tuple) form
        // must both resolve — distinct selectors, no collision.
        let deployed = lookup(&selector(
            "setScopeWithWebauthn(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32,(bytes32,bytes,bytes,uint256,uint256,uint256))",
        ));
        let current = lookup(&selector(
            "setScope(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32)",
        ));
        assert_eq!(deployed.map(|f| f.name), Some("setScopeWithWebauthn"));
        assert_eq!(current.map(|f| f.name), Some("setScope"));
        assert_eq!(
            lookup(&selector("revokeScope(bytes32,bytes32)")).map(|f| f.params.len()),
            Some(2)
        );
    }

    /// encode_calldata is the exact inverse of decode_calldata for every shape
    /// the daemon emits — static words, trailing dynamic `bytes`, and a dynamic
    /// `bytes32[]` ahead of a trailing tuple. This is what lets the decode
    /// endpoint round-trip real bytes instead of fabricating a decoded view.
    #[test]
    fn encode_then_decode_round_trips() {
        let h = |b: u8| json!(format!("0x{}", hex::encode([b; 32])));

        // append — all static
        let append = lookup(&selector("append(bytes32,bytes32,bytes32,uint8,bytes32)")).unwrap();
        let in_args = vec![h(0x11), h(0x22), h(0x33), json!(2u64), h(0x44)];
        let cd = encode_calldata(append, &in_args).unwrap();
        let dec = decode_calldata(&cd).unwrap();
        assert_eq!(dec.function, "append");
        let got: Vec<Value> = dec.args.iter().map(|a| a.value.clone()).collect();
        assert_eq!(got, in_args);

        // registerAgentDevice — 3 static + 2 dynamic bytes
        let reg = lookup(&selector(
            "registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)",
        ))
        .unwrap();
        let reg_args = vec![
            h(0x01),
            h(0x02),
            h(0x03),
            json!("0xdeadbeef"),
            json!("0x0102"),
        ];
        let cd = encode_calldata(reg, &reg_args).unwrap();
        let dec = decode_calldata(&cd).unwrap();
        let got: Vec<Value> = dec.args.iter().map(|a| a.value.clone()).collect();
        assert_eq!(got, reg_args);
        assert!(dec.note.is_none());

        // setScopeWithWebauthn — bytes32[] + statics + trailing tuple
        let scope = lookup(&selector(
            "setScopeWithWebauthn(bytes32,bytes32,bytes32[],bool,uint128,uint128,uint128,uint32,(bytes32,bytes,bytes,uint256,uint256,uint256))",
        ))
        .unwrap();
        let scope_args = vec![
            h(0xaa),
            h(0xbb),
            json!([format!("0x{}", hex::encode([0xc1; 32]))]),
            json!(true),
            json!(5u64),
            json!(6u64),
            json!(7u64),
            json!(86400u64),
            Value::Null, // tuple placeholder
        ];
        let cd = encode_calldata(scope, &scope_args).unwrap();
        let dec = decode_calldata(&cd).unwrap();
        assert_eq!(
            dec.args[2].value,
            json!([format!("0x{}", hex::encode([0xc1; 32]))])
        );
        assert_eq!(dec.args[3].value, json!(true));
        assert_eq!(dec.args[7].value, json!(86400u64));
        assert!(dec.note.is_some(), "tuple noted");
    }
}
