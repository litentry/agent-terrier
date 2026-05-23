//! EIP-712 typed-data hashing (issue #82).
//!
//! Implements the v4 EIP-712 encoding rules:
//!
//! - `digest = keccak256(0x1901 || domain_separator || hashStruct(primary_type, message))`
//! - `domain_separator = hashStruct("EIP712Domain", domain)`
//! - `hashStruct(type, value) = keccak256(typeHash(type) || encodeData(type, value))`
//! - `typeHash(type) = keccak256(encodeType(type))`
//! - `encodeType` = `"<primary>(<fields>)" || dependencies sorted alphabetically by type name`
//!
//! See <https://eips.ethereum.org/EIPS/eip-712> for the canonical spec.
//!
//! ## Supported type-string subset (v0)
//!
//! - `string`, `bytes`, `bool`, `address`
//! - All `uint{8,16,...,256}` (8-bit increments)
//! - All `int{8,16,...,256}` (8-bit increments)
//! - All `bytes{1,2,...,32}` (fixed-byte)
//! - Dynamic arrays `T[]` and fixed arrays `T[N]` of any of the above (including structs)
//! - Nested struct types defined in `types`
//!
//! Anything outside this subset raises `Eip712Error::UnsupportedType`. The
//! signer MUST refuse to sign a typed-data value with an unsupported type
//! rather than silently produce a hash the operator did not understand.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Eip712Error {
    #[error("invalid_typed_data: missing field {0}")]
    MissingField(&'static str),

    #[error("invalid_typed_data: types must contain EIP712Domain")]
    MissingDomainType,

    #[error("invalid_typed_data: primaryType '{0}' not declared in types")]
    UnknownPrimaryType(String),

    #[error("invalid_typed_data: type '{0}' referenced but not declared in types")]
    UnknownType(String),

    #[error("invalid_typed_data: unsupported type-string '{0}' (issue #82 v0 subset)")]
    UnsupportedType(String),

    #[error("invalid_typed_data: field '{field}' expects {expected}, got {got}")]
    FieldTypeMismatch {
        field: String,
        expected: String,
        got: String,
    },

    #[error("invalid_typed_data: integer '{0}' out of range for type {1}")]
    IntegerOutOfRange(String, String),

    #[error("invalid_typed_data: invalid hex in field '{field}': {reason}")]
    InvalidHex { field: String, reason: String },

    #[error(
        "invalid_typed_data: array '{field}' length {got} does not match fixed size {expected}"
    )]
    ArrayLengthMismatch {
        field: String,
        expected: usize,
        got: usize,
    },

    #[error("invalid_typed_data: cyclic type dependency through '{0}'")]
    CyclicType(String),
}

/// Field declaration inside a type definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

/// Full EIP-712 v4 typed-data payload. Matches the canonical JSON shape
/// (`MetaMask eth_signTypedData_v4`, `viem.signTypedData`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedData {
    pub domain: serde_json::Value,
    pub types: BTreeMap<String, Vec<TypeField>>,
    #[serde(rename = "primaryType")]
    pub primary_type: String,
    pub message: serde_json::Value,
}

/// Computed digests returned alongside the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip712Digests {
    pub domain_separator: [u8; 32],
    pub primary_type_hash: [u8; 32],
    pub message_hash: [u8; 32],
    pub final_digest: [u8; 32],
}

/// Compute every digest needed to sign + audit a typed-data value.
pub fn compute_digests(td: &TypedData) -> Result<Eip712Digests, Eip712Error> {
    if !td.types.contains_key("EIP712Domain") {
        return Err(Eip712Error::MissingDomainType);
    }
    if !td.types.contains_key(&td.primary_type) {
        return Err(Eip712Error::UnknownPrimaryType(td.primary_type.clone()));
    }

    let domain_separator = hash_struct(&td.types, "EIP712Domain", &td.domain)?;
    let primary_type_hash = type_hash(&td.types, &td.primary_type)?;
    let message_hash = hash_struct(&td.types, &td.primary_type, &td.message)?;

    let mut hasher = Keccak256::new();
    hasher.update([0x19, 0x01]);
    hasher.update(domain_separator);
    hasher.update(message_hash);
    let final_digest: [u8; 32] = hasher.finalize().into();

    Ok(Eip712Digests {
        domain_separator,
        primary_type_hash,
        message_hash,
        final_digest,
    })
}

/// `typeHash(type)` = `keccak256(encodeType(type))`.
pub fn type_hash(
    types: &BTreeMap<String, Vec<TypeField>>,
    type_name: &str,
) -> Result<[u8; 32], Eip712Error> {
    let encoded = encode_type(types, type_name)?;
    Ok(keccak(encoded.as_bytes()))
}

/// `encodeType("Mail")` →
/// `"Mail(Person from,Person to,string contents)Person(string name,address wallet)"`.
///
/// Dependencies are listed in alphabetical order by struct name. The primary
/// type itself comes first regardless of alphabetical order.
pub fn encode_type(
    types: &BTreeMap<String, Vec<TypeField>>,
    primary: &str,
) -> Result<String, Eip712Error> {
    let mut deps = BTreeSet::new();
    collect_dependencies(types, primary, &mut deps, &mut BTreeSet::new())?;
    deps.remove(primary);

    let mut out = String::new();
    out.push_str(&encode_one_type(types, primary)?);
    for dep in &deps {
        out.push_str(&encode_one_type(types, dep)?);
    }
    Ok(out)
}

fn encode_one_type(
    types: &BTreeMap<String, Vec<TypeField>>,
    name: &str,
) -> Result<String, Eip712Error> {
    let fields = types
        .get(name)
        .ok_or_else(|| Eip712Error::UnknownType(name.to_string()))?;
    let mut out = String::from(name);
    out.push('(');
    let body = fields
        .iter()
        .map(|f| format!("{} {}", f.ty, f.name))
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&body);
    out.push(')');
    Ok(out)
}

fn collect_dependencies(
    types: &BTreeMap<String, Vec<TypeField>>,
    name: &str,
    out: &mut BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) -> Result<(), Eip712Error> {
    if visiting.contains(name) {
        return Err(Eip712Error::CyclicType(name.to_string()));
    }
    if out.contains(name) {
        return Ok(());
    }
    visiting.insert(name.to_string());
    let fields = types
        .get(name)
        .ok_or_else(|| Eip712Error::UnknownType(name.to_string()))?;
    for f in fields {
        let base = strip_array_suffix(&f.ty);
        if types.contains_key(base) {
            collect_dependencies(types, base, out, visiting)?;
        }
    }
    visiting.remove(name);
    out.insert(name.to_string());
    Ok(())
}

/// Strip the outermost `[N]` or `[]` suffix from a type string. `"uint256[2][]"`
/// → `"uint256[2]"`, `"Person[]"` → `"Person"`, `"uint256"` → `"uint256"`.
fn strip_array_suffix(ty: &str) -> &str {
    if let Some(stripped) = ty.strip_suffix(']') {
        if let Some(bracket_open) = stripped.rfind('[') {
            return &ty[..bracket_open];
        }
    }
    ty
}

/// `hashStruct(type, value) = keccak256(typeHash(type) || encodeData(type, value))`.
pub fn hash_struct(
    types: &BTreeMap<String, Vec<TypeField>>,
    type_name: &str,
    value: &serde_json::Value,
) -> Result<[u8; 32], Eip712Error> {
    let th = type_hash(types, type_name)?;
    let obj = value
        .as_object()
        .ok_or_else(|| Eip712Error::FieldTypeMismatch {
            field: type_name.to_string(),
            expected: "object".to_string(),
            got: value_kind(value),
        })?;
    let fields = types
        .get(type_name)
        .ok_or_else(|| Eip712Error::UnknownType(type_name.to_string()))?;

    let mut buf = Vec::with_capacity(32 * (1 + fields.len()));
    buf.extend_from_slice(&th);
    for field in fields {
        // EIP-712 v4 + viem permit absent EIP712Domain fields: if a field is
        // declared in the type but missing from the object, treat as the
        // zero value (matches viem's behavior on optional domain fields).
        let raw = obj.get(&field.name).unwrap_or(&serde_json::Value::Null);
        let encoded = encode_data_for_field(types, &field.ty, raw, &field.name)?;
        buf.extend_from_slice(&encoded);
    }
    Ok(keccak(&buf))
}

fn encode_data_for_field(
    types: &BTreeMap<String, Vec<TypeField>>,
    ty: &str,
    value: &serde_json::Value,
    field_name: &str,
) -> Result<[u8; 32], Eip712Error> {
    // Arrays: keccak256(concat(encode_data_for_field(inner, x) for x in arr)).
    if let Some(inner_ty) = parse_array_outer(ty) {
        let arr = value
            .as_array()
            .ok_or_else(|| Eip712Error::FieldTypeMismatch {
                field: field_name.to_string(),
                expected: ty.to_string(),
                got: value_kind(value),
            })?;
        if let ArrayKind::Fixed(n) = inner_ty.kind {
            if arr.len() != n {
                return Err(Eip712Error::ArrayLengthMismatch {
                    field: field_name.to_string(),
                    expected: n,
                    got: arr.len(),
                });
            }
        }
        let mut concat = Vec::with_capacity(arr.len() * 32);
        for (i, item) in arr.iter().enumerate() {
            let sub_field = format!("{field_name}[{i}]");
            let h = encode_data_for_field(types, inner_ty.element_ty, item, &sub_field)?;
            concat.extend_from_slice(&h);
        }
        return Ok(keccak(&concat));
    }

    // Struct: hashStruct.
    if types.contains_key(ty) {
        return hash_struct(types, ty, value);
    }

    // Primitives.
    match ty {
        "bytes" => {
            let bytes = parse_hex_field(value, field_name)?;
            Ok(keccak(&bytes))
        }
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| Eip712Error::FieldTypeMismatch {
                    field: field_name.to_string(),
                    expected: "string".to_string(),
                    got: value_kind(value),
                })?;
            Ok(keccak(s.as_bytes()))
        }
        "bool" => {
            let b = value
                .as_bool()
                .ok_or_else(|| Eip712Error::FieldTypeMismatch {
                    field: field_name.to_string(),
                    expected: "bool".to_string(),
                    got: value_kind(value),
                })?;
            let mut buf = [0u8; 32];
            if b {
                buf[31] = 1;
            }
            Ok(buf)
        }
        "address" => {
            let bytes = parse_hex_field(value, field_name)?;
            if bytes.len() != 20 {
                return Err(Eip712Error::FieldTypeMismatch {
                    field: field_name.to_string(),
                    expected: "address (20 bytes)".to_string(),
                    got: format!("{} bytes", bytes.len()),
                });
            }
            let mut buf = [0u8; 32];
            buf[12..].copy_from_slice(&bytes);
            Ok(buf)
        }
        _ if ty.starts_with("uint") => {
            let bits = parse_int_bits(&ty[4..])
                .ok_or_else(|| Eip712Error::UnsupportedType(ty.to_string()))?;
            encode_uint(value, field_name, ty, bits)
        }
        _ if ty.starts_with("int") => {
            let bits = parse_int_bits(&ty[3..])
                .ok_or_else(|| Eip712Error::UnsupportedType(ty.to_string()))?;
            encode_int(value, field_name, ty, bits)
        }
        _ if ty.starts_with("bytes") => {
            let n = ty[5..]
                .parse::<usize>()
                .map_err(|_| Eip712Error::UnsupportedType(ty.to_string()))?;
            if n == 0 || n > 32 {
                return Err(Eip712Error::UnsupportedType(ty.to_string()));
            }
            let bytes = parse_hex_field(value, field_name)?;
            if bytes.len() != n {
                return Err(Eip712Error::FieldTypeMismatch {
                    field: field_name.to_string(),
                    expected: format!("bytes{n}"),
                    got: format!("{} bytes", bytes.len()),
                });
            }
            let mut buf = [0u8; 32];
            buf[..n].copy_from_slice(&bytes);
            Ok(buf)
        }
        _ => Err(Eip712Error::UnsupportedType(ty.to_string())),
    }
}

fn parse_int_bits(suffix: &str) -> Option<u32> {
    if suffix.is_empty() {
        return Some(256);
    }
    let n: u32 = suffix.parse().ok()?;
    if n == 0 || n > 256 || !n.is_multiple_of(8) {
        return None;
    }
    Some(n)
}

enum ArrayKind {
    Dynamic,
    Fixed(usize),
}

struct ArrayParse<'a> {
    element_ty: &'a str,
    kind: ArrayKind,
}

/// If `ty` ends in `[...]`, return the inner type and the kind. Returns
/// `None` for non-arrays (so the caller can fall through to primitive /
/// struct handling).
fn parse_array_outer(ty: &str) -> Option<ArrayParse<'_>> {
    let stripped = ty.strip_suffix(']')?;
    let bracket_open = stripped.rfind('[')?;
    let inside = &ty[bracket_open + 1..ty.len() - 1];
    let kind = if inside.is_empty() {
        ArrayKind::Dynamic
    } else {
        ArrayKind::Fixed(inside.parse().ok()?)
    };
    Some(ArrayParse {
        element_ty: &ty[..bracket_open],
        kind,
    })
}

fn encode_uint(
    value: &serde_json::Value,
    field_name: &str,
    ty: &str,
    bits: u32,
) -> Result<[u8; 32], Eip712Error> {
    let s = number_or_string(value, field_name, ty)?;
    let big = parse_uint_string(&s)
        .ok_or_else(|| Eip712Error::IntegerOutOfRange(s.clone(), ty.to_string()))?;
    if bits < 256 {
        let max = U256::ONE.shl(bits as usize);
        if big >= max {
            return Err(Eip712Error::IntegerOutOfRange(s, ty.to_string()));
        }
    }
    Ok(big.to_be_bytes())
}

fn encode_int(
    value: &serde_json::Value,
    field_name: &str,
    ty: &str,
    bits: u32,
) -> Result<[u8; 32], Eip712Error> {
    let s = number_or_string(value, field_name, ty)?;
    let (neg, magnitude) = match s.strip_prefix('-') {
        Some(rest) => (true, rest.to_string()),
        None => (false, s.clone()),
    };
    let mag = parse_uint_string(&magnitude)
        .ok_or_else(|| Eip712Error::IntegerOutOfRange(s.clone(), ty.to_string()))?;
    // Range check: for intN, magnitude must fit in (N-1) bits when positive
    // (i.e. mag < 2^(N-1)) and ≤ 2^(N-1) when negative (covers int's
    // asymmetric range: [-2^(N-1), 2^(N-1) - 1]).
    //
    // The pos_max boundary 2^(N-1) fits in our U256 (which holds 256
    // bits) for every supported N from 8 to 256 — including int256,
    // where pos_max = 2^255 is exactly representable. Codex P2 review on
    // PR #95 caught the earlier `if bits < 256` guard that skipped the
    // range check for int256 entirely — letting values >= 2^255 wrap
    // silently into negative two's-complement.
    let pos_max = U256::ONE.shl((bits - 1) as usize);
    if neg {
        if mag > pos_max {
            return Err(Eip712Error::IntegerOutOfRange(s, ty.to_string()));
        }
    } else if mag >= pos_max {
        return Err(Eip712Error::IntegerOutOfRange(s, ty.to_string()));
    }
    let encoded = if neg { mag.neg_twos_complement() } else { mag };
    Ok(encoded.to_be_bytes())
}

fn number_or_string(
    value: &serde_json::Value,
    field_name: &str,
    ty: &str,
) -> Result<String, Eip712Error> {
    if let Some(s) = value.as_str() {
        return Ok(s.to_string());
    }
    if let Some(n) = value.as_u64() {
        return Ok(n.to_string());
    }
    if let Some(n) = value.as_i64() {
        return Ok(n.to_string());
    }
    Err(Eip712Error::FieldTypeMismatch {
        field: field_name.to_string(),
        expected: ty.to_string(),
        got: value_kind(value),
    })
}

fn parse_uint_string(s: &str) -> Option<U256> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return U256::from_hex(hex);
    }
    U256::from_dec(s)
}

fn parse_hex_field(value: &serde_json::Value, field_name: &str) -> Result<Vec<u8>, Eip712Error> {
    let s = value
        .as_str()
        .ok_or_else(|| Eip712Error::FieldTypeMismatch {
            field: field_name.to_string(),
            expected: "0x-prefixed hex string".to_string(),
            got: value_kind(value),
        })?;
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(stripped).map_err(|e| Eip712Error::InvalidHex {
        field: field_name.to_string(),
        reason: e.to_string(),
    })
}

fn value_kind(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
    .to_string()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

// ============================================================================
// U256 — minimal big-integer needed for EIP-712 encoding.
//
// We carry exactly 256 bits as four big-endian-ordered `u64` limbs. The
// supported ops are: parse-from-decimal, parse-from-hex, compare, shift-left
// by a fixed bit count, and two's-complement negation. That's the entire
// surface EIP-712 encoding needs. Pulling in `primitive-types` / `ethnum`
// would bloat the dep tree for no functional gain.
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct U256 {
    limbs: [u64; 4], // limbs[0] = most-significant
}

impl U256 {
    const ZERO: Self = Self { limbs: [0; 4] };
    const ONE: Self = Self {
        limbs: [0, 0, 0, 1],
    };

    fn from_dec(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        let mut out = Self::ZERO;
        for c in s.chars() {
            let d = c.to_digit(10)?;
            out = out.mul_small(10)?;
            out = out.add_small(d as u64)?;
        }
        Some(out)
    }

    fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() || s.len() > 64 {
            return None;
        }
        let mut padded = String::with_capacity(64);
        for _ in 0..(64 - s.len()) {
            padded.push('0');
        }
        padded.push_str(s);
        let bytes = hex::decode(&padded).ok()?;
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            limbs[i] = u64::from_be_bytes(buf);
        }
        Some(Self { limbs })
    }

    fn mul_small(self, factor: u64) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        for i in (0..4).rev() {
            let v = self.limbs[i] as u128 * factor as u128 + carry;
            out[i] = v as u64;
            carry = v >> 64;
        }
        if carry != 0 {
            return None;
        }
        Some(Self { limbs: out })
    }

    fn add_small(self, addend: u64) -> Option<Self> {
        let mut out = self.limbs;
        let mut carry = addend as u128;
        for i in (0..4).rev() {
            let v = out[i] as u128 + carry;
            out[i] = v as u64;
            carry = v >> 64;
            if carry == 0 {
                break;
            }
        }
        if carry != 0 {
            return None;
        }
        Some(Self { limbs: out })
    }

    /// Left-shift by `bits`. Caller MUST ensure `bits <= 256`. Bits shifted
    /// out of the top limb are dropped silently — callers only use this with
    /// `Self::ONE` to compute `2^bits`, so overflow is impossible in practice.
    ///
    /// **Why the per-limb iteration over input limbs (vs the prior version
    /// that iterated output limbs):** the prior impl computed
    /// `self.limbs[3 - src] << bit_shift` and OR'd in
    /// `self.limbs[3 - (src + 1)] >> (64 - bit_shift)`. When `bit_shift == 0`
    /// (i.e. `bits` is a multiple of 64), the second term was
    /// (correctly) skipped — but the first term reduces to a plain limb
    /// copy without any shift. Codex P2 review on PR #95 caught the
    /// off-by-one: when `bits = 64`, `src = 1` for `i = 0`, and we copy
    /// `self.limbs[2]` (zero for `Self::ONE`) into `out[3]` instead of
    /// `self.limbs[3]` (the value 1) into `out[2]`. The result was
    /// `U256::ONE.shl(64) == 0` — silently rejecting valid `uint64: 1`
    /// values as out-of-range in the EIP-712 range check.
    ///
    /// This re-impl iterates INPUT limbs LSB-first; each limb's value
    /// is OR'd into its primary output slot (shifted up by `bit_shift`)
    /// plus, when `bit_shift > 0`, an extra carry into the next-most-
    /// significant slot. No off-by-one possible.
    fn shl(self, bits: usize) -> Self {
        if bits == 0 {
            return self;
        }
        if bits >= 256 {
            return Self::ZERO;
        }
        let limb_shift = bits / 64;
        let bit_shift = bits % 64;
        let mut out = [0u64; 4];
        // Iterate input limbs LSB-first (most-significant-first storage,
        // so we go index 3 → 0). For each non-zero limb, compute where
        // its bits land in the output.
        for k in (0..4).rev() {
            let val = self.limbs[k];
            if val == 0 {
                continue;
            }
            // Output index for the primary (low) bits of this limb.
            // limbs are most-sig-first, so shifting LEFT moves a limb
            // to a SMALLER index.
            let primary_out = k as i32 - limb_shift as i32;
            if (0..4).contains(&primary_out) {
                out[primary_out as usize] |= val << bit_shift;
            }
            // When the shift crosses a 64-bit boundary, the top
            // (64 - bit_shift) bits carry into the next-most-significant
            // output limb.
            if bit_shift > 0 {
                let secondary_out = primary_out - 1;
                if (0..4).contains(&secondary_out) {
                    out[secondary_out as usize] |= val >> (64 - bit_shift);
                }
            }
        }
        Self { limbs: out }
    }

    /// Two's-complement negation as a full-256-bit value: `(~self).wrapping_add(1)`.
    fn neg_twos_complement(self) -> Self {
        let mut out = self.limbs.map(|x| !x);
        // wrapping_add 1
        let mut carry = 1u128;
        for i in (0..4).rev() {
            let v = out[i] as u128 + carry;
            out[i] = v as u64;
            carry = v >> 64;
            if carry == 0 {
                break;
            }
        }
        Self { limbs: out }
    }

    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.limbs[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn types_mail() -> BTreeMap<String, Vec<TypeField>> {
        let mut t = BTreeMap::new();
        t.insert(
            "EIP712Domain".to_string(),
            vec![
                TypeField {
                    name: "name".into(),
                    ty: "string".into(),
                },
                TypeField {
                    name: "version".into(),
                    ty: "string".into(),
                },
                TypeField {
                    name: "chainId".into(),
                    ty: "uint256".into(),
                },
                TypeField {
                    name: "verifyingContract".into(),
                    ty: "address".into(),
                },
            ],
        );
        t.insert(
            "Person".to_string(),
            vec![
                TypeField {
                    name: "name".into(),
                    ty: "string".into(),
                },
                TypeField {
                    name: "wallet".into(),
                    ty: "address".into(),
                },
            ],
        );
        t.insert(
            "Mail".to_string(),
            vec![
                TypeField {
                    name: "from".into(),
                    ty: "Person".into(),
                },
                TypeField {
                    name: "to".into(),
                    ty: "Person".into(),
                },
                TypeField {
                    name: "contents".into(),
                    ty: "string".into(),
                },
            ],
        );
        t
    }

    /// Reference vector from <https://eips.ethereum.org/EIPS/eip-712> §
    /// "Specification of the eth_signTypedData_v4 JSON RPC".
    #[test]
    fn eip712_spec_example_matches_known_digest() {
        let types = types_mail();
        let td = TypedData {
            types,
            primary_type: "Mail".into(),
            domain: json!({
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            }),
            message: json!({
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
                },
                "contents": "Hello, Bob!",
            }),
        };
        let d = compute_digests(&td).unwrap();
        // Known reference: from the EIP-712 spec text and viem/ethers cross-verified.
        assert_eq!(
            hex::encode(d.final_digest),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
        );
        assert_eq!(
            hex::encode(d.domain_separator),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
        );
        assert_eq!(
            hex::encode(d.message_hash),
            "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e",
        );
    }

    #[test]
    fn encode_type_orders_deps_alphabetically_with_primary_first() {
        let types = types_mail();
        let encoded = encode_type(&types, "Mail").unwrap();
        assert_eq!(
            encoded,
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
    }

    #[test]
    fn cyclic_type_raises_error() {
        let mut t = BTreeMap::new();
        t.insert(
            "EIP712Domain".to_string(),
            vec![TypeField {
                name: "x".into(),
                ty: "uint256".into(),
            }],
        );
        t.insert(
            "A".to_string(),
            vec![TypeField {
                name: "b".into(),
                ty: "B".into(),
            }],
        );
        t.insert(
            "B".to_string(),
            vec![TypeField {
                name: "a".into(),
                ty: "A".into(),
            }],
        );
        assert!(matches!(
            encode_type(&t, "A"),
            Err(Eip712Error::CyclicType(_))
        ));
    }

    #[test]
    fn uint256_accepts_decimal_and_hex_strings() {
        let v = json!("1000000000000000000");
        let r = encode_data_for_field(&BTreeMap::new(), "uint256", &v, "amount").unwrap();
        assert_eq!(
            hex::encode(r),
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
        );

        let v = json!("0xde0b6b3a7640000");
        let r2 = encode_data_for_field(&BTreeMap::new(), "uint256", &v, "amount").unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn uint8_rejects_over_255() {
        let v = json!(256);
        let err = encode_data_for_field(&BTreeMap::new(), "uint8", &v, "x").unwrap_err();
        assert!(matches!(err, Eip712Error::IntegerOutOfRange(_, _)));
    }

    #[test]
    fn int8_negative_encodes_as_twos_complement() {
        let v = json!("-1");
        let r = encode_data_for_field(&BTreeMap::new(), "int8", &v, "x").unwrap();
        // -1 sign-extended to 256 bits is 0xff...ff.
        assert_eq!(hex::encode(r), "f".repeat(64));
    }

    #[test]
    fn bool_encodes_as_zero_padded_one() {
        let v = json!(true);
        let r = encode_data_for_field(&BTreeMap::new(), "bool", &v, "x").unwrap();
        assert_eq!(hex::encode(r), format!("{}{}", "0".repeat(62), "01"));
    }

    #[test]
    fn dynamic_array_encodes_keccak_of_concat() {
        let v = json!(["1", "2", "3"]);
        let r = encode_data_for_field(&BTreeMap::new(), "uint256[]", &v, "arr").unwrap();
        // keccak256( uint256(1) || uint256(2) || uint256(3) )
        let mut buf = [0u8; 96];
        buf[31] = 1;
        buf[63] = 2;
        buf[95] = 3;
        let expected = keccak(&buf);
        assert_eq!(r, expected);
    }

    #[test]
    fn fixed_array_length_mismatch_errors() {
        let v = json!([1, 2]);
        let err = encode_data_for_field(&BTreeMap::new(), "uint256[3]", &v, "arr").unwrap_err();
        assert!(matches!(err, Eip712Error::ArrayLengthMismatch { .. }));
    }

    #[test]
    fn unsupported_type_string_errors() {
        let v = json!("0xabcd");
        let err = encode_data_for_field(&BTreeMap::new(), "uintfoo", &v, "x").unwrap_err();
        assert!(matches!(err, Eip712Error::UnsupportedType(_)));
    }

    #[test]
    fn strip_array_suffix_handles_nested() {
        assert_eq!(strip_array_suffix("uint256[]"), "uint256");
        assert_eq!(strip_array_suffix("uint256[3]"), "uint256");
        assert_eq!(strip_array_suffix("uint256[2][]"), "uint256[2]");
        assert_eq!(strip_array_suffix("Person"), "Person");
    }

    #[test]
    fn u256_dec_then_hex_roundtrip() {
        let a = U256::from_dec("18446744073709551616").unwrap(); // 2^64
        let b = U256::from_hex("10000000000000000").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn u256_neg_one_is_all_f() {
        let one = U256::ONE;
        let neg = one.neg_twos_complement();
        assert_eq!(hex::encode(neg.to_be_bytes()), "f".repeat(64));
    }

    /// Regression for codex P2 finding on PR #95: `U256::ONE.shl(64)` used
    /// to return ZERO because the prior off-by-one impl copied the wrong
    /// limb when `bit_shift == 0`. Now: 2^64 is exactly representable in
    /// U256 (sets bit 64), so shl(64) MUST equal that.
    #[test]
    fn u256_shl_at_64_bit_boundary_does_not_drop_to_zero() {
        let v = U256::ONE.shl(64);
        let expected = U256::from_dec("18446744073709551616").unwrap(); // 2^64
        assert_eq!(v, expected);
        let v128 = U256::ONE.shl(128);
        let expected128 = U256::from_dec("340282366920938463463374607431768211456").unwrap(); // 2^128
        assert_eq!(v128, expected128);
        let v192 = U256::ONE.shl(192);
        let expected192 =
            U256::from_hex("1000000000000000000000000000000000000000000000000").unwrap(); // 2^192
        assert_eq!(v192, expected192);
    }

    /// Same regression at the encoder layer: `uint64: 1` was rejected as
    /// out-of-range because the range check used the buggy shl.
    #[test]
    fn uint64_accepts_value_one() {
        let v = serde_json::json!(1);
        let r = encode_data_for_field(&BTreeMap::new(), "uint64", &v, "x").unwrap();
        assert_eq!(hex::encode(r), format!("{}01", "0".repeat(62)));
    }

    /// `uint128: 2^127` should round-trip (well within range).
    #[test]
    fn uint128_accepts_mid_range_value() {
        let v = serde_json::json!("170141183460469231731687303715884105728"); // 2^127
        let r = encode_data_for_field(&BTreeMap::new(), "uint128", &v, "x").unwrap();
        assert_eq!(
            hex::encode(r),
            "0000000000000000000000000000000080000000000000000000000000000000"
        );
    }

    /// Regression for codex P2 finding on PR #95: int256 range check was
    /// skipped entirely. Values >= 2^255 must be rejected (they'd wrap
    /// to negative two's-complement silently otherwise).
    #[test]
    fn int256_rejects_value_at_or_above_2_pow_255() {
        // 2^255 (the smallest "wraps to negative" value).
        let at_max = serde_json::json!(
            "57896044618658097711785492504343953926634992332820282019728792003956564819968"
        );
        let err = encode_data_for_field(&BTreeMap::new(), "int256", &at_max, "x").unwrap_err();
        assert!(
            matches!(err, Eip712Error::IntegerOutOfRange(_, _)),
            "int256 must reject value at 2^255, got {err:?}"
        );
    }

    /// int256 accepts the largest valid positive value (2^255 - 1).
    #[test]
    fn int256_accepts_max_positive() {
        // 2^255 - 1
        let max = serde_json::json!(
            "57896044618658097711785492504343953926634992332820282019728792003956564819967"
        );
        encode_data_for_field(&BTreeMap::new(), "int256", &max, "x").unwrap();
    }

    /// int256 accepts the smallest valid negative value (-2^255).
    #[test]
    fn int256_accepts_min_negative() {
        let min = serde_json::json!(
            "-57896044618658097711785492504343953926634992332820282019728792003956564819968"
        );
        encode_data_for_field(&BTreeMap::new(), "int256", &min, "x").unwrap();
    }
}
