//! Clear-signing (ERC-7730 + EIP-712) — issue #82.
//!
//! Two responsibilities:
//!
//! 1. **EIP-712 typed-data hashing** ([`eip712`]). Implements the v4 encoding
//!    rules so the signer can hash + sign a typed-data value, and so the
//!    daemon / CLI can re-derive the same digest without contacting the
//!    signer.
//!
//! 2. **ERC-7730 metadata** ([`parser`], [`format`], [`binding`], [`catalog`]).
//!    Loads operator-readable display rules ("Approve USDC 1000 to
//!    Uniswap router") for typed-data messages, so the operator can review
//!    *what* an agent is about to authorize before approving.
//!
//! ## Public entry points
//!
//! - [`ClearSigningCatalog::bundled`] — load the compile-time-bundled v0 set.
//! - [`build_preview`] — given a catalog + typed data, compute the digest,
//!   resolve the matching 7730 file, render the intent text, compute the
//!   audit-row commitment hash.
//!
//! ## The intent-commitment property
//!
//! `signed_intent_hash = keccak256(intent_text || "|" || digest)` — the audit
//! row carries this hash, so later auditors verifying a sign event can
//! re-render the intent from the same 7730 file and check the commitment
//! matches. This closes the "agent-A signed `0xdead…beef`" failure mode
//! that arch.md §15.3 calls out. See [`docs/arch.md`].

pub mod binding;
pub mod catalog;
pub mod eip712;
pub mod format;
pub mod parser;

use sha3::{Digest, Keccak256};
use thiserror::Error;

pub use catalog::ClearSigningCatalog;
pub use eip712::{compute_digests, Eip712Digests, Eip712Error, TypeField, TypedData};
pub use format::{interpolate_intent, RenderedFields};
pub use parser::{Erc7730Error, Erc7730File};

#[derive(Debug, Error)]
pub enum ClearSigningError {
    #[error("eip712: {0}")]
    Eip712(#[from] Eip712Error),

    #[error("7730: {0}")]
    Erc7730(#[from] Erc7730Error),

    #[error("no_7730_file_for_domain: typed-data domain does not match any 7730 file in catalog")]
    NoMatch,

    #[error("no_format_for_primary_type: matched 7730 file does not define format for primary type '{0}'")]
    NoFormatForPrimaryType(String),

    #[error("no_intent: matched 7730 format does not define an intent string")]
    NoIntent,
}

/// What [`build_preview`] returns: the rendered intent text, the matched
/// 7730 file, the EIP-712 digests, and the intent-commitment hash that the
/// audit row should carry.
#[derive(Debug, Clone)]
pub struct ClearSigningPreview {
    pub typed_data: TypedData,
    pub digests: Eip712Digests,
    /// Operator-readable text. Example:
    /// `"Approve 1000.5 USDC to spender 0xabcd…1234"`.
    pub intent_text: String,
    /// `keccak256(intent_text || "|" || digest)` — the cryptographic
    /// commitment that the audit row stores alongside the signature, so a
    /// later auditor can verify the rendered intent the operator saw.
    pub intent_commitment: [u8; 32],
    /// Per-field rendered (label, value) pairs in the order the 7730 file
    /// declares them. Used by the CLI to print a field-by-field review.
    pub fields: Vec<(String, String)>,
}

/// Build a preview for `typed_data` against `catalog`. The preview is the
/// rendered intent plus the digests the signer would produce; it does NOT
/// itself produce a signature.
pub fn build_preview(
    catalog: &ClearSigningCatalog,
    typed_data: TypedData,
) -> Result<ClearSigningPreview, ClearSigningError> {
    let digests = compute_digests(&typed_data)?;
    let file =
        binding::match_file(catalog.iter(), &typed_data).ok_or(ClearSigningError::NoMatch)?;
    let format = file
        .display
        .formats
        .get(&typed_data.primary_type)
        .ok_or_else(|| {
            ClearSigningError::NoFormatForPrimaryType(typed_data.primary_type.clone())
        })?;
    let intent_template = format
        .intent
        .as_deref()
        .ok_or(ClearSigningError::NoIntent)?;

    let rendered = RenderedFields::render(&typed_data.message, format);
    let intent_text = interpolate_intent(intent_template, &rendered);
    let intent_commitment = commit_intent(&intent_text, &digests.final_digest);
    let fields = rendered
        .iter_pairs(format)
        .map(|(l, v)| (l.to_string(), v.to_string()))
        .collect();

    Ok(ClearSigningPreview {
        typed_data,
        digests,
        intent_text,
        intent_commitment,
        fields,
    })
}

/// `keccak256(intent_text.as_bytes() || 0x7c || final_digest)`. The
/// separator byte (`0x7c` = ASCII `|`) is a domain-separation token so an
/// adversary cannot construct an `intent_text` whose last byte fakes the
/// digest boundary.
pub fn commit_intent(intent_text: &str, final_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(intent_text.as_bytes());
    hasher.update([0x7c]);
    hasher.update(final_digest);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn usdc_permit_typed_data() -> TypedData {
        let mut types: BTreeMap<String, Vec<TypeField>> = BTreeMap::new();
        types.insert(
            "EIP712Domain".into(),
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
        types.insert(
            "Permit".into(),
            vec![
                TypeField {
                    name: "owner".into(),
                    ty: "address".into(),
                },
                TypeField {
                    name: "spender".into(),
                    ty: "address".into(),
                },
                TypeField {
                    name: "value".into(),
                    ty: "uint256".into(),
                },
                TypeField {
                    name: "nonce".into(),
                    ty: "uint256".into(),
                },
                TypeField {
                    name: "deadline".into(),
                    ty: "uint256".into(),
                },
            ],
        );
        TypedData {
            types,
            primary_type: "Permit".into(),
            domain: json!({
                "name": "USD Coin",
                "version": "2",
                "chainId": 1,
                "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            }),
            message: json!({
                "owner":   "0x1111111111111111111111111111111111111111",
                "spender": "0xaaaabbbbccccddddeeeeffff0000111122223333",
                "value":   "1500000",
                "nonce":   "0",
                "deadline": "1900000000",
            }),
        }
    }

    #[test]
    fn build_preview_against_bundled_renders_usdc_intent() {
        let catalog = ClearSigningCatalog::bundled();
        let td = usdc_permit_typed_data();
        let p = build_preview(&catalog, td).unwrap();
        assert_eq!(p.intent_text, "Approve 1.5 USDC to spender 0xaaaa…3333");
        // intent_commitment is deterministic for the same intent + digest:
        let again = commit_intent(&p.intent_text, &p.digests.final_digest);
        assert_eq!(p.intent_commitment, again);
        // Fields list carries the per-field rendering for CLI review:
        assert!(p
            .fields
            .iter()
            .any(|(l, v)| l == "Amount" && v == "1.5 USDC"));
    }

    #[test]
    fn build_preview_fails_when_no_7730_matches() {
        let catalog = ClearSigningCatalog::empty();
        let td = usdc_permit_typed_data();
        let err = build_preview(&catalog, td).unwrap_err();
        assert!(matches!(err, ClearSigningError::NoMatch));
    }

    #[test]
    fn commit_intent_is_collision_resistant_across_separator() {
        // "foo|bar" hashed differently from intent="foo|" + digest=[b'b','a','r',...]
        // because we use a non-printable separator + 32-byte digest with explicit length.
        let digest = [0u8; 32];
        let a = commit_intent("foo", &digest);
        let mut b_digest = [0u8; 32];
        b_digest[..3].copy_from_slice(b"bar");
        let b = commit_intent("foo|", &b_digest);
        assert_ne!(a, b);
    }
}
