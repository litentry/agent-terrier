//! Domain → ERC-7730 file binding (issue #82).
//!
//! Given an EIP-712 typed-data domain, locate the ERC-7730 file in the
//! catalog that describes how to render the message. v0 binding rule:
//! exact match on `{name, version, chainId, verifyingContract}` — at least
//! one of these MUST match, all set fields MUST match. Unset fields in the
//! 7730 file are wildcards.

use super::eip712::TypedData;
use super::parser::{Erc7730Eip712Domain, Erc7730File};

/// Look up the ERC-7730 file whose `context.eip712.domain` matches the
/// typed-data `domain`. Returns `None` if no file in the catalog matches.
pub fn match_file<'a>(
    files: impl IntoIterator<Item = &'a Erc7730File>,
    typed_data: &TypedData,
) -> Option<&'a Erc7730File> {
    let td_domain = parse_typed_data_domain(&typed_data.domain)?;
    for file in files {
        if let Some(ctx) = &file.context.eip712 {
            if domain_matches(&ctx.domain, &td_domain) {
                return Some(file);
            }
        }
    }
    None
}

pub(crate) fn parse_typed_data_domain(domain: &serde_json::Value) -> Option<Erc7730Eip712Domain> {
    let obj = domain.as_object()?;
    Some(Erc7730Eip712Domain {
        name: obj.get("name").and_then(|v| v.as_str()).map(str::to_string),
        version: obj
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        chain_id: obj.get("chainId").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        }),
        verifying_contract: obj
            .get("verifyingContract")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase()),
    })
}

fn domain_matches(file: &Erc7730Eip712Domain, td: &Erc7730Eip712Domain) -> bool {
    if let Some(f) = &file.name {
        if td.name.as_ref() != Some(f) {
            return false;
        }
    }
    if let Some(f) = &file.version {
        if td.version.as_ref() != Some(f) {
            return false;
        }
    }
    if let Some(f) = file.chain_id {
        if td.chain_id != Some(f) {
            return false;
        }
    }
    if let Some(f) = &file.verifying_contract {
        let f_lower = f.to_lowercase();
        if td.verifying_contract.as_ref() != Some(&f_lower) {
            return false;
        }
    }
    // At least one field MUST have been set, otherwise this is a wildcard
    // file that matches everything — refuse to bind.
    file.name.is_some()
        || file.version.is_some()
        || file.chain_id.is_some()
        || file.verifying_contract.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clear_signing::parser::parse;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn usdc_permit_file() -> Erc7730File {
        let json = r#"{
          "context": { "eip712": { "domain": {
            "name": "USD Coin",
            "version": "2",
            "chainId": 1,
            "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
          } } },
          "metadata": {},
          "display": { "formats": { "Permit": { "intent": "x" } } }
        }"#;
        parse(json).unwrap()
    }

    fn permit_td(verifying: &str) -> TypedData {
        TypedData {
            primary_type: "Permit".into(),
            types: BTreeMap::new(),
            domain: json!({
                "name": "USD Coin",
                "version": "2",
                "chainId": 1,
                "verifyingContract": verifying,
            }),
            message: json!({}),
        }
    }

    #[test]
    fn exact_match_succeeds() {
        let files = vec![usdc_permit_file()];
        let td = permit_td("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        assert!(match_file(&files, &td).is_some());
    }

    #[test]
    fn match_is_case_insensitive_on_address() {
        let files = vec![usdc_permit_file()];
        let td = permit_td("0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48");
        assert!(match_file(&files, &td).is_some());
    }

    #[test]
    fn mismatched_chain_id_fails() {
        let files = vec![usdc_permit_file()];
        let mut td = permit_td("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        td.domain
            .as_object_mut()
            .unwrap()
            .insert("chainId".into(), json!(137));
        assert!(match_file(&files, &td).is_none());
    }

    #[test]
    fn empty_file_domain_is_wildcard_refused() {
        let json = r#"{
          "context": { "eip712": { "domain": {} } },
          "metadata": {},
          "display": { "formats": {} }
        }"#;
        let files = vec![parse(json).unwrap()];
        let td = permit_td("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        assert!(match_file(&files, &td).is_none());
    }
}
