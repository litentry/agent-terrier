//! ERC-7730 v2 metadata file parser (issue #82).
//!
//! Parses the JSON shape documented at <https://eips.ethereum.org/EIPS/eip-7730>
//! into typed Rust structs. Only the subset needed for v0 clear-signing is
//! retained — operator-facing intent strings, EIP-712 domain binding, and
//! per-field display formats. Calldata-recursion, enum-resolved-from-chain,
//! and contract-deployment lookup beyond exact-match are out of scope.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Erc7730Error {
    #[error("malformed_7730_file: {0}")]
    Malformed(String),

    #[error("unsupported_7730_format: {0}")]
    Unsupported(String),
}

/// Top-level ERC-7730 file. Other fields the spec defines (`metadata.owner`,
/// `metadata.info.legalName`, etc.) are accepted but not currently surfaced
/// to the operator — operators looking at the rendered preview see the
/// rendered intent string, not the metadata block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7730File {
    pub context: Erc7730Context,
    #[serde(default)]
    pub metadata: serde_json::Value,
    pub display: Erc7730Display,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7730Context {
    /// EIP-712 binding — domain.{name, version, chainId, verifyingContract}
    /// is the lookup key for typed-data sign requests.
    #[serde(rename = "eip712", default)]
    pub eip712: Option<Erc7730Eip712Context>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7730Eip712Context {
    pub domain: Erc7730Eip712Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Erc7730Eip712Domain {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default, rename = "chainId")]
    pub chain_id: Option<u64>,
    #[serde(default, rename = "verifyingContract")]
    pub verifying_contract: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7730Display {
    /// Keyed by the primary type (EIP-712) or function selector (calldata).
    /// v0 only honors the EIP-712 primary-type form.
    pub formats: BTreeMap<String, Erc7730Format>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7730Format {
    /// Intent string with `{field}` interpolation. Example:
    /// `"Approve {value} {token} to {spender}"`.
    #[serde(default)]
    pub intent: Option<String>,
    /// Per-field display rules. Path is JSONPath-lite (`message.value`,
    /// `message.permit.token`).
    #[serde(default)]
    pub fields: Vec<Erc7730Field>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7730Field {
    pub path: String,
    #[serde(default)]
    pub label: Option<String>,
    /// One of: `"tokenAmount"`, `"address"`, `"raw"`, `"date"`, `"integer"`,
    /// `"enum"`, `"bool"`. Unknown formats fall back to raw.
    pub format: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

pub fn parse(json: &str) -> Result<Erc7730File, Erc7730Error> {
    serde_json::from_str::<Erc7730File>(json)
        .map_err(|e| Erc7730Error::Malformed(format!("invalid JSON: {e}")))
}

pub fn parse_value(value: serde_json::Value) -> Result<Erc7730File, Erc7730Error> {
    serde_json::from_value::<Erc7730File>(value)
        .map_err(|e| Erc7730Error::Malformed(format!("schema mismatch: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC_PERMIT_7730: &str = r#"{
      "context": {
        "eip712": {
          "domain": {
            "name": "USD Coin",
            "version": "2",
            "chainId": 1,
            "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
          }
        }
      },
      "metadata": { "owner": "Circle" },
      "display": {
        "formats": {
          "Permit": {
            "intent": "Approve USDC {value} to {spender}",
            "fields": [
              { "path": "owner",    "label": "Owner",    "format": "address" },
              { "path": "spender",  "label": "Spender",  "format": "address" },
              { "path": "value",    "label": "Amount",   "format": "tokenAmount", "params": { "decimals": 6, "ticker": "USDC" } },
              { "path": "nonce",    "label": "Nonce",    "format": "integer" },
              { "path": "deadline", "label": "Deadline", "format": "date" }
            ]
          }
        }
      }
    }"#;

    #[test]
    fn parses_usdc_permit_fixture() {
        let file = parse(USDC_PERMIT_7730).unwrap();
        let eip712 = file.context.eip712.unwrap();
        assert_eq!(eip712.domain.name.as_deref(), Some("USD Coin"));
        assert_eq!(eip712.domain.chain_id, Some(1));
        let permit = file.display.formats.get("Permit").unwrap();
        assert_eq!(
            permit.intent.as_deref(),
            Some("Approve USDC {value} to {spender}")
        );
        assert_eq!(permit.fields.len(), 5);
        let value_field = permit.fields.iter().find(|f| f.path == "value").unwrap();
        assert_eq!(value_field.format, "tokenAmount");
        assert_eq!(value_field.params["decimals"], serde_json::json!(6));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(matches!(
            parse("{not json"),
            Err(Erc7730Error::Malformed(_))
        ));
    }
}
