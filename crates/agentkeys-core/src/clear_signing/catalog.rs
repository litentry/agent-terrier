//! ERC-7730 file catalog (issue #82).
//!
//! Holds a collection of ERC-7730 files keyed by their EIP-712 domain. The
//! catalog is the source of truth for "given this typed-data domain, how do
//! I render the message?".
//!
//! v0 sources:
//! - **Bundled**: files compiled into the binary under
//!   `crates/agentkeys-core/src/clear_signing/fixtures/`. The minimum
//!   shippable set ships in this PR (USDC permit). Add more as operators
//!   need them; each is a single JSON file in the fixtures dir.
//! - **Filesystem**: load all `*.json` from a directory pointed at by
//!   `$AGENTKEYS_7730_DIR` (per arch.md §22 pluggable surfaces). Lets
//!   operators ship operator-custom 7730 files without recompiling.
//!
//! v1 (separate issue): fetch from the upstream
//! `ethereum/clear-signing-erc7730-registry` GitHub repo at daemon startup,
//! cached locally.

use std::path::Path;

use super::parser::{parse, Erc7730Error, Erc7730File};

/// One bundled USDC permit ERC-7730 file. New bundled files are added here
/// alongside their JSON; the JSON is the source of truth, this array is
/// just the compile-time include.
const BUNDLED_FILES: &[(&str, &str)] = &[(
    "erc20-permit-usdc.json",
    include_str!("fixtures/erc20-permit-usdc.json"),
)];

/// Catalog of ERC-7730 files. Cheap to clone (each file's `Erc7730File` is
/// already heap-allocated; the catalog is `Vec<Erc7730File>`).
#[derive(Debug, Clone, Default)]
pub struct ClearSigningCatalog {
    files: Vec<Erc7730File>,
}

impl ClearSigningCatalog {
    /// Empty catalog — preview will fail to bind any typed data.
    pub fn empty() -> Self {
        Self { files: Vec::new() }
    }

    /// Bundled set — the canonical v0 default.
    pub fn bundled() -> Self {
        let mut catalog = Self::empty();
        for (name, json) in BUNDLED_FILES {
            match parse(json) {
                Ok(file) => catalog.files.push(file),
                Err(e) => {
                    eprintln!("agentkeys clear_signing: bundled file {name} failed to parse: {e}");
                }
            }
        }
        catalog
    }

    /// Bundled + every `*.json` file under `dir`. Errors loading individual
    /// files surface as `Err`; the caller decides whether to ignore.
    pub fn bundled_plus_dir(dir: impl AsRef<Path>) -> Result<Self, Erc7730Error> {
        let mut catalog = Self::bundled();
        catalog.extend_from_dir(dir)?;
        Ok(catalog)
    }

    /// Add one parsed ERC-7730 file to the catalog.
    pub fn push(&mut self, file: Erc7730File) {
        self.files.push(file);
    }

    /// Load all `*.json` under `dir` and append them.
    pub fn extend_from_dir(&mut self, dir: impl AsRef<Path>) -> Result<(), Erc7730Error> {
        let dir = dir.as_ref();
        let read_dir = std::fs::read_dir(dir).map_err(|e| {
            Erc7730Error::Malformed(format!("cannot read 7730 dir {}: {e}", dir.display()))
        })?;
        for entry in read_dir {
            let entry = entry
                .map_err(|e| Erc7730Error::Malformed(format!("dir entry error: {e}")))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let content = std::fs::read_to_string(&path).map_err(|e| {
                Erc7730Error::Malformed(format!("read {}: {e}", path.display()))
            })?;
            self.files.push(parse(&content)?);
        }
        Ok(())
    }

    /// Iterate the catalog's files — used by binding for domain lookup.
    pub fn iter(&self) -> impl Iterator<Item = &Erc7730File> {
        self.files.iter()
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_catalog_loads_usdc_permit() {
        let catalog = ClearSigningCatalog::bundled();
        assert!(!catalog.is_empty(), "bundled catalog must contain ≥ 1 file");
        let has_usdc = catalog.iter().any(|f| {
            f.context
                .eip712
                .as_ref()
                .and_then(|e| e.domain.name.as_deref())
                .map(|n| n == "USD Coin")
                .unwrap_or(false)
        });
        assert!(has_usdc, "bundled catalog must include USDC permit");
    }

    #[test]
    fn extend_from_dir_loads_json_files() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("custom.json");
        std::fs::write(
            &path,
            r#"{
              "context": { "eip712": { "domain": {
                "name": "Custom", "version": "1", "chainId": 1
              } } },
              "metadata": {},
              "display": { "formats": {} }
            }"#,
        )
        .unwrap();
        let mut catalog = ClearSigningCatalog::empty();
        catalog.extend_from_dir(tmp.path()).unwrap();
        assert_eq!(catalog.len(), 1);
    }
}
