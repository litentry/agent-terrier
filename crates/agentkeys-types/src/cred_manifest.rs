//! Off-chain credential manifest (#216 default-key selection).
//!
//! The on-chain `AgentKeysScope` stores only `keccak(service)` HASHES, so an
//! agent cannot enumerate its authorized service NAMES, nor learn which one is
//! its default LLM key, from chain alone — keccak is one-way and there is no
//! "default" field. The master KNOWS the plaintext names + the designated
//! default at grant time (they are the input to `setScope` before hashing) and
//! records them HERE, off-chain, where the agent reads them at wire time.
//!
//! This is **discovery-only** and never widens authorization: every fetch still
//! re-verifies on-chain via `isServiceInScope` (broker cap-mint + worker), so a
//! service name that appears in the manifest but NOT in the on-chain scope is
//! rejected regardless. The manifest answers "which of my authorized creds is
//! the default LLM key?", a question the hash-only chain layer cannot.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The agent's authorized credential services + master-designated default.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CredManifest {
    /// Authorized credential service names (plaintext), in the master's order —
    /// the same names the master granted as `cred:<service>` scopes on-chain.
    #[serde(default)]
    pub services: Vec<String>,
    /// The master-designated default service: the no-UI LLM key the agent uses
    /// when the developer makes no selection. When `None`, or absent from
    /// `services`, the FIRST service is treated as the default.
    #[serde(default)]
    pub default_service: Option<String>,
}

/// Why a service could not be resolved from the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredManifestError {
    /// No explicit service, no `--select`, and the manifest lists no services.
    Empty,
    /// A 1-based `--select N` outside `1..=services.len()`.
    SelectOutOfRange { select: usize, len: usize },
}

impl std::fmt::Display for CredManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredManifestError::Empty => write!(
                f,
                "no credential service to fetch: pass an explicit service, or record a \
                 manifest (the master designates the default authorized cred)"
            ),
            CredManifestError::SelectOutOfRange { select, len } => write!(
                f,
                "--select {select} is out of range — the manifest lists {len} authorized \
                 service(s) (use 1..={len})"
            ),
        }
    }
}

impl std::error::Error for CredManifestError {}

impl CredManifest {
    pub fn new(services: Vec<String>, default_service: Option<String>) -> Self {
        Self {
            services,
            default_service,
        }
    }

    /// The default service name: the master-designated default when it is set
    /// AND present in `services`, otherwise the first service. `None` only when
    /// the manifest is empty.
    pub fn default_name(&self) -> Option<&str> {
        if let Some(d) = self.default_service.as_deref() {
            if self.services.iter().any(|s| s == d) {
                return Some(d);
            }
        }
        self.services.first().map(String::as_str)
    }

    /// Resolve which credential service to fetch, by precedence:
    ///   1. `explicit` — an operator/developer-typed service name, used as-is
    ///      (it is still on-chain-verified at fetch; the manifest never gates it);
    ///   2. `select` — a **1-based** index into `services` (matches the #216
    ///      `--select 1` notation, where `1` = the first authorized service);
    ///   3. the master-designated default ([`default_name`](Self::default_name)).
    ///
    /// Errors only when nothing resolves (empty manifest, or out-of-range select).
    pub fn resolve(
        &self,
        explicit: Option<&str>,
        select: Option<usize>,
    ) -> Result<String, CredManifestError> {
        if let Some(s) = explicit {
            return Ok(s.to_string());
        }
        if let Some(n) = select {
            if n == 0 || n > self.services.len() {
                return Err(CredManifestError::SelectOutOfRange {
                    select: n,
                    len: self.services.len(),
                });
            }
            return Ok(self.services[n - 1].clone());
        }
        self.default_name()
            .map(str::to_string)
            .ok_or(CredManifestError::Empty)
    }

    /// Load from a JSON file. A MISSING file yields an empty manifest (so a
    /// no-manifest environment degrades to "explicit service required", never a
    /// hard error). A present-but-malformed file IS an error (don't mask it).
    pub fn load(path: &Path) -> std::io::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Write the manifest as pretty JSON (0600 is the caller's responsibility —
    /// the manifest holds only public service NAMES, never secrets).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(services: &[&str], default: Option<&str>) -> CredManifest {
        CredManifest::new(
            services.iter().map(|s| s.to_string()).collect(),
            default.map(str::to_string),
        )
    }

    #[test]
    fn default_name_prefers_designated_when_present() {
        assert_eq!(
            m(&["openrouter", "anthropic"], Some("anthropic")).default_name(),
            Some("anthropic")
        );
    }

    #[test]
    fn default_name_falls_back_to_first_when_designated_absent_or_none() {
        // designated default not in the list → first
        assert_eq!(
            m(&["openrouter", "anthropic"], Some("ghost")).default_name(),
            Some("openrouter")
        );
        // no designated default → first
        assert_eq!(m(&["openrouter"], None).default_name(), Some("openrouter"));
    }

    #[test]
    fn default_name_none_when_empty() {
        assert_eq!(m(&[], None).default_name(), None);
    }

    #[test]
    fn resolve_precedence_explicit_beats_select_and_default() {
        let man = m(&["openrouter", "anthropic"], Some("anthropic"));
        assert_eq!(man.resolve(Some("typed"), Some(1)).unwrap(), "typed");
    }

    #[test]
    fn resolve_select_is_one_based() {
        let man = m(&["openrouter", "anthropic"], Some("anthropic"));
        assert_eq!(man.resolve(None, Some(1)).unwrap(), "openrouter");
        assert_eq!(man.resolve(None, Some(2)).unwrap(), "anthropic");
    }

    #[test]
    fn resolve_no_args_uses_master_default() {
        let man = m(&["openrouter", "anthropic"], Some("anthropic"));
        assert_eq!(man.resolve(None, None).unwrap(), "anthropic");
    }

    #[test]
    fn resolve_select_out_of_range_errors() {
        let man = m(&["openrouter"], None);
        assert_eq!(
            man.resolve(None, Some(0)),
            Err(CredManifestError::SelectOutOfRange { select: 0, len: 1 })
        );
        assert_eq!(
            man.resolve(None, Some(2)),
            Err(CredManifestError::SelectOutOfRange { select: 2, len: 1 })
        );
    }

    #[test]
    fn resolve_empty_manifest_errors_without_explicit() {
        assert_eq!(
            m(&[], None).resolve(None, None),
            Err(CredManifestError::Empty)
        );
        // …but an explicit service always resolves, even with an empty manifest.
        assert_eq!(
            m(&[], None).resolve(Some("openrouter"), None).unwrap(),
            "openrouter"
        );
    }

    #[test]
    fn load_missing_file_is_empty_manifest() {
        let p = std::env::temp_dir().join("agentkeys-cred-manifest-does-not-exist-xyz.json");
        let _ = std::fs::remove_file(&p);
        assert_eq!(CredManifest::load(&p).unwrap(), CredManifest::default());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let man = m(&["openrouter", "anthropic"], Some("anthropic"));
        let p = std::env::temp_dir().join(format!(
            "agentkeys-cred-manifest-rt-{}.json",
            std::process::id()
        ));
        man.save(&p).unwrap();
        assert_eq!(CredManifest::load(&p).unwrap(), man);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn deserializes_with_absent_default_field() {
        let man: CredManifest = serde_json::from_str(r#"{"services":["openrouter"]}"#).unwrap();
        assert_eq!(man.default_service, None);
        assert_eq!(man.default_name(), Some("openrouter"));
    }
}
