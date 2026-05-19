//! Stage-1 K11 stub helpers.
//!
//! Real K11 binding (arch.md §5a.1 + §22a.6) uses platform WebAuthn:
//! the operator's laptop has a synced passkey; the broker issues a
//! WebAuthn challenge; the authenticator signs `SHA256(binding_nonce || D_pub)`;
//! the broker forwards the assertion on-chain via
//! `SidecarRegistry.registerMasterDevice(... k11Assertion ...)`.
//!
//! Stage 1 ships a *deterministic stub* so the rest of the flow
//! (scope-set, scope-revoke, agent-create) works without dragging the
//! whole webauthn-rs stack into the laptop CLI. The on-chain contract
//! gates on `k11Assertion.length != 0` only (no P-256 verify); the stub
//! provides exactly that.
//!
//! Stage 2 (#90) replaces this module with real webauthn-rs integration,
//! Touch ID prompt, and on-chain assertion verification via the
//! EIP-7212 P-256 precompile.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct K11Enrollment {
    pub operator_omni: String,
    pub credential_id_hex: String,
    pub cose_pubkey_hex: String,
    pub enrolled_at_unix: u64,
    /// `"stage1-stub"` until #90 lands real WebAuthn.
    pub mode: String,
}

#[derive(Debug, thiserror::Error)]
pub enum K11Error {
    #[error("io: {0}")]
    Io(String),
    #[error("serde: {0}")]
    Serde(String),
    #[error("invalid operator_omni: {0}")]
    InvalidOperatorOmni(String),
}

fn enrollment_path(operator_omni: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home)
        .join(".agentkeys")
        .join("k11")
        .join(format!("{}.json", operator_omni.trim_start_matches("0x")))
}

pub fn enroll(operator_omni: &str) -> Result<K11Enrollment, K11Error> {
    validate_omni(operator_omni)?;
    let credential_id = sha256_str(&format!("agentkeys-k11-stub-cred:{}", operator_omni));
    let cose_pubkey = sha256_str(&format!("agentkeys-k11-stub-cose:{}", operator_omni));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let enrollment = K11Enrollment {
        operator_omni: operator_omni.to_string(),
        credential_id_hex: credential_id,
        cose_pubkey_hex: cose_pubkey,
        enrolled_at_unix: now,
        mode: "stage1-stub".into(),
    };
    let path = enrollment_path(operator_omni);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| K11Error::Io(e.to_string()))?;
    }
    let json = serde_json::to_vec_pretty(&enrollment)
        .map_err(|e| K11Error::Serde(e.to_string()))?;
    fs::write(&path, json).map_err(|e| K11Error::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .map_err(|e| K11Error::Io(e.to_string()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).map_err(|e| K11Error::Io(e.to_string()))?;
    }
    Ok(enrollment)
}

/// Produce a stage-1 stub assertion. Non-empty (the contract gate is
/// `length != 0`), deterministic per (operator_omni, message) for
/// debuggability, and labelled so we can tell stage-1 from real
/// assertions when audit reports cross over to stage 2.
pub fn assert_stub(operator_omni: &str, message: &[u8]) -> Result<Vec<u8>, K11Error> {
    validate_omni(operator_omni)?;
    let mut h = Sha256::new();
    h.update(b"agentkeys-k11-stub-assert:");
    h.update(operator_omni.trim_start_matches("0x").to_lowercase().as_bytes());
    h.update(b":");
    h.update(message);
    let digest = h.finalize();
    let mut out = b"stage1-k11-stub:".to_vec();
    out.extend_from_slice(&digest);
    Ok(out)
}

fn validate_omni(operator_omni: &str) -> Result<(), K11Error> {
    let stripped = operator_omni.trim_start_matches("0x");
    if stripped.len() != 64 {
        return Err(K11Error::InvalidOperatorOmni(format!(
            "expected 64-hex (32 bytes), got {} chars",
            stripped.len()
        )));
    }
    hex::decode(stripped).map_err(|e| K11Error::InvalidOperatorOmni(e.to_string()))?;
    Ok(())
}

fn sha256_str(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_omni() -> String {
        format!("0x{}", "a".repeat(64))
    }

    #[test]
    fn enroll_writes_file_with_strict_perms() {
        let omni = test_omni();
        let e = enroll(&omni).unwrap();
        assert_eq!(e.operator_omni, omni);
        assert_eq!(e.mode, "stage1-stub");
        assert_eq!(e.credential_id_hex.len(), 64);
        let path = enrollment_path(&omni);
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
        // cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn assert_stub_is_deterministic() {
        let omni = test_omni();
        let a1 = assert_stub(&omni, b"hello").unwrap();
        let a2 = assert_stub(&omni, b"hello").unwrap();
        assert_eq!(a1, a2);
        let a3 = assert_stub(&omni, b"different").unwrap();
        assert_ne!(a1, a3);
    }

    #[test]
    fn assert_stub_starts_with_label() {
        let omni = test_omni();
        let a = assert_stub(&omni, b"x").unwrap();
        assert!(a.starts_with(b"stage1-k11-stub:"));
        assert_eq!(a.len(), b"stage1-k11-stub:".len() + 32);
    }

    #[test]
    fn validate_omni_rejects_short() {
        assert!(matches!(
            assert_stub("0xabc", b""),
            Err(K11Error::InvalidOperatorOmni(_))
        ));
    }

    #[test]
    fn validate_omni_rejects_non_hex() {
        let bad = format!("0x{}", "z".repeat(64));
        assert!(matches!(
            assert_stub(&bad, b""),
            Err(K11Error::InvalidOperatorOmni(_))
        ));
    }
}
