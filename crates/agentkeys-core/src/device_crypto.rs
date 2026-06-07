//! Shared device-key crypto for the §10.2 agent bootstrap (issue #144).
//!
//! De-duplicates the secp256k1 / EIP-191 / keccak helpers previously inlined in
//! `agentkeys-cli::device_session` and the broker's `plugins::auth::wallet_sig`,
//! so the daemon (keygen + link-code redeem), the CLI (interim device-session),
//! and the broker (redeem `pop_sig` verify) agree byte-for-byte.
//!
//! The proof-of-possession preimage is the **deployed** one —
//! `keccak256("agentkeys-agent-pop:" || device_key_hash_hex)` — matching
//! `scripts/heima-agent-create.sh` and the on-chain `registerAgentDevice` inputs.
//! (arch.md §10.2 still shows the stale `link_code || D_pub`; the doc is being
//! reconciled to this preimage, not the other way around.)

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

/// Keccak-256 over `bytes`.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// EVM address (`0x` + 40 lowercase hex) = last 20 bytes of
/// keccak256(uncompressed pubkey x‖y).
pub fn evm_address(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(false);
    let xy = &point.as_bytes()[1..]; // drop the 0x04 SEC1 tag → 64 bytes
    let hash = keccak256(xy);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// `device_key_hash = keccak256(address_bytes)` as `0x` + 64 hex. `addr` may be
/// `0x`-prefixed and any case; the 20 raw address bytes are hashed (not ASCII).
pub fn device_key_hash(addr: &str) -> Result<String> {
    let addr_lc = addr.trim().to_lowercase();
    let hex_part = addr_lc.strip_prefix("0x").unwrap_or(&addr_lc);
    let addr_bytes = hex::decode(hex_part).context("address is not hex")?;
    if addr_bytes.len() != 20 {
        return Err(anyhow!(
            "address must be 20 bytes, got {}",
            addr_bytes.len()
        ));
    }
    Ok(format!("0x{}", hex::encode(keccak256(&addr_bytes))))
}

/// The MASTER device key hash, derived deterministically from the operator
/// omni: `device_key_hash = keccak256(operator_omni_bytes)` as `0x` + 64 hex.
///
/// This mirrors the web/#164 register convention `cast keccak "0x$OPERATOR_OMNI"`
/// (`harness/scripts/heima-register-first-master.sh` + `_lib.sh::resolve_active_master_dkh`)
/// — `cast keccak` over a `0x`-prefixed value hashes the 32 RAW omni bytes, not
/// the ASCII hex. Because the hash is derivable from the omni alone, the master
/// session needs no cached `device_key_hash` to resolve cap-mint after a daemon
/// restart (issue #220): the on-chain `SidecarRegistry` binding is the source of
/// truth and `keccak(operator_omni)` reproduces its key with no re-onboarding.
///
/// `omni` may be `0x`/`0X`-prefixed or bare; it MUST decode to exactly 32 bytes.
pub fn device_key_hash_from_omni(omni: &str) -> Result<String> {
    let trimmed = omni.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let omni_bytes = hex::decode(hex_part).context("omni is not hex")?;
    if omni_bytes.len() != 32 {
        return Err(anyhow!("omni must be 32 bytes, got {}", omni_bytes.len()));
    }
    Ok(format!("0x{}", hex::encode(keccak256(&omni_bytes))))
}

/// The agent proof-of-possession preimage:
/// `keccak256("agentkeys-agent-pop:" || device_key_hash_hex)`, where
/// `device_key_hash_hex` is the `0x`-prefixed string from [`device_key_hash`].
pub fn agent_pop_payload(device_key_hash_hex: &str) -> [u8; 32] {
    keccak256(format!("agentkeys-agent-pop:{device_key_hash_hex}").as_bytes())
}

/// EIP-191 `personal_sign` over `message`, producing 65-byte `r‖s‖v` hex
/// (`v ∈ {27,28}`, low-s via k256). Matches the broker's ecrecover envelope.
pub fn eip191_sign(sk: &SigningKey, message: &[u8]) -> Result<String> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message);
    let digest = h.finalize();
    let (sig, recid): (Signature, RecoveryId) = sk
        .sign_prehash_recoverable(&digest)
        .context("sign_prehash_recoverable")?;
    let mut out = sig.to_bytes().to_vec(); // 64 bytes r‖s
    out.push(27 + recid.to_byte());
    Ok(format!("0x{}", hex::encode(out)))
}

/// EIP-191 ecrecover: recover the `0x`-lowercase signer address from a 65-byte
/// `r‖s‖v` hex signature over `message`. `v ∈ {0,1,27,28}`.
pub fn ecrecover_eip191(message: &[u8], signature_hex: &str) -> Result<String> {
    let sig_hex = signature_hex.trim().trim_start_matches("0x");
    let sig_bytes = hex::decode(sig_hex).context("signature is not hex")?;
    if sig_bytes.len() != 65 {
        return Err(anyhow!(
            "signature must be 65 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let recovery_id_byte = match sig_bytes[64] {
        v @ (0 | 1) => v,
        v @ (27 | 28) => v - 27,
        other => return Err(anyhow!("unsupported v byte: {other}")),
    };
    let recovery_id = RecoveryId::try_from(recovery_id_byte).context("bad recovery id")?;
    let signature = Signature::from_slice(&sig_bytes[..64]).context("bad sig bytes")?;
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut h = Keccak256::new();
    h.update(prefix.as_bytes());
    h.update(message);
    let digest = h.finalize();
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|e| anyhow!("recover failed: {e}"))?;
    Ok(evm_address(&vk))
}

fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    p.to_string()
}

#[cfg(unix)]
pub fn write_key_0600(path: &str, content: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Custody hardening: `mode(0o600)` is honoured ONLY when the file is freshly
    // created — a pre-existing group/world-readable file would be truncated +
    // rewritten while KEEPING its loose perms, and a planted symlink at `path`
    // would redirect the write outside the owner-only file. So reject an existing
    // symlink / non-regular target, and force 0600 AFTER opening (covers the
    // pre-existing-loose-file case). Residual TOCTOU between the check and open is
    // not closed here — O_NOFOLLOW would, but needs a libc dep (follow-up).
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(anyhow!(
                "refusing to write {path}: existing target is a symlink/special file (key-custody)"
            ));
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {path} (0600)"))?;
    // Force owner-only even if the file pre-existed with looser permissions.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {path}"))?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
pub fn write_key_0600(path: &str, content: &str) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("write {path}"))
}

/// Before loading an EXISTING device key, verify it's a regular, owner-only
/// file. A copied/restored key with group/other read bits — or a symlink to
/// another file — would otherwise still produce a valid signer, silently
/// breaking the "key never leaves / only the owner can use it" guarantee. We
/// reject (not auto-repair): loose perms mean the key may already be exposed.
#[cfg(unix)]
pub fn enforce_owner_only(path: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("stat {path}"))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "device key {path} is a symlink — refusing (key-custody); use a real owner-only file or regenerate"
        ));
    }
    if !meta.file_type().is_file() {
        return Err(anyhow!(
            "device key {path} is not a regular file — refusing"
        ));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(anyhow!(
            "device key {path} has loose permissions {mode:o} (group/other bits set) — \
             it may already be exposed. Run `chmod 600 {path}` (or regenerate) and retry."
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn enforce_owner_only(_path: &str) -> Result<()> {
    Ok(())
}

/// An agent's secp256k1 device key (K10). Generated IN THE SANDBOX and never
/// leaves it; used only for the redeem `pop_sig` and per-request cap-mint sigs.
/// Its omni is decoupled from this key (issue #144 decision 2 — the omni is the
/// broker-minted HDKD child).
pub struct DeviceKey {
    sk: SigningKey,
    address: String,
}

impl DeviceKey {
    /// Load the owner-only key file if present (rejecting loose perms / symlinks),
    /// else generate a fresh key and persist it `0600`. `regen` forces a fresh
    /// key. `key_file` may use a leading `~/`.
    ///
    /// On a failed bind/grant the caller should re-run WITHOUT `regen` so the
    /// same key (→ same `device_key_hash`) is reused and the on-chain submit
    /// hits the `already-registered` short-circuit instead of binding a 2nd key.
    pub fn load_or_generate(key_file: &str, regen: bool) -> Result<Self> {
        let key_path = expand_home(key_file);
        if regen {
            let _ = std::fs::remove_file(&key_path);
        }
        let sk = if Path::new(&key_path).exists() {
            enforce_owner_only(&key_path)?;
            let raw = std::fs::read_to_string(&key_path).context("read device key file")?;
            let raw = raw.trim().trim_start_matches("0x");
            let bytes = hex::decode(raw).context("device key file is not hex")?;
            SigningKey::from_slice(&bytes).context("invalid secp256k1 device key")?
        } else {
            let sk = SigningKey::random(&mut rand_core::OsRng);
            if let Some(dir) = Path::new(&key_path).parent() {
                std::fs::create_dir_all(dir).ok();
            }
            write_key_0600(&key_path, &format!("0x{}", hex::encode(sk.to_bytes())))?;
            sk
        };
        let address = evm_address(sk.verifying_key());
        Ok(Self { sk, address })
    }

    /// The K10 EVM address (`0x` + 40 lowercase hex).
    pub fn address(&self) -> &str {
        &self.address
    }

    /// `device_key_hash = keccak256(address_bytes)`.
    pub fn device_key_hash(&self) -> Result<String> {
        device_key_hash(&self.address)
    }

    /// EIP-191 sign `message` with this device key.
    pub fn sign_eip191(&self, message: &[u8]) -> Result<String> {
        eip191_sign(&self.sk, message)
    }

    /// Proof-of-possession signature the broker verifies at link-code redeem and
    /// the master submits with `registerAgentDevice`:
    /// `EIP-191( keccak256("agentkeys-agent-pop:" || device_key_hash) )`.
    pub fn pop_sig(&self) -> Result<String> {
        let dkh = self.device_key_hash()?;
        self.sign_eip191(&agent_pop_payload(&dkh))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // issue #220 — the master device hash must be derivable from the omni alone
    // (no cached register result) so the daemon resolves cap-mint after a restart.
    // Vector: keccak256(32 zero bytes) is the well-known constant
    // 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563.
    #[test]
    fn device_key_hash_from_omni_matches_cast_keccak() {
        let zero_omni = format!("0x{}", "00".repeat(32));
        assert_eq!(
            device_key_hash_from_omni(&zero_omni).unwrap(),
            "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
        );
    }

    #[test]
    fn device_key_hash_from_omni_ignores_prefix_and_case() {
        let bare = "11".repeat(32);
        let with_0x = format!("0x{bare}");
        let with_0x_upper = format!("0X{bare}");
        let h = device_key_hash_from_omni(&bare).unwrap();
        assert_eq!(h, device_key_hash_from_omni(&with_0x).unwrap());
        assert_eq!(h, device_key_hash_from_omni(&with_0x_upper).unwrap());
        assert!(h.starts_with("0x") && h.len() == 66);
    }

    #[test]
    fn device_key_hash_from_omni_rejects_wrong_length() {
        // A 20-byte address is NOT a valid 32-byte omni.
        let addr = format!("0x{}", "ab".repeat(20));
        assert!(device_key_hash_from_omni(&addr).is_err());
    }

    #[test]
    fn eip191_round_trip_recovers_signer() {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let addr = evm_address(sk.verifying_key());
        let msg = b"hello agentkeys";
        let sig = eip191_sign(&sk, msg).unwrap();
        let recovered = ecrecover_eip191(msg, &sig).unwrap();
        assert_eq!(recovered, addr);
    }

    #[test]
    fn pop_sig_recovers_to_device_address() {
        // The redeem-critical match: the broker recovers the device address from
        // pop_sig over agent_pop_payload(device_key_hash) and checks it equals
        // the supplied device_pubkey.
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("dev.key");
        let dk = DeviceKey::load_or_generate(kf.to_str().unwrap(), true).unwrap();
        let dkh = dk.device_key_hash().unwrap();
        let pop = dk.pop_sig().unwrap();
        let recovered = ecrecover_eip191(&agent_pop_payload(&dkh), &pop).unwrap();
        assert_eq!(recovered, dk.address());
    }

    #[test]
    fn device_key_persists_and_reloads_same_address() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("dev.key");
        let a = DeviceKey::load_or_generate(kf.to_str().unwrap(), false).unwrap();
        let b = DeviceKey::load_or_generate(kf.to_str().unwrap(), false).unwrap();
        assert_eq!(a.address(), b.address());
    }

    #[test]
    fn device_key_hash_is_0x_64_hex() {
        let h = device_key_hash("0x0000000000000000000000000000000000000000").unwrap();
        assert!(h.starts_with("0x"));
        assert_eq!(h.len(), 66);
    }

    #[test]
    fn ecrecover_rejects_wrong_length() {
        assert!(ecrecover_eip191(b"x", "0x00").is_err());
    }
}
