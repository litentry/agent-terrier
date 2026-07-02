//! Std layer over the device-key crypto for the §10.2 agent bootstrap (#144).
//!
//! The pure secp256k1 / EIP-191 / keccak primitives now live in the `no_std`
//! [`agentkeys_device_core`] crate so the daemon / CLI / broker (native) and the
//! ESP32 firmware (xtensa staticlib) run the SAME bytes (issue #367 anti-drift).
//! This module RE-EXPORTS them — wrapping the fallible ones back into
//! `anyhow::Result` — and adds the host-only pieces device-core deliberately
//! omits: `OsRng` keygen + `0600` file custody ([`DeviceKey`], `write_key_0600`,
//! `enforce_owner_only`, `load_device_key_from_env`). Callers keep importing
//! `agentkeys_core::device_crypto::*` unchanged.
//!
//! The proof-of-possession preimage is the **deployed** one —
//! `keccak256("agentkeys-agent-pop:" || device_key_hash_hex)` — matching
//! `scripts/operator/chain/heima-agent-create.sh` and the on-chain `registerAgentDevice` inputs.
//! (arch.md §10.2 still shows the stale `link_code || D_pub`; the doc is being
//! reconciled to this preimage, not the other way around.)

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use k256::ecdsa::SigningKey;

// The pure secp256k1 / EIP-191 / keccak primitives live in the no_std
// `agentkeys-device-core` crate so the daemon and the ESP32 firmware share ONE
// implementation (issue #367 anti-drift). Re-export the infallible ones verbatim;
// the four fallible ones are thin-wrapped below back into `anyhow::Result`, so
// every `device_crypto::*` caller — and `DeviceKey` — stays byte-identical.
pub use agentkeys_device_core::{
    agent_pop_payload, cap_in_scope, cap_pop_payload, delegation_payload, evm_address, keccak256,
    DeviceCryptoError,
};

/// Verify a single-hop device→sandbox delegation (issue #369): recover the device
/// signer from `delegation_sig` over [`delegation_payload`] and assert
/// `keccak(signer) == device_key_hash`. Returns the recovered device address.
/// Thin `anyhow` wrapper over [`agentkeys_device_core::verify_delegation`] — the
/// WORKER calls this to re-check, independently of the broker, that a sandbox's
/// cap is backed by a device-issued delegation. The caller still enforces
/// `now < expires_at` and that the cap request falls within `scope`.
pub fn verify_delegation(
    device_key_hash_hex: &str,
    sandbox_key: &str,
    scope: &str,
    expires_at: u64,
    delegation_sig: &str,
) -> Result<String> {
    Ok(agentkeys_device_core::verify_delegation(
        device_key_hash_hex,
        sandbox_key,
        scope,
        expires_at,
        delegation_sig,
    )?)
}

/// `device_key_hash = keccak256(address_bytes)` as `0x` + 64 hex.
/// Thin `anyhow` wrapper over [`agentkeys_device_core::device_key_hash`].
pub fn device_key_hash(addr: &str) -> Result<String> {
    Ok(agentkeys_device_core::device_key_hash(addr)?)
}

/// The MASTER device key hash, derived deterministically from the operator omni
/// (issue #220 — `keccak256(operator_omni_bytes)`, the `cast keccak "0x$OMNI"`
/// convention). Thin `anyhow` wrapper over
/// [`agentkeys_device_core::device_key_hash_from_omni`].
pub fn device_key_hash_from_omni(omni: &str) -> Result<String> {
    Ok(agentkeys_device_core::device_key_hash_from_omni(omni)?)
}

/// EIP-191 `personal_sign` over `message` (65-byte `r‖s‖v` hex, `v ∈ {27,28}`).
/// Thin `anyhow` wrapper over [`agentkeys_device_core::eip191_sign`].
pub fn eip191_sign(sk: &SigningKey, message: &[u8]) -> Result<String> {
    Ok(agentkeys_device_core::eip191_sign(sk, message)?)
}

/// EIP-191 ecrecover of the `0x`-lowercase signer address from a 65-byte
/// `r‖s‖v` hex signature. Thin `anyhow` wrapper over
/// [`agentkeys_device_core::ecrecover_eip191`].
pub fn ecrecover_eip191(message: &[u8], signature_hex: &str) -> Result<String> {
    Ok(agentkeys_device_core::ecrecover_eip191(
        message,
        signature_hex,
    )?)
}

/// Load the K10 device key from `AGENTKEYS_DEVICE_KEY_FILE` (default
/// `~/.agentkeys/agent-device.key`) for cap-mint proof-of-possession signing
/// (issue #76). Returns `None` when the file is absent — callers should warn +
/// let cap-mint fail clearly, NOT generate a fresh key here (a fresh key is not
/// registered on chain and the broker/worker would reject every cap it signs).
/// This is the ONE place the cap-mint clients (MCP server, daemon ui-bridge)
/// resolve the agent/master K10, so the path convention stays in sync.
pub fn load_device_key_from_env() -> Option<DeviceKey> {
    let path = std::env::var("AGENTKEYS_DEVICE_KEY_FILE")
        .unwrap_or_else(|_| "~/.agentkeys/agent-device.key".to_string());
    let expanded = expand_home(&path);
    if !Path::new(&expanded).exists() {
        return None;
    }
    DeviceKey::load_or_generate(&expanded, false).ok()
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

    /// Device→sandbox delegation co-signature (issue #369): authorize `sandbox_key`
    /// (the sandbox's OWN ephemeral key) to mint caps on this device's behalf,
    /// bounded by `scope` + `expires_at`. The software twin of the ESP32
    /// `ak_device_delegation_sig` — same [`delegation_payload`] bytes, so a daemon-
    /// hosted device key and a hardware K10 are interchangeable to the worker. Used
    /// when the master daemon delegates to a local sandbox (no ESP32 in the loop).
    pub fn delegation_sig(
        &self,
        sandbox_key: &str,
        scope: &str,
        expires_at: u64,
    ) -> Result<String> {
        let dkh = self.device_key_hash()?;
        self.sign_eip191(&delegation_payload(&dkh, sandbox_key, scope, expires_at))
    }

    /// Per-request cap-mint proof-of-possession signature (issue #76). Signs
    /// [`cap_pop_payload`] with this device key; the worker recovers the signer
    /// and asserts `keccak(address) == device_key_hash`. See [`cap_pop_payload`]
    /// for the threat model. Deterministic given its inputs (used in tests);
    /// call sites should prefer [`DeviceKey::cap_pop_now`].
    #[allow(clippy::too_many_arguments)]
    pub fn cap_pop_sig(
        &self,
        operator_omni: &str,
        actor_omni: &str,
        service: &str,
        op: &str,
        data_class: &str,
        client_nonce: &str,
        client_ts: u64,
    ) -> Result<String> {
        self.sign_eip191(&cap_pop_payload(
            operator_omni,
            actor_omni,
            service,
            op,
            data_class,
            client_nonce,
            client_ts,
        ))
    }

    /// Call-site helper: generate a fresh `(client_sig, client_nonce, client_ts)`
    /// cap-PoP triple for a cap-mint request — random 16-byte nonce + current
    /// unix time, signed with this device key. `op`/`data_class` are the
    /// snake_case strings from the backend-client `CapMintOp` (`op_str()` /
    /// `data_class()`). One-liner for the cap-mint callers (daemon proxy,
    /// ui-bridge, MCP tools).
    pub fn cap_pop_now(
        &self,
        operator_omni: &str,
        actor_omni: &str,
        service: &str,
        op: &str,
        data_class: &str,
    ) -> Result<CapPop> {
        let mut nonce_bytes = [0u8; 16];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let client_nonce = hex::encode(nonce_bytes);
        let client_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let client_sig = self.cap_pop_sig(
            operator_omni,
            actor_omni,
            service,
            op,
            data_class,
            &client_nonce,
            client_ts,
        )?;
        Ok(CapPop {
            client_sig,
            client_nonce,
            client_ts,
        })
    }
}

/// A fresh cap-mint proof-of-possession triple from [`DeviceKey::cap_pop_now`].
#[derive(Debug, Clone)]
pub struct CapPop {
    pub client_sig: String,
    pub client_nonce: String,
    pub client_ts: u64,
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
    fn cap_pop_sig_recovers_to_device_and_matches_hash() {
        // The worker-critical match: recover the signer from cap_pop_sig over
        // cap_pop_payload(...) and check keccak(address) == device_key_hash.
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("dev.key");
        let dk = DeviceKey::load_or_generate(kf.to_str().unwrap(), true).unwrap();
        let (operator, actor, service, op, dc, nonce, ts) = (
            "0xAABB",
            "ccdd",
            "memory:travel",
            "store",
            "memory",
            "0011223344556677",
            1_767_300_000u64,
        );
        let sig = dk
            .cap_pop_sig(operator, actor, service, op, dc, nonce, ts)
            .unwrap();
        let preimage = cap_pop_payload(operator, actor, service, op, dc, nonce, ts);
        let recovered = ecrecover_eip191(&preimage, &sig).unwrap();
        assert_eq!(recovered, dk.address());
        assert_eq!(
            device_key_hash(recovered.as_str()).unwrap(),
            dk.device_key_hash().unwrap()
        );
    }

    #[test]
    fn delegation_sig_round_trips_and_rejects_wrong_device() {
        // The full #369 producer→verifier loop on the native side: a device key
        // co-signs a delegation to a sandbox key, and verify_delegation (what the
        // worker runs) recovers THIS device — but not a different one.
        let dir = tempfile::tempdir().unwrap();
        let device =
            DeviceKey::load_or_generate(dir.path().join("dev.key").to_str().unwrap(), true)
                .unwrap();
        let other =
            DeviceKey::load_or_generate(dir.path().join("other.key").to_str().unwrap(), true)
                .unwrap();
        let sandbox = "0x1563915e194d8cfba1943570603f7606a3115508";
        let scope = "memory:get memory:put";
        let expires = 1_767_300_000u64;

        let sig = device.delegation_sig(sandbox, scope, expires).unwrap();
        let recovered = verify_delegation(
            &device.device_key_hash().unwrap(),
            sandbox,
            scope,
            expires,
            &sig,
        )
        .unwrap();
        assert_eq!(recovered, device.address());

        // The same sig verified against ANOTHER device's hash must fail.
        assert!(verify_delegation(
            &other.device_key_hash().unwrap(),
            sandbox,
            scope,
            expires,
            &sig
        )
        .is_err());
    }

    #[test]
    fn cap_pop_payload_canonicalizes_omni_prefix_and_case() {
        // 0x-prefix + case must not change the preimage (client and worker may
        // hold the omni in different forms).
        let a = cap_pop_payload(
            "0xABCD",
            "0xEF01",
            "openrouter",
            "fetch",
            "credentials",
            "ab",
            9,
        );
        let b = cap_pop_payload(
            "abcd",
            "ef01",
            "openrouter",
            "fetch",
            "credentials",
            "ab",
            9,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn cap_pop_payload_binds_op_and_data_class() {
        // A different op or data_class → different preimage (defense-in-depth
        // vs cross-op cap reuse).
        let base = cap_pop_payload("a", "b", "s", "store", "credentials", "n", 1);
        assert_ne!(
            base,
            cap_pop_payload("a", "b", "s", "fetch", "credentials", "n", 1)
        );
        assert_ne!(
            base,
            cap_pop_payload("a", "b", "s", "store", "memory", "n", 1)
        );
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
