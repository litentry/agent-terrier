//! Agent-side device-session bootstrap — interim §10.2 (full version: issue #144).
//!
//! Runs IN THE SANDBOX (the agent machine), invoked by the wire harness as
//! `agentkeys agent device-session`. Generates (or loads) a secp256k1 device
//! key that NEVER leaves the agent machine, derives the EVM address +
//! `actor_omni`, mints a broker session via the wallet_sig SIWE flow, and emits
//! the values the master needs to bind the device on-chain (`device_key_hash` +
//! agent `pop_sig`) — without ever exposing the private key to the master.
//!
//! This fixes the "master bootstrap" violation: the agent key is born here, in
//! the sandbox, not on the operator laptop. The full HDKD-literal ceremony
//! (broker `/v1/agent/pairing/{request,claim,poll}` + daemon keygen,
//! `O_agent = HDKD(O_master, path)`) is tracked in issue #144 (method A) and
//! supersedes this. Pure-shell can't do EIP-191/secp256k1 and the sandbox has no `cast`, so
//! the crypto lives in the already-deployed `agentkeys` binary; shell drives it.
//!
//! Derivations match the broker's wallet_sig verify
//! (`crates/agentkeys-broker-server/src/plugins/auth/wallet_sig.rs`) and the
//! on-chain `registerAgentDevice` inputs in `scripts/operator/chain/heima-agent-create.sh`:
//!   `device_key_hash = keccak256(address_bytes)`               (cast keccak 0x<addr>)
//!   `actor_omni      = sha256("agentkeys"||"evm"||addr_lc)`     (broker derive_omni_account)
//!   `pop_payload     = keccak256(utf8("agentkeys-agent-pop:" || device_key_hash))`
//!   `pop_sig         = EIP-191(pop_payload)`                    (cast wallet sign)
//!   `session         = wallet_sig SIWE (EIP-191 over siwe_message) -> session JWT`

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::Sha256;
use sha3::{Digest, Keccak256};

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// EVM address = last 20 bytes of keccak256(uncompressed pubkey x‖y).
fn evm_address(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(false);
    let xy = &point.as_bytes()[1..]; // drop the 0x04 SEC1 tag → 64 bytes
    let hash = keccak256(xy);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// EIP-191 personal_sign producing the 65-byte `r‖s‖v` hex (v ∈ {27,28}) that
/// the broker `ecrecover`s. `message` is the raw bytes signed (the SIWE text,
/// or the 32-byte pop_payload). k256 normalizes to low-s, which the broker's
/// verify requires.
fn eip191_sign(sk: &SigningKey, message: &[u8]) -> Result<String> {
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

async fn post_json(client: &reqwest::Client, url: &str, body: Value) -> Result<Value> {
    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("POST {url} -> HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).with_context(|| format!("parse {url} response: {text}"))
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
fn write_key_0600(path: &str, content: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {path} (0600)"))?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_0600(path: &str, content: &str) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("write {path}"))
}

/// Before minting a session from an EXISTING device key, verify it's a regular,
/// owner-only file. A copied/restored key with group/other read bits — or a
/// symlink to another file — would otherwise still mint a valid session,
/// silently breaking the "key never leaves / only the owner can use it"
/// guarantee. We reject (not auto-repair): loose perms mean the key may already
/// have been exposed, so the operator should `chmod 600` it deliberately or
/// `--regen` a fresh one.
#[cfg(unix)]
fn enforce_owner_only(path: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("stat {path}"))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "device key {path} is a symlink — refusing (key-custody); use a real owner-only file or --regen"
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
             it may already be exposed. Run `chmod 600 {path}` (or --regen for a fresh key) and retry."
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_owner_only(_path: &str) -> Result<()> {
    Ok(())
}

/// `agentkeys agent device-session` — generate/load the in-sandbox device key,
/// mint the broker session, emit the JSON the harness feeds to the master for
/// on-chain binding. Returns the JSON string (printed by the caller).
pub async fn device_session(
    broker_url: &str,
    key_file: &str,
    link_code: &str,
    chain_id: u64,
    regen: bool,
) -> Result<String> {
    let key_path = expand_home(key_file);
    if regen {
        let _ = std::fs::remove_file(&key_path);
    }

    let sk = if Path::new(&key_path).exists() {
        // Custody guarantee holds only if the EXISTING key is owner-only — a
        // fresh key is created 0600, but a copied/restored file may be looser
        // (or a symlink to someone else's file). Reject those before minting.
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
    let vk = *sk.verifying_key();
    let address = evm_address(&vk);
    let addr_lc = address.to_lowercase();

    // actor_omni = sha256("agentkeys" || "evm" || addr_lc)
    let mut sh = Sha256::new();
    sh.update(b"agentkeys");
    sh.update(b"evm");
    sh.update(addr_lc.as_bytes());
    let actor_omni = format!("0x{}", hex::encode(sh.finalize()));

    // device_key_hash = keccak256(address_bytes)
    let addr_bytes = hex::decode(&addr_lc[2..]).context("address hex")?;
    let device_key_hash = format!("0x{}", hex::encode(keccak256(&addr_bytes)));

    // pop_sig = EIP-191( keccak256(utf8("agentkeys-agent-pop:" || device_key_hash)) )
    let pop_payload = keccak256(format!("agentkeys-agent-pop:{device_key_hash}").as_bytes());
    let pop_sig = eip191_sign(&sk, &pop_payload)?;

    // wallet_sig SIWE → session JWT (omni == actor_omni)
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("build http client")?;
    let base = broker_url.trim_end_matches('/');
    let start = post_json(
        &client,
        &format!("{base}/v1/auth/wallet/start"),
        json!({ "address": address, "chain_id": chain_id }),
    )
    .await?;
    let request_id = start
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("wallet/start missing request_id: {start}"))?;
    let siwe_message = start
        .get("siwe_message")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("wallet/start missing siwe_message: {start}"))?;
    let sig = eip191_sign(&sk, siwe_message.as_bytes())?;
    let verify = post_json(
        &client,
        &format!("{base}/v1/auth/wallet/verify"),
        json!({ "request_id": request_id, "signature": sig }),
    )
    .await?;
    let session_jwt = verify
        .get("session_jwt")
        .or_else(|| verify.get("jwt"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("wallet/verify missing session JWT: {verify}"))?;

    Ok(serde_json::to_string(&json!({
        "agent_address": address,
        "actor_omni": actor_omni,
        "device_key_hash": device_key_hash,
        "pop_sig": pop_sig,
        "session_jwt": session_jwt,
        "link_code": link_code,
        "key_file": key_path,
    }))?)
}
