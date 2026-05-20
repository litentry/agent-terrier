//! Real WebAuthn enrollment + assertion ceremony — `--webauthn` mode for
//! `agentkeys k11 enroll/assert`.
//!
//! Why a localhost HTTP server: the WebAuthn API (`navigator.credentials
//! .{create,get}`) is browser-only and demands an HTTPS / `http://localhost`
//! origin. We bind a one-shot axum server on `http://localhost:<random>`,
//! open the operator's default browser at it, and the page runs the
//! ceremony. The result is POSTed back to the server; the CLI prints it
//! and exits.
//!
//! Why manual instead of `webauthn-rs`: we need the WebAuthn challenge to
//! equal `sha256(application_message)` for the assert path so the resulting
//! assertion is bound to a specific cap-mint / scope-mutation payload.
//! `webauthn-rs`'s high-level passkey API generates its own random
//! challenge and doesn't expose a public hook to inject ours. Going
//! manual is ~300 LOC and gives us full control over the challenge,
//! signature-over-bytes layout, and storage format.
//!
//! Platform authenticator binding: the JS forces
//! `authenticatorSelection.authenticatorAttachment = "platform"` +
//! `userVerification = "required"`, which on macOS triggers the Touch ID
//! prompt against the Secure Enclave-resident platform passkey. No
//! roaming authenticator (YubiKey) is accepted in this mode — that's a
//! stage-2 multi-authenticator concern.
//!
//! **Stage 1 limitation (codex audit, arch.md §22b.1)**: we DON'T verify
//! the attestation **statement** — only the attested credential data
//! (rpIdHash, UP|UV|AT flags, credentialId-matches-browser-id, COSE
//! pubkey shape). For platform authenticators the operator's JS
//! configures `attestation: "none"`, so the attestation statement is
//! the empty CBOR map and there's nothing meaningful to verify against
//! a vendor metadata service today. The signed-message assert path
//! still gives full cryptographic binding (challenge = sha256(message);
//! ECDSA verify against stored COSE pubkey). Stage 2 (#90) wires in
//! `webauthn-rs` for the enrollment path to validate attestation
//! statements against the FIDO MDS3 metadata service when
//! `attestation != "none"` is requested.

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, response::Html, response::IntoResponse, routing::{get, post}, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

const CEREMONY_TIMEOUT_SECS: u64 = 300;

// Shared CSS injected into both ceremony pages. Native-macOS look:
// system-ui font (matches the Touch ID modal), light/dark adaptive via
// prefers-color-scheme so the page background blends with the OS sheet
// instead of clashing against a stark white. Card layout, monospace
// hex blocks, a primary pill button styled like macOS controls.
const SHARED_CSS: &str = "<style>
  :root {
    --bg: #f5f5f7;
    --fg: #1d1d1f;
    --muted: #6e6e73;
    --card: #ffffff;
    --border: #d2d2d7;
    --hex-bg: #f5f5f7;
    --accent: #0066cc;
    --accent-fg: #ffffff;
    --ok: #248a3d;
    --err: #d70015;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #1a1a1c;
      --fg: #f5f5f7;
      --muted: #98989d;
      --card: #2c2c2e;
      --border: #38383a;
      --hex-bg: #1c1c1e;
      --accent: #0a84ff;
      --accent-fg: #ffffff;
      --ok: #30d158;
      --err: #ff453a;
    }
  }
  html, body {
    background: var(--bg);
    color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text',
                 'Segoe UI', Roboto, sans-serif;
    margin: 0;
    padding: 0;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }
  body {
    display: flex; justify-content: center; align-items: flex-start;
    padding: 4em 1em;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2em 2.25em;
    max-width: 560px;
    width: 100%;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 8px 24px rgba(0,0,0,0.04);
  }
  .brand {
    display: flex; align-items: center; gap: 0.5em;
    color: var(--muted); font-size: 0.85em; letter-spacing: 0.02em;
    text-transform: uppercase; font-weight: 600; margin-bottom: 0.5em;
  }
  .dot {
    width: 8px; height: 8px; background: var(--accent); border-radius: 50%;
  }
  h1 {
    font-size: 1.4em; margin: 0 0 0.25em 0; font-weight: 600;
    letter-spacing: -0.01em;
  }
  .sub { color: var(--muted); margin: 0 0 1.5em 0; font-size: 0.95em; }
  .kv { display: grid; grid-template-columns: max-content 1fr;
        column-gap: 1.5em; row-gap: 0.75em; margin: 0 0 1.5em 0;
        font-size: 0.9em; }
  .kv dt { color: var(--muted); font-weight: 500; }
  .kv dt .kv-meta { color: var(--muted); font-weight: 400;
                    font-size: 0.85em; margin-left: 0.5em; opacity: 0.7; }
  .kv dd { margin: 0; }
  .hex {
    background: var(--hex-bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 0.35em 0.55em;
    font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo,
                 Consolas, monospace;
    font-size: 0.82em; word-break: break-all; line-height: 1.4;
    display: inline-block; max-width: 100%; box-sizing: border-box;
  }
  .hex.msg { display: block; max-height: 6em; overflow-y: auto; }
  .status { color: var(--muted); font-size: 0.92em; margin: 0 0 1em 0; }
  .status.ok { color: var(--ok); }
  .status.err { color: var(--err); }
  button.primary {
    background: var(--accent); color: var(--accent-fg);
    border: none; border-radius: 8px;
    padding: 0.75em 1.5em; font-size: 1em; font-weight: 500;
    font-family: inherit; cursor: pointer;
    transition: opacity 0.15s ease, transform 0.05s ease;
    width: 100%;
  }
  button.primary:hover { opacity: 0.92; }
  button.primary:active { transform: scale(0.99); }
  button.primary:disabled { opacity: 0.5; cursor: default; }
</style>";

#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error("io: {0}")]
    Io(String),
    #[error("bind localhost: {0}")]
    Bind(String),
    #[error("open browser: {0}")]
    BrowserOpen(String),
    #[error("ceremony timed out after {0}s")]
    Timeout(u64),
    #[error("browser POST'd invalid data: {0}")]
    BadPost(String),
    #[error("challenge mismatch: expected {expected}, got {got}")]
    ChallengeMismatch { expected: String, got: String },
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: &'static str, got: String },
    #[error("origin mismatch: expected {expected}, got {got}")]
    OriginMismatch { expected: String, got: String },
    #[error("CBOR decode: {0}")]
    Cbor(String),
    #[error("missing required CBOR field: {0}")]
    MissingField(&'static str),
    #[error("invalid COSE pubkey: {0}")]
    InvalidCosePubkey(String),
    #[error("signature parse: {0}")]
    SigParse(String),
    #[error("signature verify failed")]
    SigInvalid,
    #[error("serde_json: {0}")]
    SerdeJson(String),
    #[error("base64 decode: {0}")]
    B64Decode(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebauthnEnrollment {
    pub operator_omni: String,
    /// `base64url(raw credential id bytes)` — what the browser returns for `id`.
    pub credential_id_b64url: String,
    /// `0x` + 65 hex chars (130 chars) — raw uncompressed P-256 point (`0x04 || X || Y`).
    pub cose_pubkey_hex: String,
    pub enrolled_at_unix: u64,
    /// `"webauthn"` (NOT `"stage1-stub"`).
    pub mode: String,
    /// Optional RP ID override. Default `"localhost"`. Companion daemon mode
    /// uses `"companion.localhost"` to get a SECOND, distinct credential in
    /// the platform keychain on the same Mac.
    #[serde(default)]
    pub rp_id: Option<String>,
}

/// Chain-ready K11 assertion payload — all the fields the on-chain
/// K11Verifier / SidecarRegistry need, pre-extracted from the raw WebAuthn
/// outputs. Produced by [`assert_webauthn_for_chain`] for callers building
/// on-chain `revokeMasterDevice` / `setScopeWithWebauthn` txs.
///
/// Field correspondence with the contracts:
/// - `authenticator_data_hex` → `K11Assertion.authenticatorData`
/// - `client_data_json` (raw bytes; UTF-8 string OK) → `clientDataJSON`
/// - `challenge_location` → byte offset of the value's first char
/// - `r_hex, s_hex` → ECDSA (r, s) components in 0x-prefixed hex (32 bytes each)
/// - `pub_x_hex, pub_y_hex` → P-256 public key coords in 0x-prefixed hex
/// - `expected_challenge_hex` → the 32-byte challenge the contract should
///   reconstruct from operation params + nonce; CLI re-emits it for the
///   operator's eyeball-verify
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct K11ChainAssertion {
    pub operator_omni: String,
    pub credential_id_b64url: String,
    pub authenticator_data_hex: String,
    pub client_data_json_b64url: String,
    pub client_data_json_utf8: String,
    pub challenge_location: usize,
    pub r_hex: String,
    pub s_hex: String,
    pub pub_x_hex: String,
    pub pub_y_hex: String,
    pub expected_challenge_hex: String,
    pub sign_count: u32,
}

#[derive(Debug, Clone, Serialize)]
struct ServerCtx {
    rp_id: String,
    rp_origin: String,
    operator_omni: String,
    /// `base64url(challenge_bytes)` for the browser-side script.
    challenge_b64url: String,
    /// For assert flows: the previously-enrolled credential id (base64url).
    allow_credential_b64url: Option<String>,
    /// For assert flows: the message bytes hex-encoded (display-only).
    message_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EnrollPost {
    /// `base64url(raw credential id bytes)`
    id: String,
    /// `base64url(clientDataJSON)`
    client_data_json: String,
    /// `base64url(attestationObject)`
    attestation_object: String,
}

#[derive(Debug, Deserialize)]
struct AssertPost {
    /// `base64url(raw credential id bytes)`
    id: String,
    /// `base64url(clientDataJSON)`
    client_data_json: String,
    /// `base64url(authenticatorData)`
    authenticator_data: String,
    /// `base64url(signature DER)`
    signature: String,
}

#[derive(Debug, Deserialize)]
struct ClientDataJson {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
}

pub fn enrollment_path(operator_omni: &str) -> PathBuf {
    enrollment_path_with_rp(operator_omni, "localhost")
}

/// rp_id-aware enrollment path so primary (rp_id=localhost) and companion
/// (rp_id=companion.localhost) credentials live in distinct files.
/// Backward-compat: `rp_id=localhost` yields the original filename
/// `<omni>.json` so existing primary enrollments still load.
pub fn enrollment_path_with_rp(operator_omni: &str, rp_id: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let suffix = if rp_id == "localhost" {
        String::new()
    } else {
        format!("--{rp_id}")
    };
    PathBuf::from(home)
        .join(".agentkeys")
        .join("k11")
        .join(format!(
            "{}{suffix}.json",
            operator_omni.trim_start_matches("0x")
        ))
}

/// Run the enrollment ceremony. Blocks (awaits) until the browser POSTs
/// back or the 5-minute timeout fires. Persists the result to
/// `~/.agentkeys/k11/<omni>.json` (mode 0600).
///
/// Async — call from inside an existing tokio runtime (e.g. the CLI's
/// `#[tokio::main]`). Creating a nested runtime via `block_on` panics
/// with "Cannot start a runtime from within a runtime".
pub async fn enroll_webauthn(operator_omni: &str) -> Result<WebauthnEnrollment, WebauthnError> {
    enroll_webauthn_inner(operator_omni, "localhost").await
}

/// Same as [`enroll_webauthn`] but with a configurable RP ID. The companion
/// daemon uses RP ID `"companion.localhost"` so the platform keychain
/// creates a distinct passkey from the primary daemon on the same Mac.
pub async fn enroll_webauthn_with_rp(
    operator_omni: &str,
    rp_id: &str,
) -> Result<WebauthnEnrollment, WebauthnError> {
    enroll_webauthn_inner(operator_omni, rp_id).await
}

/// Run the assert ceremony. Returns the assertion bytes
/// (`authenticatorData || clientDataJSON || signature`).
pub async fn assert_webauthn(
    operator_omni: &str,
    message: &[u8],
) -> Result<Vec<u8>, WebauthnError> {
    assert_webauthn_inner(operator_omni, message, "localhost").await
}

/// Same as [`assert_webauthn`] but for the companion daemon — uses RP ID
/// `"companion.localhost"` so the platform keychain creates a SECOND,
/// distinct passkey on the same Mac.
pub async fn assert_webauthn_with_rp(
    operator_omni: &str,
    message: &[u8],
    rp_id: &str,
) -> Result<Vec<u8>, WebauthnError> {
    assert_webauthn_inner(operator_omni, message, rp_id).await
}

/// Chain-ready variant: runs the ceremony, then post-processes the result
/// into the exact field set the on-chain K11Verifier needs (r, s as 256-bit
/// integers, pubX, pubY, authData, clientDataJSON, challengeLocation, sign
/// count). The `expected_challenge` param MUST be the same 32-byte value the
/// on-chain contract will reconstruct from operation params + nonce — we
/// re-emit it in the output so the caller can sanity-check before broadcasting.
pub async fn assert_webauthn_for_chain(
    operator_omni: &str,
    expected_challenge: [u8; 32],
    rp_id: &str,
) -> Result<K11ChainAssertion, WebauthnError> {
    let enrollment = load_enrollment_with_rp(operator_omni, rp_id)?;
    let parts = assert_webauthn_inner_parts(operator_omni, expected_challenge, rp_id).await?;
    extract_chain_assertion(&enrollment, expected_challenge, &parts)
}

async fn enroll_webauthn_inner(
    operator_omni: &str,
    rp_id: &str,
) -> Result<WebauthnEnrollment, WebauthnError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| WebauthnError::Bind(e.to_string()))?;
    let local_addr = listener.local_addr().map_err(|e| WebauthnError::Bind(e.to_string()))?;
    let port = local_addr.port();
    // Bind URL uses 127.0.0.1; but the browser must see the RP ID (e.g.
    // `companion.localhost` for the companion daemon) as the effective
    // domain. Modern Chrome/Safari treat `*.localhost` as loopback so
    // `http://companion.localhost:PORT` resolves without /etc/hosts.
    let rp_origin = format!("http://{rp_id}:{port}");

    let mut challenge_bytes = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut challenge_bytes);
    let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge_bytes);

    let ctx = Arc::new(ServerCtx {
        rp_id: rp_id.to_string(),
        rp_origin: rp_origin.clone(),
        operator_omni: operator_omni.to_string(),
        challenge_b64url: challenge_b64url.clone(),
        allow_credential_b64url: None,
        message_hex: None,
    });

    let (tx, rx) = oneshot::channel::<EnrollPost>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let app = Router::new()
        .route("/", get(serve_enroll_page))
        .route("/finish", post({
            let tx = tx.clone();
            move |_: State<Arc<ServerCtx>>, Json(body): Json<EnrollPost>| {
                let tx = tx.clone();
                async move {
                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send(body);
                    }
                    (StatusCode::OK, "ok")
                }
            }
        }))
        .with_state(ctx.clone());

    let server_task = tokio::spawn(async move {
        axum::serve(listener, app).await
    });

    // Open the default browser (macOS: `open`; Linux: `xdg-open`; Windows: `start`).
    open_in_browser(&rp_origin)?;

    eprintln!(
        "==> waiting for WebAuthn enrollment in browser at {rp_origin}\n\
        ==> macOS Touch ID prompt should appear in your browser…\n\
        ==> timing out after {CEREMONY_TIMEOUT_SECS}s"
    );

    // RAII abort guard — fires server_task.abort() on every exit path
    // including the timeout-error-return below. Codex audit: the prior
    // `server_task.abort()` after the `?`s was unreachable on early
    // returns and the server would dangle until process exit.
    let _abort_guard = AbortOnDrop(server_task);
    let post = tokio::time::timeout(Duration::from_secs(CEREMONY_TIMEOUT_SECS), rx)
        .await
        .map_err(|_| WebauthnError::Timeout(CEREMONY_TIMEOUT_SECS))?
        .map_err(|e| WebauthnError::Io(format!("oneshot recv: {e}")))?;

    let enrollment = finalize_enroll(operator_omni, rp_id, &challenge_b64url, &rp_origin, &post)?;
    persist_enrollment(&enrollment)?;
    Ok(enrollment)
}

async fn assert_webauthn_inner(
    operator_omni: &str,
    message: &[u8],
    rp_id: &str,
) -> Result<Vec<u8>, WebauthnError> {
    // Legacy callers pass arbitrary-length message bytes; we sha256 them
    // to fit WebAuthn's 32-byte challenge slot. This produces an assertion
    // bound to the message (challenge ≡ sha256(message)) but is NOT
    // suitable for chain submission — the contract expects challenge to
    // BE the operation hash, not sha256(operation hash). Use
    // `assert_webauthn_for_chain` for that path.
    let mut h = Sha256::new();
    h.update(message);
    let challenge_bytes: [u8; 32] = h.finalize().into();
    let parts = assert_webauthn_inner_parts(operator_omni, challenge_bytes, rp_id).await?;
    let mut out = Vec::with_capacity(
        parts.authenticator_data.len() + parts.client_data_json.len() + parts.signature_der.len(),
    );
    out.extend_from_slice(&parts.authenticator_data);
    out.extend_from_slice(&parts.client_data_json);
    out.extend_from_slice(&parts.signature_der);
    Ok(out)
}

async fn assert_webauthn_inner_parts(
    operator_omni: &str,
    challenge_bytes: [u8; 32],
    rp_id: &str,
) -> Result<AssertParts, WebauthnError> {
    // Load the previously-enrolled credential for THIS rp_id (primary vs
    // companion live in distinct files; see enrollment_path_with_rp).
    let enrollment = load_enrollment_with_rp(operator_omni, rp_id)?;
    // Sanity: the stored rp_id should match what we asked for. If not, the
    // file was written by an older CLI; reject so the user re-enrolls cleanly.
    let enrolled_rp = enrollment.rp_id.clone().unwrap_or_else(|| "localhost".to_string());
    if enrolled_rp != rp_id {
        return Err(WebauthnError::Io(format!(
            "K11 credential at ~/.agentkeys/k11/{}--{rp_id}.json was enrolled with rp_id={enrolled_rp:?} \
             but assert was called with rp_id={rp_id:?}. Re-enroll the credential with the \
             matching --rp-id flag.",
            operator_omni.trim_start_matches("0x")
        )));
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| WebauthnError::Bind(e.to_string()))?;
    let port = listener.local_addr().map_err(|e| WebauthnError::Bind(e.to_string()))?.port();
    let rp_origin = format!("http://{rp_id}:{port}");

    // The 32-byte challenge passed in IS the value WebAuthn signs over (no
    // additional hashing). Caller is responsible for deciding whether to
    // pre-hash an arbitrary message (legacy callers) or pass a pre-computed
    // 32-byte commitment (chain submission via assert_webauthn_for_chain).
    let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge_bytes);

    let ctx = Arc::new(ServerCtx {
        rp_id: rp_id.to_string(),
        rp_origin: rp_origin.clone(),
        operator_omni: operator_omni.to_string(),
        challenge_b64url: challenge_b64url.clone(),
        allow_credential_b64url: Some(enrollment.credential_id_b64url.clone()),
        message_hex: Some(hex::encode(challenge_bytes)),
    });

    let (tx, rx) = oneshot::channel::<AssertPost>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let app = Router::new()
        .route("/", get(serve_assert_page))
        .route("/finish", post({
            let tx = tx.clone();
            move |_: State<Arc<ServerCtx>>, Json(body): Json<AssertPost>| {
                let tx = tx.clone();
                async move {
                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send(body);
                    }
                    (StatusCode::OK, "ok")
                }
            }
        }))
        .with_state(ctx.clone());

    let server_task = tokio::spawn(async move {
        axum::serve(listener, app).await
    });

    open_in_browser(&rp_origin)?;

    eprintln!(
        "==> waiting for WebAuthn assertion in browser at {rp_origin}\n\
        ==> macOS Touch ID prompt should appear in your browser…\n\
        ==> signing over message hash 0x{}\n\
        ==> timing out after {CEREMONY_TIMEOUT_SECS}s",
        hex::encode(challenge_bytes)
    );

    // RAII abort guard — fires server_task.abort() on every exit path
    // including the timeout-error-return below. Codex audit: the prior
    // `server_task.abort()` after the `?`s was unreachable on early
    // returns and the server would dangle until process exit.
    let _abort_guard = AbortOnDrop(server_task);
    let post = tokio::time::timeout(Duration::from_secs(CEREMONY_TIMEOUT_SECS), rx)
        .await
        .map_err(|_| WebauthnError::Timeout(CEREMONY_TIMEOUT_SECS))?
        .map_err(|e| WebauthnError::Io(format!("oneshot recv: {e}")))?;

    finalize_assert_parts(&enrollment, &challenge_b64url, &rp_origin, &post)
}

/// RAII guard: when dropped, aborts the wrapped tokio task. Used to
/// guarantee the local ceremony server is shut down on every exit path
/// from `enroll_webauthn_async` / `assert_webauthn_async` (including
/// the timeout-error early-return).
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn open_in_browser(url: &str) -> Result<(), WebauthnError> {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "start"
    } else {
        "xdg-open"
    };
    std::process::Command::new(cmd)
        .arg(url)
        .spawn()
        .map_err(|e| WebauthnError::BrowserOpen(format!("{cmd} {url}: {e}")))?;
    Ok(())
}

fn finalize_enroll(
    operator_omni: &str,
    rp_id: &str,
    expected_challenge: &str,
    expected_origin: &str,
    post: &EnrollPost,
) -> Result<WebauthnEnrollment, WebauthnError> {
    let client_data_bytes = URL_SAFE_NO_PAD
        .decode(&post.client_data_json)
        .map_err(|e| WebauthnError::B64Decode(format!("clientDataJSON: {e}")))?;
    let cd: ClientDataJson = serde_json::from_slice(&client_data_bytes)
        .map_err(|e| WebauthnError::SerdeJson(format!("clientDataJSON: {e}")))?;
    if cd.ty != "webauthn.create" {
        return Err(WebauthnError::TypeMismatch { expected: "webauthn.create", got: cd.ty });
    }
    if cd.challenge != expected_challenge {
        return Err(WebauthnError::ChallengeMismatch {
            expected: expected_challenge.to_string(),
            got: cd.challenge,
        });
    }
    if cd.origin != expected_origin {
        return Err(WebauthnError::OriginMismatch {
            expected: expected_origin.to_string(),
            got: cd.origin,
        });
    }

    let attestation_bytes = URL_SAFE_NO_PAD
        .decode(&post.attestation_object)
        .map_err(|e| WebauthnError::B64Decode(format!("attestationObject: {e}")))?;
    let parsed = extract_attested_credential(&attestation_bytes)?;

    // Verify the credential id the browser sent in `cred.id` matches the
    // credentialId the authenticator placed inside attestedCredentialData.
    // Without this check, a malicious page could substitute an arbitrary
    // id (codex audit finding).
    let post_cred_id = URL_SAFE_NO_PAD
        .decode(&post.id)
        .map_err(|e| WebauthnError::B64Decode(format!("credential id: {e}")))?;
    if post_cred_id != parsed.credential_id {
        return Err(WebauthnError::Cbor(format!(
            "credential id mismatch: browser sent {} bytes, authenticator bound {} bytes",
            post_cred_id.len(),
            parsed.credential_id.len()
        )));
    }

    // Verify rpIdHash == sha256(rp_id). This binds the credential to our
    // relying party so a passkey enrolled against a different RP can't be
    // replayed here. Primary daemon: rp_id = "localhost". Companion daemon:
    // "companion.localhost".
    let mut h = Sha256::new();
    h.update(rp_id.as_bytes());
    let expected_rp_id_hash = h.finalize();
    if parsed.rp_id_hash != expected_rp_id_hash.as_slice() {
        return Err(WebauthnError::Cbor(format!(
            "rpIdHash mismatch: expected sha256({rp_id:?}), got {}",
            hex::encode(&parsed.rp_id_hash)
        )));
    }

    // Verify flags require user-presence + user-verified + attested-credential-data.
    // FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_AT = 0x40.
    const FLAG_UP: u8 = 0x01;
    const FLAG_UV: u8 = 0x04;
    const FLAG_AT: u8 = 0x40;
    if (parsed.flags & (FLAG_UP | FLAG_UV | FLAG_AT)) != (FLAG_UP | FLAG_UV | FLAG_AT) {
        return Err(WebauthnError::Cbor(format!(
            "authData flags missing UP/UV/AT bits (got 0x{:02x})",
            parsed.flags
        )));
    }

    Ok(WebauthnEnrollment {
        operator_omni: operator_omni.to_string(),
        credential_id_b64url: post.id.clone(),
        cose_pubkey_hex: format!("0x{}", hex::encode(&parsed.cose_pubkey)),
        enrolled_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        mode: "webauthn".to_string(),
        rp_id: Some(rp_id.to_string()),
    })
}

/// Verified parts of a WebAuthn assertion — extracted from the raw post and
/// ready for either chain submission (use [`extract_chain_assertion`]) or the
/// flat-bytes legacy format ([`finalize_assert`]).
pub struct AssertParts {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature_der: Vec<u8>,
}

fn finalize_assert_parts(
    enrollment: &WebauthnEnrollment,
    expected_challenge: &str,
    expected_origin: &str,
    post: &AssertPost,
) -> Result<AssertParts, WebauthnError> {
    // Cross-check credential id, parse clientDataJSON, verify sig, return
    // the three parts so the caller can pick the output format.
    if post.id != enrollment.credential_id_b64url {
        return Err(WebauthnError::Cbor(format!(
            "assertion credential id ({}) doesn't match enrolled credential ({})",
            post.id, enrollment.credential_id_b64url
        )));
    }
    let client_data_bytes = URL_SAFE_NO_PAD
        .decode(&post.client_data_json)
        .map_err(|e| WebauthnError::B64Decode(format!("clientDataJSON: {e}")))?;
    let cd: ClientDataJson = serde_json::from_slice(&client_data_bytes)
        .map_err(|e| WebauthnError::SerdeJson(format!("clientDataJSON: {e}")))?;
    if cd.ty != "webauthn.get" {
        return Err(WebauthnError::TypeMismatch { expected: "webauthn.get", got: cd.ty });
    }
    if cd.challenge != expected_challenge {
        return Err(WebauthnError::ChallengeMismatch {
            expected: expected_challenge.to_string(),
            got: cd.challenge,
        });
    }
    if cd.origin != expected_origin {
        return Err(WebauthnError::OriginMismatch {
            expected: expected_origin.to_string(),
            got: cd.origin,
        });
    }
    let authenticator_data = URL_SAFE_NO_PAD
        .decode(&post.authenticator_data)
        .map_err(|e| WebauthnError::B64Decode(format!("authenticatorData: {e}")))?;
    let signature_der = URL_SAFE_NO_PAD
        .decode(&post.signature)
        .map_err(|e| WebauthnError::B64Decode(format!("signature: {e}")))?;
    let mut h = Sha256::new();
    h.update(&client_data_bytes);
    let cd_hash = h.finalize();
    let mut signed_bytes = Vec::with_capacity(authenticator_data.len() + cd_hash.len());
    signed_bytes.extend_from_slice(&authenticator_data);
    signed_bytes.extend_from_slice(&cd_hash);
    let pubkey_hex = enrollment.cose_pubkey_hex.trim_start_matches("0x");
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| WebauthnError::InvalidCosePubkey(format!("hex: {e}")))?;
    let encoded_point = p256::EncodedPoint::from_bytes(&pubkey_bytes)
        .map_err(|e| WebauthnError::InvalidCosePubkey(e.to_string()))?;
    let pubkey = p256::PublicKey::from_encoded_point(&encoded_point);
    let pubkey = if pubkey.is_some().into() {
        pubkey.unwrap()
    } else {
        return Err(WebauthnError::InvalidCosePubkey("not on curve".into()));
    };
    let verifying_key = VerifyingKey::from(pubkey);
    let sig = Signature::from_der(&signature_der)
        .map_err(|e| WebauthnError::SigParse(e.to_string()))?;
    verifying_key
        .verify(&signed_bytes, &sig)
        .map_err(|_| WebauthnError::SigInvalid)?;
    Ok(AssertParts { authenticator_data, client_data_json: client_data_bytes, signature_der })
}

/// Convert verified WebAuthn assertion parts into the chain-ready payload
/// (r, s decimal-extracted from DER, pubkey coords split, challenge location
/// in clientDataJSON found, etc.). The contract uses these fields to verify
/// the assertion on chain via [K11Verifier].
pub fn extract_chain_assertion(
    enrollment: &WebauthnEnrollment,
    expected_challenge: [u8; 32],
    parts: &AssertParts,
) -> Result<K11ChainAssertion, WebauthnError> {
    // Parse DER signature → (r, s) as 32-byte big-endian integers.
    let sig = Signature::from_der(&parts.signature_der)
        .map_err(|e| WebauthnError::SigParse(format!("der → (r,s): {e}")))?;
    let sig_bytes = sig.to_bytes(); // 64 bytes: r || s
    if sig_bytes.len() != 64 {
        return Err(WebauthnError::SigParse(format!(
            "sig.to_bytes() returned {} bytes; expected 64",
            sig_bytes.len()
        )));
    }
    let r_hex = format!("0x{}", hex::encode(&sig_bytes[0..32]));
    let s_hex = format!("0x{}", hex::encode(&sig_bytes[32..64]));

    // Split COSE pubkey into X, Y.
    let pk_hex = enrollment.cose_pubkey_hex.trim_start_matches("0x");
    let pk_bytes = hex::decode(pk_hex)
        .map_err(|e| WebauthnError::InvalidCosePubkey(format!("hex: {e}")))?;
    if pk_bytes.len() != 65 || pk_bytes[0] != 0x04 {
        return Err(WebauthnError::InvalidCosePubkey(format!(
            "expected 0x04 || X(32) || Y(32) = 65 bytes; got {} bytes",
            pk_bytes.len()
        )));
    }
    let pub_x_hex = format!("0x{}", hex::encode(&pk_bytes[1..33]));
    let pub_y_hex = format!("0x{}", hex::encode(&pk_bytes[33..65]));

    // Find the challenge location in clientDataJSON (byte offset of the
    // value's first char). Search for the literal `"challenge":"` prefix.
    let cdj_utf8 = std::str::from_utf8(&parts.client_data_json)
        .map_err(|e| WebauthnError::SerdeJson(format!("cdj utf-8: {e}")))?;
    let needle = "\"challenge\":\"";
    let challenge_location = cdj_utf8
        .find(needle)
        .map(|p| p + needle.len())
        .ok_or_else(|| {
            WebauthnError::SerdeJson(format!(
                "clientDataJSON missing {needle:?} prefix: {cdj_utf8}"
            ))
        })?;

    // Extract sign count from authData[33..37] (big-endian uint32).
    if parts.authenticator_data.len() < 37 {
        return Err(WebauthnError::Cbor(format!(
            "authenticatorData {} bytes; expected ≥ 37",
            parts.authenticator_data.len()
        )));
    }
    let sign_count = u32::from_be_bytes([
        parts.authenticator_data[33],
        parts.authenticator_data[34],
        parts.authenticator_data[35],
        parts.authenticator_data[36],
    ]);

    Ok(K11ChainAssertion {
        operator_omni: enrollment.operator_omni.clone(),
        credential_id_b64url: enrollment.credential_id_b64url.clone(),
        authenticator_data_hex: format!("0x{}", hex::encode(&parts.authenticator_data)),
        client_data_json_b64url: URL_SAFE_NO_PAD.encode(&parts.client_data_json),
        client_data_json_utf8: cdj_utf8.to_string(),
        challenge_location,
        r_hex,
        s_hex,
        pub_x_hex,
        pub_y_hex,
        expected_challenge_hex: format!("0x{}", hex::encode(expected_challenge)),
        sign_count,
    })
}

struct AttestedCredential {
    rp_id_hash: Vec<u8>,
    flags: u8,
    credential_id: Vec<u8>,
    /// Raw uncompressed P-256 pubkey (`0x04 || X || Y`, 65 bytes).
    cose_pubkey: Vec<u8>,
}

/// Walk the attestationObject CBOR, return rpIdHash + flags + credentialId +
/// COSE pubkey extracted from authData.attestedCredentialData. Returning
/// all four lets the caller bind the enrollment to the relying party
/// (rpIdHash) AND verify the credential id the browser sent matches the
/// authenticator-bound one (codex audit finding).
fn extract_attested_credential(att_obj_bytes: &[u8]) -> Result<AttestedCredential, WebauthnError> {
    // attestationObject is CBOR: { "fmt": str, "attStmt": map, "authData": bytes }
    let value: ciborium::Value = ciborium::from_reader(Cursor::new(att_obj_bytes))
        .map_err(|e| WebauthnError::Cbor(format!("attestationObject root: {e}")))?;
    let map = value.as_map().ok_or(WebauthnError::MissingField("attestationObject not a map"))?;
    let auth_data_bytes = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.as_bytes())
        .ok_or(WebauthnError::MissingField("authData"))?;

    // authData layout (per WebAuthn spec):
    //   rpIdHash       (32 bytes)
    //   flags          (1 byte)
    //   signCount      (4 bytes)
    //   attestedCredentialData {
    //     aaguid       (16 bytes)
    //     credentialIdLength (2 bytes, big-endian)
    //     credentialId (credentialIdLength bytes)
    //     credentialPublicKey (CBOR-encoded COSEKey, variable length)
    //   }
    if auth_data_bytes.len() < 37 + 16 + 2 {
        return Err(WebauthnError::Cbor(format!(
            "authData too short ({} bytes; need ≥ 55 for attestedCredentialData)",
            auth_data_bytes.len()
        )));
    }
    let rp_id_hash = auth_data_bytes[0..32].to_vec();
    let flags = auth_data_bytes[32];
    // bytes 33..37 = signCount (4 BE bytes) — not used here
    // bytes 37..53 = aaguid (16 bytes) — not used here
    let cred_id_len = u16::from_be_bytes([auth_data_bytes[53], auth_data_bytes[54]]) as usize;
    let cred_id_start = 55;
    let cred_id_end = cred_id_start + cred_id_len;
    if auth_data_bytes.len() <= cred_id_end {
        return Err(WebauthnError::Cbor("authData missing credentialPublicKey".into()));
    }
    let credential_id = auth_data_bytes[cred_id_start..cred_id_end].to_vec();
    let cose_bytes = &auth_data_bytes[cred_id_end..];
    let cose: ciborium::Value = ciborium::from_reader(Cursor::new(cose_bytes))
        .map_err(|e| WebauthnError::Cbor(format!("COSE pubkey: {e}")))?;
    let cose_map = cose.as_map().ok_or(WebauthnError::MissingField("COSE pubkey not a map"))?;
    // COSE labels: -2 = x, -3 = y (for EC2 keys). 1 = kty (should be 2 = EC2). 3 = alg (should be -7 = ES256).
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    for (k, v) in cose_map {
        if let Some(i) = k.as_integer() {
            // ciborium 0.2: clippy claims Integer is Copy + Into<i128>, but
            // rustc rejects `*i` with E0614 "cannot be dereferenced" and
            // there's no public &Integer→i128 path. clone-then-try_from
            // is the only working form. Silence the two lints below.
            #[allow(clippy::clone_on_copy, clippy::unnecessary_fallible_conversions)]
            let lab: i128 = match i128::try_from(i.clone()) {
                Ok(n) => n,
                Err(_) => continue,
            };
            match lab {
                -2 => x = v.as_bytes().cloned(),
                -3 => y = v.as_bytes().cloned(),
                _ => {}
            }
        }
    }
    let x = x.ok_or(WebauthnError::MissingField("COSE pubkey x"))?;
    let y = y.ok_or(WebauthnError::MissingField("COSE pubkey y"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(WebauthnError::InvalidCosePubkey(format!(
            "expected 32-byte X+Y, got {}+{}",
            x.len(),
            y.len()
        )));
    }
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    Ok(AttestedCredential {
        rp_id_hash,
        flags,
        credential_id,
        cose_pubkey: uncompressed,
    })
}

pub fn persist_enrollment(enrollment: &WebauthnEnrollment) -> Result<(), WebauthnError> {
    let rp_id = enrollment.rp_id.as_deref().unwrap_or("localhost");
    let path = enrollment_path_with_rp(&enrollment.operator_omni, rp_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| WebauthnError::Io(e.to_string()))?;
    }
    let json = serde_json::to_vec_pretty(enrollment)
        .map_err(|e| WebauthnError::SerdeJson(e.to_string()))?;
    fs::write(&path, json).map_err(|e| WebauthnError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .map_err(|e| WebauthnError::Io(e.to_string()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).map_err(|e| WebauthnError::Io(e.to_string()))?;
    }
    Ok(())
}

pub fn load_enrollment(operator_omni: &str) -> Result<WebauthnEnrollment, WebauthnError> {
    load_enrollment_with_rp(operator_omni, "localhost")
}

pub fn load_enrollment_with_rp(
    operator_omni: &str,
    rp_id: &str,
) -> Result<WebauthnEnrollment, WebauthnError> {
    let path = enrollment_path_with_rp(operator_omni, rp_id);
    let bytes = fs::read(&path).map_err(|e| WebauthnError::Io(format!("read {path:?}: {e}")))?;
    let enrollment: WebauthnEnrollment = serde_json::from_slice(&bytes)
        .map_err(|e| WebauthnError::SerdeJson(format!("parse {path:?}: {e}")))?;
    if enrollment.mode != "webauthn" {
        return Err(WebauthnError::Io(format!(
            "stored enrollment at {path:?} is mode={:?} not 'webauthn' — re-enroll with --webauthn first",
            enrollment.mode
        )));
    }
    Ok(enrollment)
}

// ─── HTML handlers (one-shot ceremony pages) ──────────────────────────

async fn serve_enroll_page(State(ctx): State<Arc<ServerCtx>>) -> impl IntoResponse {
    let is_companion = ctx.rp_id.contains("companion");
    let role_label = if is_companion { "COMPANION MASTER" } else { "PRIMARY MASTER" };
    let role_tagline = if is_companion {
        "Bind a SECOND platform passkey for M-of-N recovery quorum."
    } else {
        "Bind a platform passkey for master-tier authorisation."
    };
    let role_accent = if is_companion { "#a855f7" } else { "#0a84ff" };
    let role_emoji = if is_companion { "🛡️" } else { "🔑" };
    // Short, human-readable name shown by macOS in the Touch ID dialog
    // ("Use Touch ID to sign in to 'localhost' with your passkey for ..."
    // — macOS displays user.name there, NOT the full omni hex).
    let user_name_short = if is_companion {
        "AgentKeys Companion Master"
    } else {
        "AgentKeys Primary Master"
    };
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>AgentKeys — Enroll {role_label}</title>
{shared_css}
<style>
  .card {{ border-top: 4px solid {role_accent}; }}
  .role-badge {{
    display: inline-flex; align-items: center; gap: 0.4em;
    background: {role_accent}; color: white;
    padding: 0.35em 0.75em; border-radius: 6px;
    font-size: 0.85em; font-weight: 600; letter-spacing: 0.04em;
    margin-bottom: 0.5em;
  }}
  button.primary {{ background: {role_accent}; }}
</style>
</head><body>
<main class="card">
  <header>
    <div class="role-badge"><span>{role_emoji}</span> {role_label}</div>
    <h1>K11 enrollment</h1>
    <p class="sub">{role_tagline}</p>
  </header>
  <section class="kv">
    <dt>Operator</dt>
    <dd><code class="hex">{omni}</code></dd>
    <dt>RP ID</dt>
    <dd><code class="hex">{rp_id_display}</code></dd>
    <dt>Authenticator</dt>
    <dd>Platform (Touch ID / Windows Hello / Secure Enclave)</dd>
    <dt>Algorithm</dt>
    <dd>ECDSA P-256 / SHA-256 (ES256)</dd>
  </section>
  <p id="status" class="status">Press the button below. macOS will prompt for Touch ID.</p>
  <button id="go" class="primary">Enroll as {role_label}</button>
</main>
<script>
const challenge = "{challenge}";
const omni = "{omni}";
function b64urlDecode(s) {{
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}}
function b64urlEncode(buf) {{
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}}
// operator_omni is a 32-byte SHA-256 digest in 0x-prefixed hex form.
// WebAuthn caps user.id at 64 bytes — the UTF-8-encoded hex string is
// 66 bytes which the browser rejects. Decode to the raw 32 bytes.
function hexToBytes(hex) {{
  const clean = hex.replace(/^0x/i, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {{
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }}
  return out;
}}
document.getElementById('go').onclick = async () => {{
  const status = document.getElementById('status');
  try {{
    const cred = await navigator.credentials.create({{
      publicKey: {{
        rp: {{ id: "{rp_id_js}", name: "AgentKeys" }},
        user: {{
          // user.id: 32 raw bytes derived from operator_omni (WebAuthn caps
          // id at 64 bytes; the 66-byte UTF-8 hex string would be rejected).
          id: hexToBytes(omni),
          // user.name: shown by macOS in the Touch ID dialog ("Use Touch ID
          // to sign in to ... with your passkey for <NAME>"). Keep it short
          // and human-readable; append a 10-char omni prefix for disambig
          // across operators.
          name: "{user_name_short} (" + omni.substring(0, 10) + "…)",
          displayName: "{user_name_short}"
        }},
        challenge: b64urlDecode(challenge),
        // ES256-only: the on-chain verifier (when EIP-7212 P-256 ships on
        // Heima) only knows P-256/SHA-256. RS256 keys would be unverifiable.
        // Chromium logs a warning about "missing RS256 default" — safe to
        // ignore for our platform-authenticator-only target (Touch ID,
        // Windows Hello, Secure Enclave all support ES256 natively).
        pubKeyCredParams: [{{ alg: -7, type: "public-key" }}],
        authenticatorSelection: {{
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "preferred"
        }},
        timeout: 60000,
        attestation: "none"
      }}
    }});
    const resp = cred.response;
    const payload = {{
      id: cred.id,
      client_data_json: b64urlEncode(resp.clientDataJSON),
      attestation_object: b64urlEncode(resp.attestationObject)
    }};
    const r = await fetch("/finish", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload)
    }});
    if (r.ok) {{
      status.className = 'status ok';
      status.textContent = '✓ Enrollment complete — you can close this tab.';
      document.getElementById('go').disabled = true;
    }} else {{
      status.className = 'status err';
      status.textContent = '✗ Server rejected: ' + r.status;
    }}
  }} catch (e) {{
    status.className = 'status err';
    status.textContent = '✗ ' + e.message;
  }}
}};
</script>
</body></html>"##,
        omni = ctx.operator_omni,
        challenge = ctx.challenge_b64url,
        shared_css = SHARED_CSS,
        rp_id_js = ctx.rp_id,
        rp_id_display = ctx.rp_id,
        role_label = role_label,
        role_tagline = role_tagline,
        role_accent = role_accent,
        role_emoji = role_emoji,
        user_name_short = user_name_short,
    );
    Html(html)
}

async fn serve_assert_page(State(ctx): State<Arc<ServerCtx>>) -> impl IntoResponse {
    let cred_id = ctx.allow_credential_b64url.as_deref().unwrap_or("");
    let msg_hex = ctx.message_hex.as_deref().unwrap_or("");
    // Distinguish primary from companion in the UI: the operator may be
    // about to tap Touch ID for either role and the macOS prompt itself
    // doesn't say which credential — so we surface it here loudly.
    let is_companion = ctx.rp_id.contains("companion");
    let role_label = if is_companion { "COMPANION MASTER" } else { "PRIMARY MASTER" };
    let role_tagline = if is_companion {
        "Second device authorizing an M-of-N quorum operation."
    } else {
        "Original device authorizing a master-mutation."
    };
    let role_accent = if is_companion { "#a855f7" } else { "#0a84ff" }; // purple vs blue
    let role_emoji = if is_companion { "🛡️" } else { "🔑" };
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>AgentKeys — {role_label}</title>
{shared_css}
<style>
  .card {{ border-top: 4px solid {role_accent}; }}
  .role-badge {{
    display: inline-flex; align-items: center; gap: 0.4em;
    background: {role_accent}; color: white;
    padding: 0.35em 0.75em; border-radius: 6px;
    font-size: 0.85em; font-weight: 600; letter-spacing: 0.04em;
    margin-bottom: 0.5em;
  }}
  .role-badge .emoji {{ font-size: 1.1em; }}
  button.primary {{ background: {role_accent}; }}
  .rp-callout {{
    background: rgba(0,0,0,0.04);
    border: 1px solid rgba(0,0,0,0.08);
    border-left: 3px solid {role_accent};
    border-radius: 6px;
    padding: 0.6em 0.8em;
    margin: 0 0 1em 0;
    font-size: 0.9em;
  }}
  @media (prefers-color-scheme: dark) {{
    .rp-callout {{ background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.1); }}
  }}
  .rp-callout strong {{ color: {role_accent}; }}
</style>
</head><body>
<main class="card">
  <header>
    <div class="role-badge"><span class="emoji">{role_emoji}</span> {role_label}</div>
    <h1>K11 assertion</h1>
    <p class="sub">{role_tagline}</p>
    <div class="rp-callout">
      About to sign with the passkey bound to <strong>{rp_id_display}</strong>.
      Make sure the Touch ID prompt shows this RP — if it shows the OTHER one,
      cancel and check which browser tab is focused.
    </div>
  </header>
  <section class="kv">
    <dt>Operator</dt>
    <dd><code class="hex">{omni}</code></dd>
    <dt>RP ID</dt>
    <dd><code class="hex">{rp_id_display}</code></dd>
    <dt>Challenge <span class="kv-meta">32-byte commitment</span></dt>
    <dd><code class="hex msg">0x{msg}</code></dd>
  </section>
  <p id="status" class="status">Press the button below. macOS will prompt for Touch ID.</p>
  <button id="go" class="primary">Sign as {role_label}</button>
</main>
{shared_css_extra}
<script>
const challenge = "{challenge}";
const credId = "{cred_id}";
function b64urlDecode(s) {{
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}}
function b64urlEncode(buf) {{
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}}
document.getElementById('go').onclick = async () => {{
  const status = document.getElementById('status');
  try {{
    const cred = await navigator.credentials.get({{
      publicKey: {{
        rpId: "{rp_id_js}",
        challenge: b64urlDecode(challenge),
        allowCredentials: [{{ id: b64urlDecode(credId), type: "public-key" }}],
        userVerification: "required",
        timeout: 60000
      }}
    }});
    const resp = cred.response;
    const payload = {{
      id: cred.id,
      client_data_json: b64urlEncode(resp.clientDataJSON),
      authenticator_data: b64urlEncode(resp.authenticatorData),
      signature: b64urlEncode(resp.signature)
    }};
    const r = await fetch("/finish", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload)
    }});
    if (r.ok) {{
      status.className = 'status ok';
      status.textContent = '✓ Signature delivered — you can close this tab.';
      document.getElementById('go').disabled = true;
    }} else {{
      status.className = 'status err';
      status.textContent = '✗ Server rejected: ' + r.status;
    }}
  }} catch (e) {{
    status.className = 'status err';
    status.textContent = '✗ ' + e.message;
  }}
}};
</script>
</body></html>
{shared_css_extra}"##,
        omni = ctx.operator_omni,
        challenge = ctx.challenge_b64url,
        cred_id = cred_id,
        msg = msg_hex,
        shared_css = SHARED_CSS,
        shared_css_extra = "",
        rp_id_js = ctx.rp_id,
        rp_id_display = ctx.rp_id,
        role_label = role_label,
        role_tagline = role_tagline,
        role_accent = role_accent,
        role_emoji = role_emoji,
    );
    Html(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_path_uses_strip_0x() {
        let path = enrollment_path(&format!("0x{}", "a".repeat(64)));
        assert!(path.to_string_lossy().contains(&"a".repeat(64)));
        assert!(!path.to_string_lossy().contains("0xa"));
    }

    #[test]
    fn finalize_enroll_rejects_wrong_challenge() {
        let post = EnrollPost {
            id: "fake-id".into(),
            // {"type":"webauthn.create","challenge":"BAD","origin":"http://localhost:1234"} base64url
            client_data_json: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.create","challenge":"BAD","origin":"http://localhost:1234"}"#,
            ),
            attestation_object: URL_SAFE_NO_PAD.encode([0xa0u8]), // empty CBOR map; we won't reach the parser
        };
        let err = finalize_enroll("0xabc", "localhost", "GOOD", "http://localhost:1234", &post).unwrap_err();
        assert!(matches!(err, WebauthnError::ChallengeMismatch { .. }));
    }

    #[test]
    fn finalize_enroll_rejects_wrong_type() {
        let post = EnrollPost {
            id: "fake-id".into(),
            client_data_json: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.get","challenge":"GOOD","origin":"http://localhost:1234"}"#,
            ),
            attestation_object: URL_SAFE_NO_PAD.encode([0xa0u8]),
        };
        let err = finalize_enroll("0xabc", "localhost", "GOOD", "http://localhost:1234", &post).unwrap_err();
        assert!(matches!(err, WebauthnError::TypeMismatch { .. }));
    }

    #[test]
    fn finalize_enroll_rejects_wrong_origin() {
        let post = EnrollPost {
            id: "fake-id".into(),
            client_data_json: URL_SAFE_NO_PAD.encode(
                br#"{"type":"webauthn.create","challenge":"GOOD","origin":"http://evil:1234"}"#,
            ),
            attestation_object: URL_SAFE_NO_PAD.encode([0xa0u8]),
        };
        let err = finalize_enroll("0xabc", "localhost", "GOOD", "http://localhost:1234", &post).unwrap_err();
        assert!(matches!(err, WebauthnError::OriginMismatch { .. }));
    }
}
