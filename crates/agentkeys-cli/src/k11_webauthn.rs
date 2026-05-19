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
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".agentkeys")
        .join("k11")
        .join(format!("{}.json", operator_omni.trim_start_matches("0x")))
}

/// Run the enrollment ceremony. Blocks (awaits) until the browser POSTs
/// back or the 5-minute timeout fires. Persists the result to
/// `~/.agentkeys/k11/<omni>.json` (mode 0600).
///
/// Async — call from inside an existing tokio runtime (e.g. the CLI's
/// `#[tokio::main]`). Creating a nested runtime via `block_on` panics
/// with "Cannot start a runtime from within a runtime".
pub async fn enroll_webauthn(operator_omni: &str) -> Result<WebauthnEnrollment, WebauthnError> {
    enroll_webauthn_inner(operator_omni).await
}

/// Run the assert ceremony. Returns the assertion bytes
/// (`authenticatorData || clientDataJSON || signature`).
pub async fn assert_webauthn(
    operator_omni: &str,
    message: &[u8],
) -> Result<Vec<u8>, WebauthnError> {
    assert_webauthn_inner(operator_omni, message).await
}

async fn enroll_webauthn_inner(operator_omni: &str) -> Result<WebauthnEnrollment, WebauthnError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| WebauthnError::Bind(e.to_string()))?;
    let local_addr = listener.local_addr().map_err(|e| WebauthnError::Bind(e.to_string()))?;
    let port = local_addr.port();
    let rp_origin = format!("http://localhost:{port}");

    let mut challenge_bytes = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut challenge_bytes);
    let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge_bytes);

    let ctx = Arc::new(ServerCtx {
        rp_id: "localhost".to_string(),
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

    let enrollment = finalize_enroll(operator_omni, &challenge_b64url, &rp_origin, &post)?;
    persist_enrollment(&enrollment)?;
    Ok(enrollment)
}

async fn assert_webauthn_inner(
    operator_omni: &str,
    message: &[u8],
) -> Result<Vec<u8>, WebauthnError> {
    // Load the previously-enrolled credential.
    let enrollment = load_enrollment(operator_omni)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| WebauthnError::Bind(e.to_string()))?;
    let port = listener.local_addr().map_err(|e| WebauthnError::Bind(e.to_string()))?.port();
    let rp_origin = format!("http://localhost:{port}");

    // WebAuthn challenge = sha256(application message). The browser signs
    // over (authenticatorData || sha256(clientDataJSON)) and clientDataJSON
    // includes this challenge — so the resulting signature binds to our
    // application message.
    let mut h = Sha256::new();
    h.update(message);
    let challenge_bytes = h.finalize();
    let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge_bytes);

    let ctx = Arc::new(ServerCtx {
        rp_id: "localhost".to_string(),
        rp_origin: rp_origin.clone(),
        operator_omni: operator_omni.to_string(),
        challenge_b64url: challenge_b64url.clone(),
        allow_credential_b64url: Some(enrollment.credential_id_b64url.clone()),
        message_hex: Some(hex::encode(message)),
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

    finalize_assert(&enrollment, &challenge_b64url, &rp_origin, &post)
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

    // Verify rpIdHash == sha256("localhost"). This binds the credential
    // to our relying party so a passkey enrolled against a different RP
    // can't be replayed here.
    let mut h = Sha256::new();
    h.update(b"localhost");
    let expected_rp_id_hash = h.finalize();
    if parsed.rp_id_hash != expected_rp_id_hash.as_slice() {
        return Err(WebauthnError::Cbor(format!(
            "rpIdHash mismatch: expected sha256('localhost'), got {}",
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
    })
}

fn finalize_assert(
    enrollment: &WebauthnEnrollment,
    expected_challenge: &str,
    expected_origin: &str,
    post: &AssertPost,
) -> Result<Vec<u8>, WebauthnError> {
    // Cross-check the credential id the browser used against the one
    // we enrolled. The browser will only sign with a passkey whose id
    // was in `allowCredentials` — but a debug build of the page could
    // be tweaked, and verifying here is cheap.
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

    // WebAuthn signature contract (per W3C WebAuthn §6.3.3):
    //   sig = ECDSA-sign(privkey, authenticatorData || sha256(clientDataJSON))
    // The signed bytes are the CONCATENATION (authData || cd_hash) — the
    // verify function then sha256's the message internally. The previous
    // code SHA256'd this concatenation BEFORE passing to verify, so
    // verify was effectively checking sha256(sha256(...))  (codex audit).
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
    // Pass the message unhashed; `Verifier::verify` on p256::ecdsa::VerifyingKey
    // applies SHA-256 internally per the ECDSA-with-SHA256 contract.
    verifying_key
        .verify(&signed_bytes, &sig)
        .map_err(|_| WebauthnError::SigInvalid)?;

    // Return the WebAuthn assertion in its canonical transport shape:
    // authenticatorData || clientDataJSON || signature
    let mut out = Vec::with_capacity(authenticator_data.len() + client_data_bytes.len() + signature_der.len());
    out.extend_from_slice(&authenticator_data);
    out.extend_from_slice(&client_data_bytes);
    out.extend_from_slice(&signature_der);
    Ok(out)
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
    let path = enrollment_path(&enrollment.operator_omni);
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
    let path = enrollment_path(operator_omni);
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
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>AgentKeys — K11 enrollment</title>
{shared_css}
</head><body>
<main class="card">
  <header>
    <div class="brand">
      <span class="dot"></span>
      <span class="brand-name">AgentKeys</span>
    </div>
    <h1>K11 enrollment</h1>
    <p class="sub">Bind a platform passkey for master-tier authorisation.</p>
  </header>
  <section class="kv">
    <dt>Operator</dt>
    <dd><code class="hex">{omni}</code></dd>
    <dt>Authenticator</dt>
    <dd>Platform (Touch ID / Windows Hello / Secure Enclave)</dd>
    <dt>Algorithm</dt>
    <dd>ECDSA P-256 / SHA-256 (ES256)</dd>
  </section>
  <p id="status" class="status">Press the button below. macOS will prompt for Touch ID.</p>
  <button id="go" class="primary">Start enrollment</button>
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
        rp: {{ id: "localhost", name: "AgentKeys" }},
        user: {{
          id: hexToBytes(omni),       // 32 raw bytes (within WebAuthn 64-byte cap)
          name: omni,                  // display name — no byte limit
          displayName: "agentkeys-master"
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
    );
    Html(html)
}

async fn serve_assert_page(State(ctx): State<Arc<ServerCtx>>) -> impl IntoResponse {
    let cred_id = ctx.allow_credential_b64url.as_deref().unwrap_or("");
    let msg_hex = ctx.message_hex.as_deref().unwrap_or("");
    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>AgentKeys — K11 assertion</title>
{shared_css}
</head><body>
<main class="card">
  <header>
    <div class="brand">
      <span class="dot"></span>
      <span class="brand-name">AgentKeys</span>
    </div>
    <h1>K11 assertion</h1>
    <p class="sub">Sign a master-mutation payload with the bound passkey.</p>
  </header>
  <section class="kv">
    <dt>Operator</dt>
    <dd><code class="hex">{omni}</code></dd>
    <dt>Message <span class="kv-meta">SHA-256 = challenge</span></dt>
    <dd><code class="hex msg">0x{msg}</code></dd>
  </section>
  <p id="status" class="status">Press the button below. macOS will prompt for Touch ID.</p>
  <button id="go" class="primary">Sign with Touch ID</button>
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
        rpId: "localhost",
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
        let err = finalize_enroll("0xabc", "GOOD", "http://localhost:1234", &post).unwrap_err();
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
        let err = finalize_enroll("0xabc", "GOOD", "http://localhost:1234", &post).unwrap_err();
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
        let err = finalize_enroll("0xabc", "GOOD", "http://localhost:1234", &post).unwrap_err();
        assert!(matches!(err, WebauthnError::OriginMismatch { .. }));
    }
}
