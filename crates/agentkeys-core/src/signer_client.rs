//! Daemon-side RPC client for the signer edge.
//!
//! The daemon never holds private key material. Instead, it asks the signer
//! to (a) reveal the EVM address derived from a given `omni_account` and
//! (b) sign EIP-191 messages under that derived key. The wire contract is
//! pinned by `docs/spec/signer-protocol.md`; the v0 implementation in
//! `agentkeys-mock-server::dev_key_service` is HKDF-backed; issue #74 step 2
//! replaces it with a TEE worker behind the same wire shape.
//!
//! Daemon code MUST treat the signer as an opaque RPC dependency (no
//! assumptions about derivation, no caching of signing keys). The
//! `SignerClient` trait is the swap-point: tests inject a TEE-stub fixture,
//! prod code injects the HTTP client.

use async_trait::async_trait;
use thiserror::Error;

use crate::clear_signing::TypedData;

/// Wire-protocol error codes from `signer-protocol.md`. Daemon code matches
/// on these (and the transport variants) to drive retry / surface logic.
#[derive(Debug, Error)]
pub enum SignerClientError {
    /// 400 `invalid_omni_account` — bug in caller; not retriable.
    #[error("invalid_omni_account: {0}")]
    InvalidOmniAccount(String),

    /// 400 `invalid_message_hex` — bug in caller; not retriable.
    #[error("invalid_message_hex: {0}")]
    InvalidMessageHex(String),

    /// 400 `invalid_typed_data` (issue #82) — `typed_data` payload was
    /// rejected by the signer before any signing happened: malformed JSON,
    /// unknown type, value out of range for declared type.
    #[error("invalid_typed_data: {0}")]
    InvalidTypedData(String),

    /// 503 `signer_disabled` — operator must set
    /// `DEV_KEY_SERVICE_MASTER_SECRET` (dev) or attest the TEE (prod).
    #[error("signer_disabled: {0}")]
    SignerDisabled(String),

    /// 401 `unauthorized` — bearer JWT missing, expired, or omni_account mismatch.
    /// Caller should re-init to obtain a fresh session JWT.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// 500 `internal` from the signer — bug; surface to operator.
    #[error("signer_internal: {0}")]
    Internal(String),

    /// HTTP layer failure (DNS, TCP, TLS, timeout, malformed body).
    #[error("transport: {0}")]
    Transport(String),

    /// Server returned a status / `error` code not covered by the contract.
    #[error("unexpected_response: status={status} error={error:?} message={message:?}")]
    Unexpected {
        status: u16,
        error: Option<String>,
        message: Option<String>,
    },
}

/// Successful response from `/dev/derive-address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAddress {
    /// Lowercase 0x-prefixed 40-char hex EVM address.
    pub address: String,
    /// Derivation domain version. Daemon SHOULD record this alongside the
    /// address; a mid-session change implies master-secret rotation.
    pub key_version: u8,
}

/// Successful response from `/dev/sign-message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    /// 0x-prefixed 130-char hex `r || s || v` with `v ∈ {0, 1}`.
    pub signature: String,
    /// MUST equal the address `derive_address` returned for the same
    /// `omni_account`. Daemon MAY assert this invariant on every sign call.
    pub address: String,
    pub key_version: u8,
}

/// Successful response from `/dev/sign-typed-data` (issue #82). Carries
/// the signature plus every digest the signer computed internally — so the
/// caller can cross-reference against the ERC-7730 metadata file pinned to
/// the same domain separator / primary type hash for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTypedData {
    pub signature: String,
    pub address: String,
    pub primary_type_hash: String,
    pub domain_separator: String,
    pub digest: String,
    pub key_version: u8,
}

/// The daemon's view of the signer. Three methods, all pure RPC.
#[async_trait]
pub trait SignerClient: Send + Sync {
    /// Resolve `omni_account` (64 lowercase hex chars) to its derived EVM
    /// address. Idempotent and side-effect-free.
    async fn derive_address(&self, omni_account: &str)
        -> Result<DerivedAddress, SignerClientError>;

    /// EIP-191-sign `message_bytes` under the keypair derived from
    /// `omni_account`. Returns the canonical 65-byte signature.
    ///
    /// Implementations MUST verify (or trust the wire promise that)
    /// `signed.address` equals `derive_address(omni_account).address`. The
    /// daemon's SIWE round-trip relies on this equality.
    async fn sign_eip191(
        &self,
        omni_account: &str,
        message_bytes: &[u8],
    ) -> Result<SignedMessage, SignerClientError>;

    /// EIP-712-sign `typed_data` under the keypair derived from
    /// `omni_account` (issue #82). The signer parses the typed-data JSON
    /// itself and computes the digest internally — callers MUST NOT pass a
    /// pre-hashed value.
    ///
    /// Returns the signature + every intermediate digest the signer
    /// produced (`primary_type_hash`, `domain_separator`, final `digest`),
    /// so the daemon can cross-reference against an ERC-7730 metadata file
    /// and emit an audit row whose intent commitment binds to the same
    /// digest the signer signed over.
    async fn sign_eip712(
        &self,
        omni_account: &str,
        typed_data: &TypedData,
    ) -> Result<SignedTypedData, SignerClientError>;
}

/// HTTP implementation of `SignerClient` — talks to the dev_key_service
/// (or a TEE worker) over the `/dev/*` routes documented in
/// `signer-protocol.md`.
pub struct HttpSignerClient {
    base_url: String,
    http: reqwest::Client,
    /// When set, added as `Authorization: Bearer <jwt>` on every `/dev/*` request.
    /// Required when the signer listener has JWT bearer auth enabled
    /// (issue #74 step 1b: `--signer-only` mode).
    session_jwt: Option<String>,
}

impl HttpSignerClient {
    /// `base_url` must NOT include a trailing slash. The client appends
    /// `/dev/derive-address` and `/dev/sign-message`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            session_jwt: None,
        }
    }

    /// Custom `reqwest::Client` injection — used by tests that need a
    /// pre-configured connection pool or custom timeout.
    pub fn with_http_client(base_url: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            session_jwt: None,
        }
    }

    /// Attach a session JWT that will be sent as `Authorization: Bearer <jwt>`
    /// on every `/dev/*` request. Required when the signer listener runs in
    /// `--signer-only` mode (issue #74 step 1b).
    pub fn with_session_jwt(mut self, jwt: String) -> Self {
        self.session_jwt = Some(jwt);
        self
    }
}

#[async_trait]
impl SignerClient for HttpSignerClient {
    async fn derive_address(
        &self,
        omni_account: &str,
    ) -> Result<DerivedAddress, SignerClientError> {
        let url = format!("{}/dev/derive-address", self.base_url);
        let mut req = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "omni_account": omni_account }));
        if let Some(jwt) = &self.session_jwt {
            req = req.header("Authorization", format!("Bearer {jwt}"));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| SignerClientError::Transport(format!("POST {url}: {e}")))?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SignerClientError::Transport(format!("parse JSON: {e}")))?;

        if status == 200 {
            let address = body["address"]
                .as_str()
                .ok_or_else(|| SignerClientError::Unexpected {
                    status,
                    error: None,
                    message: Some("missing 'address'".into()),
                })?
                .to_string();
            let key_version = body["key_version"].as_u64().unwrap_or(0) as u8;
            return Ok(DerivedAddress {
                address,
                key_version,
            });
        }
        Err(map_error(status, &body))
    }

    async fn sign_eip191(
        &self,
        omni_account: &str,
        message_bytes: &[u8],
    ) -> Result<SignedMessage, SignerClientError> {
        let url = format!("{}/dev/sign-message", self.base_url);
        let mut req = self.http.post(&url).json(&serde_json::json!({
            "omni_account": omni_account,
            "message_hex":  hex::encode(message_bytes),
        }));
        if let Some(jwt) = &self.session_jwt {
            req = req.header("Authorization", format!("Bearer {jwt}"));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| SignerClientError::Transport(format!("POST {url}: {e}")))?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SignerClientError::Transport(format!("parse JSON: {e}")))?;

        if status == 200 {
            let signature = body["signature"]
                .as_str()
                .ok_or_else(|| SignerClientError::Unexpected {
                    status,
                    error: None,
                    message: Some("missing 'signature'".into()),
                })?
                .to_string();
            let address = body["address"]
                .as_str()
                .ok_or_else(|| SignerClientError::Unexpected {
                    status,
                    error: None,
                    message: Some("missing 'address'".into()),
                })?
                .to_string();
            let key_version = body["key_version"].as_u64().unwrap_or(0) as u8;
            return Ok(SignedMessage {
                signature,
                address,
                key_version,
            });
        }
        Err(map_error(status, &body))
    }

    async fn sign_eip712(
        &self,
        omni_account: &str,
        typed_data: &TypedData,
    ) -> Result<SignedTypedData, SignerClientError> {
        let url = format!("{}/dev/sign-typed-data", self.base_url);
        let mut req = self.http.post(&url).json(&serde_json::json!({
            "omni_account": omni_account,
            "typed_data": typed_data,
        }));
        if let Some(jwt) = &self.session_jwt {
            req = req.header("Authorization", format!("Bearer {jwt}"));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| SignerClientError::Transport(format!("POST {url}: {e}")))?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SignerClientError::Transport(format!("parse JSON: {e}")))?;

        if status == 200 {
            let pick = |k: &'static str| -> Result<String, SignerClientError> {
                body[k]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| SignerClientError::Unexpected {
                        status,
                        error: None,
                        message: Some(format!("missing '{k}'")),
                    })
            };
            return Ok(SignedTypedData {
                signature: pick("signature")?,
                address: pick("address")?,
                primary_type_hash: pick("primary_type_hash")?,
                domain_separator: pick("domain_separator")?,
                digest: pick("digest")?,
                key_version: body["key_version"].as_u64().unwrap_or(0) as u8,
            });
        }
        Err(map_error(status, &body))
    }
}

/// Translate a non-2xx response body into a typed `SignerClientError`,
/// honoring the stable `error` codes from `signer-protocol.md`.
fn map_error(status: u16, body: &serde_json::Value) -> SignerClientError {
    let code = body["error"].as_str().unwrap_or("");
    let message = body["message"].as_str().unwrap_or("").to_string();
    match (status, code) {
        (400, "invalid_omni_account") => SignerClientError::InvalidOmniAccount(message),
        (400, "invalid_message_hex") => SignerClientError::InvalidMessageHex(message),
        (400, "invalid_typed_data") => SignerClientError::InvalidTypedData(message),
        (401, "unauthorized") => SignerClientError::Unauthorized(message),
        (503, "signer_disabled") => SignerClientError::SignerDisabled(message),
        (500, "internal") => SignerClientError::Internal(message),
        _ => SignerClientError::Unexpected {
            status,
            error: if code.is_empty() {
                None
            } else {
                Some(code.to_string())
            },
            message: if message.is_empty() {
                None
            } else {
                Some(message)
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_error_recognizes_signer_disabled() {
        let body = serde_json::json!({"error":"signer_disabled","message":"unset"});
        match map_error(503, &body) {
            SignerClientError::SignerDisabled(m) => assert_eq!(m, "unset"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn map_error_recognizes_invalid_omni_account() {
        let body = serde_json::json!({"error":"invalid_omni_account","message":"too short"});
        match map_error(400, &body) {
            SignerClientError::InvalidOmniAccount(m) => assert_eq!(m, "too short"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn map_error_falls_back_for_unknown_codes() {
        let body = serde_json::json!({"error":"weird","message":"???"});
        match map_error(418, &body) {
            SignerClientError::Unexpected {
                status,
                error,
                message,
            } => {
                assert_eq!(status, 418);
                assert_eq!(error.as_deref(), Some("weird"));
                assert_eq!(message.as_deref(), Some("???"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn http_signer_client_strips_trailing_slash() {
        let c = HttpSignerClient::new("http://localhost:8090/");
        assert_eq!(c.base_url, "http://localhost:8090");
    }
}
