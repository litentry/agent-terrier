//! Native signer transport over the shared protocol; keys remain with the signer.

use agentkeys_protocol::auth::{
    DeriveAddressRequest, DeriveDeviceRequest, SignMessageRequest, SignTypedDataRequest,
    SignedDeviceCapPop,
};
pub use agentkeys_protocol::auth::{
    DerivedAddress, DerivedDevice, SignDeviceCapPopRequest as DeviceCapPopFields, SignedMessage,
    SignedTypedData,
};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::clear_signing::TypedData;

/// Stable signer failures shared by wallet and device transports.
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

    /// 503: the configured signer is unavailable.
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
        signer_request(
            &self.http,
            &self.base_url,
            "/dev/derive-address",
            &DeriveAddressRequest {
                omni_account: omni_account.into(),
            },
            self.session_jwt.as_deref(),
        )
        .await
    }

    async fn sign_eip191(
        &self,
        omni_account: &str,
        message_bytes: &[u8],
    ) -> Result<SignedMessage, SignerClientError> {
        signer_request(
            &self.http,
            &self.base_url,
            "/dev/sign-message",
            &SignMessageRequest {
                omni_account: omni_account.into(),
                message_hex: hex::encode(message_bytes),
            },
            self.session_jwt.as_deref(),
        )
        .await
    }

    async fn sign_eip712(
        &self,
        omni_account: &str,
        typed_data: &TypedData,
    ) -> Result<SignedTypedData, SignerClientError> {
        signer_request(
            &self.http,
            &self.base_url,
            "/dev/sign-typed-data",
            &SignTypedDataRequest {
                omni_account: omni_account.into(),
                typed_data,
            },
            self.session_jwt.as_deref(),
        )
        .await
    }
}

async fn signer_request<Request: Serialize, Response: DeserializeOwned>(
    http: &reqwest::Client,
    base_url: &str,
    path: &str,
    body: &Request,
    bearer: Option<&str>,
) -> Result<Response, SignerClientError> {
    let mut request = http.post(format!("{base_url}{path}")).json(body);
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    let response = request
        .send()
        .await
        .map_err(|error| SignerClientError::Transport(error.to_string()))?;
    let status = response.status().as_u16();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|_| SignerClientError::Transport("invalid signer JSON response".into()))?;
    if status != 200 {
        return Err(map_error(status, &body));
    }
    serde_json::from_value(body).map_err(|_| SignerClientError::Unexpected {
        status,
        error: None,
        message: Some("invalid signer response schema".into()),
    })
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
        (401, "unauthorized") | (403, "actor_not_authorized") => {
            SignerClientError::Unauthorized(message)
        }
        (503, "signer_disabled" | "signer_auth_not_configured") => {
            SignerClientError::SignerDisabled(message)
        }
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

pub struct DeviceSignerClient {
    base_url: String,
    http: reqwest::Client,
}

impl DeviceSignerClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn derive_device(
        &self,
        actor_omni: &str,
        label: Option<&str>,
        bearer: &str,
    ) -> Result<DerivedDevice, SignerClientError> {
        signer_request(
            &self.http,
            &self.base_url,
            "/dev/derive-device",
            &DeriveDeviceRequest {
                actor_omni: actor_omni.into(),
                label: label.map(str::to_owned),
            },
            Some(bearer),
        )
        .await
    }

    pub async fn sign_cap_pop(
        &self,
        fields: &DeviceCapPopFields,
        bearer: &str,
    ) -> Result<String, SignerClientError> {
        let response: SignedDeviceCapPop = signer_request(
            &self.http,
            &self.base_url,
            "/dev/sign-device-cap-pop",
            fields,
            Some(bearer),
        )
        .await?;
        Ok(response.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_signer_versions_are_rejected_without_defaulting_or_truncation() {
        use axum::{extract::State, routing::post, Json, Router};
        use serde_json::{json, Value};
        use std::sync::{Arc, RwLock};

        let valid = json!({"address":"synthetic-address", "signature":"synthetic-signature",
            "primary_type_hash":"synthetic-hash", "domain_separator":"synthetic-domain",
            "digest":"synthetic-digest", "device_key_hash":"synthetic-device", "pop_sig":"synthetic-proof", "key_version":1});
        let response = Arc::new(RwLock::new(valid.clone()));
        async fn reply(State(response): State<Arc<RwLock<Value>>>) -> Json<Value> {
            Json(response.read().unwrap().clone())
        }
        let router = Router::new()
            .route("/dev/derive-address", post(reply))
            .route("/dev/sign-message", post(reply))
            .route("/dev/sign-typed-data", post(reply))
            .route("/dev/derive-device", post(reply))
            .route("/dev/sign-device-cap-pop", post(reply))
            .with_state(response.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let wallet = HttpSignerClient::new(&endpoint);
        let device = DeviceSignerClient::new(endpoint);
        let fields = DeviceCapPopFields {
            actor_omni: "synthetic-owner".into(),
            operator_omni: "synthetic-owner".into(),
            service: "synthetic-service".into(),
            op: "fetch".into(),
            data_class: "memory".into(),
            client_nonce: "synthetic-nonce".into(),
            client_ts: 1,
        };
        let typed_data: TypedData =
            serde_json::from_value(json!({"types":{}, "primaryType":"Synthetic",
            "domain":{}, "message":{}}))
            .unwrap();
        for version in [
            Some(json!(1)),
            None,
            Some(Value::Null),
            Some(json!(-1)),
            Some(json!(256)),
            Some(json!(1.5)),
            Some(json!("synthetic-confidential-value")),
        ] {
            let mut body = valid.clone();
            match version.clone() {
                Some(value) => body["key_version"] = value,
                None => {
                    body.as_object_mut().unwrap().remove("key_version");
                }
            }
            *response.write().unwrap() = body;
            let results = [
                wallet
                    .derive_address("synthetic-owner")
                    .await
                    .map(|reply| reply.key_version),
                wallet
                    .sign_eip191("synthetic-owner", b"synthetic-message")
                    .await
                    .map(|reply| reply.key_version),
                wallet
                    .sign_eip712("synthetic-owner", &typed_data)
                    .await
                    .map(|reply| reply.key_version),
                device
                    .derive_device("synthetic-owner", None, "synthetic-session")
                    .await
                    .map(|reply| reply.key_version),
                device
                    .sign_cap_pop(&fields, "synthetic-session")
                    .await
                    .map(|_| 1),
            ];
            for result in results {
                if version == Some(json!(1)) {
                    assert_eq!(result.unwrap(), 1);
                } else {
                    assert!(
                        result.is_err(),
                        "malformed version was accepted: {version:?}"
                    );
                    assert!(!result
                        .unwrap_err()
                        .to_string()
                        .contains("synthetic-confidential-value"));
                }
            }
        }
        server.abort();
    }

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
