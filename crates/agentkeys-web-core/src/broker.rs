//! Host-agnostic broker HTTP client for the master control plane.
//!
//! W0/X0 of `docs/plan/web-flow/wire-real-paths.md`: one typed broker client
//! that the daemon ui-bridge, the WASM `CoreBackend` (web), and the mobile
//! UniFFI shell all share — so the browser/phone never re-implement broker
//! calls in TypeScript/Swift (the "consistency is structural" rule).
//!
//! Scope: the pairing (arch.md §10.2 method A, master-side) + cap-mint
//! endpoints the web wiring proxies. The email/OAuth/SIWE auth flow lives in
//! `agentkeys_core::init_flow`; this module is the net-new surface plus a
//! reusable typed client others can build on.
//!
//! WASM: this crate pins `reqwest` to `default-features = false` so `wasm32`
//! uses the browser `fetch` backend (native adds `rustls-tls`); the client is
//! host-agnostic by construction (no filesystem, clock, or env).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("broker rejected {endpoint}: status={status} body={body}")]
    Rejected {
        endpoint: String,
        status: u16,
        body: String,
    },
    #[error("decode response: {0}")]
    Decode(String),
}

type R<T> = Result<T, BrokerError>;

/// A reusable, host-agnostic broker client. Holds a `reqwest::Client` + the
/// broker base URL; every method takes the caller's bearer (the operator's J1
/// session JWT) explicitly — the client itself stores no secret.
#[derive(Clone)]
pub struct BrokerClient {
    http: reqwest::Client,
    base_url: String,
}

/// Default `reqwest::Client`. Native hosts (daemon/CLI/mobile) get a request
/// timeout so a stalled broker can't hang a worker thread forever; the
/// wasm/browser host uses the `fetch` backend (per-request timeouts there need
/// an `AbortController`, wired in the web host — not the `ClientBuilder`).
#[cfg(not(target_arch = "wasm32"))]
fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(target_arch = "wasm32")]
fn default_client() -> reqwest::Client {
    reqwest::Client::new()
}

impl BrokerClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_client(default_client(), base_url)
    }

    /// Reuse a pre-built `reqwest::Client` (connection pooling, timeouts, or a
    /// wasm-configured client in the browser host).
    pub fn with_client(http: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    // ── Cap-mint (operator-J1-gated). One typed call per (op, data_class);
    //    the route is the source of truth for the data_class (per AGENTS.md). ──

    pub async fn cap_memory_put(&self, bearer: &str, req: &CapRequest) -> R<CapToken> {
        self.post_json("/v1/cap/memory-put", Some(bearer), req)
            .await
    }
    pub async fn cap_memory_get(&self, bearer: &str, req: &CapRequest) -> R<CapToken> {
        self.post_json("/v1/cap/memory-get", Some(bearer), req)
            .await
    }
    pub async fn cap_cred_store(&self, bearer: &str, req: &CapRequest) -> R<CapToken> {
        self.post_json("/v1/cap/cred-store", Some(bearer), req)
            .await
    }
    pub async fn cap_cred_fetch(&self, bearer: &str, req: &CapRequest) -> R<CapToken> {
        self.post_json("/v1/cap/cred-fetch", Some(bearer), req)
            .await
    }

    // ── Pairing, master-side (arch.md §10.2 method A). The agent-side
    //    request/poll lives in the daemon's one-shot modes, not here. ──

    /// Master claims an agent-shown pairing code (J1_master-gated). Binds the
    /// unbound request to the HDKD child omni; returns the device artifacts the
    /// master needs to submit the on-chain bind.
    pub async fn pairing_claim(
        &self,
        bearer: &str,
        req: &PairingClaimRequest,
    ) -> R<ClaimedBinding> {
        self.post_json("/v1/agent/pairing/claim", Some(bearer), req)
            .await
    }

    /// Master polls for claimed-but-unbound agents — the pairing-page bell /
    /// notification source.
    pub async fn pending_bindings(&self, bearer: &str) -> R<Vec<ClaimedBinding>> {
        let resp: PendingBindings = self
            .get_json("/v1/agent/pending-bindings", Some(bearer))
            .await?;
        Ok(resp.pending)
    }

    /// Master acks an on-chain bind, clearing the rendezvous.
    pub async fn ack_binding(&self, bearer: &str, request_id: &str) -> R<AckResponse> {
        self.post_json(
            "/v1/agent/pending-bindings/ack",
            Some(bearer),
            &AckRequest {
                request_id: request_id.to_string(),
            },
        )
        .await
    }

    // ── internals ──

    async fn post_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &B,
    ) -> R<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut rb = self.http.post(&url).json(body);
        if let Some(b) = bearer {
            rb = rb.bearer_auth(b);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| BrokerError::Transport(format!("POST {path}: {e}")))?;
        Self::decode(path, resp).await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str, bearer: Option<&str>) -> R<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut rb = self.http.get(&url);
        if let Some(b) = bearer {
            rb = rb.bearer_auth(b);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| BrokerError::Transport(format!("GET {path}: {e}")))?;
        Self::decode(path, resp).await
    }

    async fn decode<T: DeserializeOwned>(path: &str, resp: reqwest::Response) -> R<T> {
        let status = resp.status();
        if !status.is_success() {
            // Bound the echoed body: it's our own broker, reached over the
            // operator's own session (no cross-tenant data; the bearer is never
            // echoed back), but an unbounded error string shouldn't flow into a
            // JS rejection / log line. 512 chars preserves the broker error code.
            let raw = resp.text().await.unwrap_or_default();
            let body: String = raw.chars().take(512).collect();
            return Err(BrokerError::Rejected {
                endpoint: path.to_string(),
                status: status.as_u16(),
                body,
            });
        }
        resp.json::<T>()
            .await
            .map_err(|e| BrokerError::Decode(format!("{path}: {e}")))
    }
}

// ─── Cap-mint types ──────────────────────────────────────────────────────────
//
// The cap-mint request body is the SHARED on-wire type owned by
// `agentkeys-protocol`, aliased here as `CapRequest` so this crate's call sites
// and the `wasm.rs` bindings stay unchanged. Sharing it means the browser host
// and the native client (agentkeys-backend-client) can no longer drift on this
// body — previously each had its own copy and they diverged on `ttl_seconds`
// (`Option<u64>` here vs a required `u64` there) AND this copy was missing the
// #76 K10 cap-PoP fields (`client_sig`/`client_nonce`/`client_ts`; browser
// callers send `None` — verified-when-present until the worker enforce flag
// flips). `service` is still the namespace-qualified signed service
// `memory:<ns>` (arch.md §896) — build it with `memoryService(ns)`, never a
// bare `memory` (→ `service_not_in_scope`). The cap-token *response* shape
// stays local: a typed convenience view over the same wire bytes the native
// client keeps opaque (the deliberate B3 non-unification).
pub use agentkeys_protocol::BrokerCapRequest as CapRequest;

/// Broker-signed cap token. `payload` is the signed `CapPayload` (op, data_class,
/// k3_epoch, expiry, …) — kept as opaque JSON here; the worker re-parses + the
/// broker_sig is re-verified downstream, so the client does not need the shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapToken {
    pub payload: serde_json::Value,
    pub broker_sig: String,
}

// ─── Pairing types (mirror handlers/agent/{claim,pending}.rs) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingClaimRequest {
    pub pairing_code: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_scope: Option<String>,
}

/// The record the master sees for a claimed-but-unbound agent — carries
/// everything needed to submit `registerAgentDevice` on chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedBinding {
    pub request_id: String,
    pub child_omni: String,
    pub operator_omni: String,
    pub label: String,
    #[serde(default)]
    pub requested_scope: String,
    pub device_pubkey: String,
    pub pop_sig: String,
    pub device_key_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PendingBindings {
    #[serde(default)]
    pending: Vec<ClaimedBinding>,
}

#[derive(Debug, Clone, Serialize)]
struct AckRequest {
    request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckResponse {
    pub acked: bool,
    pub request_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::Json as AxJson,
        http::{HeaderMap, StatusCode},
        routing::{get, post},
        Router,
    };
    use serde_json::json;

    // Spin a tiny broker stub on an ephemeral port; return its base URL.
    async fn stub() -> String {
        let app = Router::new()
            .route(
                "/v1/cap/memory-put",
                post(
                    |headers: HeaderMap, AxJson(body): AxJson<serde_json::Value>| async move {
                        // Require the operator bearer.
                        if !headers.contains_key("authorization") {
                            return (
                                StatusCode::UNAUTHORIZED,
                                AxJson(json!({"error":"no-bearer"})),
                            );
                        }
                        let svc = body["service"].as_str().unwrap_or("");
                        (
                            StatusCode::OK,
                            AxJson(json!({
                                "payload": {"op":"store","data_class":"memory","service":svc},
                                "broker_sig":"c2ln"
                            })),
                        )
                    },
                ),
            )
            .route(
                "/v1/agent/pairing/claim",
                post(|AxJson(body): AxJson<serde_json::Value>| async move {
                    let code = body["pairing_code"].as_str().unwrap_or("");
                    AxJson(json!({
                        "request_id":"req-1","child_omni":"0xchild","operator_omni":"0xop",
                        "label": body["label"], "requested_scope":"memory",
                        "device_pubkey":"0xdpub","pop_sig":"0xpop","device_key_hash":"0xdkh",
                        "_echo_code": code
                    }))
                }),
            )
            .route(
                "/v1/agent/pending-bindings",
                get(|| async {
                    AxJson(json!({"pending":[{
                        "request_id":"req-1","child_omni":"0xchild","operator_omni":"0xop",
                        "label":"demo","requested_scope":"memory","device_pubkey":"0xdpub",
                        "pop_sig":"0xpop","device_key_hash":"0xdkh"
                    }]}))
                }),
            )
            .route(
                "/v1/agent/pending-bindings/ack",
                post(|AxJson(body): AxJson<serde_json::Value>| async move {
                    AxJson(json!({"acked":true,"request_id": body["request_id"]}))
                }),
            )
            .route(
                "/v1/cap/cred-store",
                post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
            )
            .route(
                // Returns an oversized body so the truncation guard can be tested.
                "/v1/cap/cred-fetch",
                post(|| async { (StatusCode::BAD_REQUEST, "x".repeat(1000)) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn cap_req() -> CapRequest {
        CapRequest {
            operator_omni: "0xop".into(),
            actor_omni: "0xactor".into(),
            service: "memory".into(),
            device_key_hash: "0xdkh".into(),
            ttl_seconds: Some(900),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        }
    }

    #[tokio::test]
    async fn cap_memory_put_roundtrips_and_sends_bearer() {
        let c = BrokerClient::new(stub().await);
        let tok = c.cap_memory_put("J1", &cap_req()).await.unwrap();
        assert_eq!(tok.broker_sig, "c2ln");
        assert_eq!(tok.payload["data_class"], "memory");
        assert_eq!(tok.payload["service"], "memory");
    }

    #[tokio::test]
    async fn non_2xx_maps_to_rejected() {
        // The cred-store stub route returns 500 → BrokerError::Rejected with the
        // status + endpoint preserved (so callers can fail closed / surface it).
        let c = BrokerClient::new(stub().await);
        let err = c.cap_cred_store("J1", &cap_req()).await.unwrap_err();
        match err {
            BrokerError::Rejected {
                status, endpoint, ..
            } => {
                assert_eq!(status, 500);
                assert_eq!(endpoint, "/v1/cap/cred-store");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejected_body_is_bounded() {
        // A broker error body longer than the cap is truncated to 512 chars so it
        // can't bloat a JS rejection / log line (status + endpoint preserved).
        let c = BrokerClient::new(stub().await);
        let err = c.cap_cred_fetch("J1", &cap_req()).await.unwrap_err();
        match err {
            BrokerError::Rejected { status, body, .. } => {
                assert_eq!(status, 400);
                assert_eq!(
                    body.chars().count(),
                    512,
                    "body should be capped at 512 chars"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pairing_claim_roundtrips() {
        let c = BrokerClient::new(stub().await);
        let claimed = c
            .pairing_claim(
                "J1",
                &PairingClaimRequest {
                    pairing_code: "ABCD-1234".into(),
                    label: "demo-agent".into(),
                    requested_scope: Some("memory".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(claimed.child_omni, "0xchild");
        assert_eq!(claimed.device_key_hash, "0xdkh");
        assert_eq!(claimed.label, "demo-agent");
    }

    #[tokio::test]
    async fn pending_then_ack() {
        let c = BrokerClient::new(stub().await);
        let pending = c.pending_bindings("J1").await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "req-1");
        let ack = c.ack_binding("J1", "req-1").await.unwrap();
        assert!(ack.acked);
        assert_eq!(ack.request_id, "req-1");
    }
}
