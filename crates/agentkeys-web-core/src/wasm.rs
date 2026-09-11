//! `wasm-bindgen` exports for the browser `CoreBackend` (X1).
//!
//! Compiled only under `--features wasm` (e.g. `wasm-pack build --target web
//! --features wasm`). Wraps [`crate::broker::BrokerClient`] in a JS-constructable
//! `WebCore` whose async methods take/return plain JSON (`serde-wasm-bindgen`)
//! and reject with the broker error string on failure. The Next.js
//! `CoreBackend` (`lib/client/core.ts`) imports the generated `pkg`.
//!
//! No secret is stored: the operator's J1 bearer is passed per call, exactly as
//! on the native side.

use wasm_bindgen::prelude::*;

use crate::broker::{BrokerClient, CapRequest, PairingClaimRequest};
use agentkeys_protocol::web_api::{ApiMemoryEntry, MasterMemoryPlantRequest};

fn to_js<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

// ── the daemon's web-API plant contract (#275 tier-3) ────────────────────────
//
// The browser used to hand-build the plant route + body in `daemon.ts` (gated
// only by a fixture diff). These exports give it the daemon's OWN types,
// compiled to wasm: the route is the shared `MASTER_MEMORY_PLANT_ROUTE` const
// and the body bytes come from serde_json over the shared structs — the exact
// serializer family the daemon deserializes with. A daemon-side field/route
// change is now a frontend compile error (via the ts-rs `ApiMemoryEntry`
// type) + a wasm rebuild, never a silently-drifted hand-rolled body.

/// The canonical plant route (`agentkeys_protocol::web_api::MASTER_MEMORY_PLANT_ROUTE`).
#[wasm_bindgen(js_name = masterMemoryPlantRoute)]
pub fn master_memory_plant_route() -> String {
    agentkeys_protocol::web_api::MASTER_MEMORY_PLANT_ROUTE.to_string()
}

/// Build the plant POST body from an `ApiMemoryEntry[]` (ts-rs-typed on the JS
/// side). Validates through the real serde types and returns the serialized
/// JSON string — post it verbatim (`content-type: application/json`).
#[wasm_bindgen(js_name = buildMasterMemoryPlantBody)]
pub fn build_master_memory_plant_body(entries: JsValue) -> Result<String, JsValue> {
    let entries: Vec<ApiMemoryEntry> = serde_wasm_bindgen::from_value(entries).map_err(to_js)?;
    serde_json::to_string(&MasterMemoryPlantRequest { entries }).map_err(to_js)
}

/// The host-agnostic master-plane core, exposed to the browser. One per broker
/// base URL; holds no secret.
#[wasm_bindgen]
pub struct WebCore {
    broker: BrokerClient,
}

#[wasm_bindgen]
impl WebCore {
    /// `new WebCore("https://broker.example.invalid")`.
    #[wasm_bindgen(constructor)]
    pub fn new(broker_base_url: String) -> WebCore {
        WebCore {
            broker: BrokerClient::new(broker_base_url),
        }
    }

    // ── cap-mint (one method per route; `req` is a CapRequest-shaped object) ──

    #[wasm_bindgen(js_name = capMemoryPut)]
    pub async fn cap_memory_put(&self, bearer: String, req: JsValue) -> Result<JsValue, JsValue> {
        let req: CapRequest = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let tok = self
            .broker
            .cap_memory_put(&bearer, &req)
            .await
            .map_err(to_js)?;
        serde_wasm_bindgen::to_value(&tok).map_err(to_js)
    }

    #[wasm_bindgen(js_name = capMemoryGet)]
    pub async fn cap_memory_get(&self, bearer: String, req: JsValue) -> Result<JsValue, JsValue> {
        let req: CapRequest = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let tok = self
            .broker
            .cap_memory_get(&bearer, &req)
            .await
            .map_err(to_js)?;
        serde_wasm_bindgen::to_value(&tok).map_err(to_js)
    }

    #[wasm_bindgen(js_name = capCredStore)]
    pub async fn cap_cred_store(&self, bearer: String, req: JsValue) -> Result<JsValue, JsValue> {
        let req: CapRequest = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let tok = self
            .broker
            .cap_cred_store(&bearer, &req)
            .await
            .map_err(to_js)?;
        serde_wasm_bindgen::to_value(&tok).map_err(to_js)
    }

    #[wasm_bindgen(js_name = capCredFetch)]
    pub async fn cap_cred_fetch(&self, bearer: String, req: JsValue) -> Result<JsValue, JsValue> {
        let req: CapRequest = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let tok = self
            .broker
            .cap_cred_fetch(&bearer, &req)
            .await
            .map_err(to_js)?;
        serde_wasm_bindgen::to_value(&tok).map_err(to_js)
    }

    // ── pairing (master-side, arch §10.2 method A) ──

    #[wasm_bindgen(js_name = pairingClaim)]
    pub async fn pairing_claim(&self, bearer: String, req: JsValue) -> Result<JsValue, JsValue> {
        let req: PairingClaimRequest = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let claimed = self
            .broker
            .pairing_claim(&bearer, &req)
            .await
            .map_err(to_js)?;
        serde_wasm_bindgen::to_value(&claimed).map_err(to_js)
    }

    #[wasm_bindgen(js_name = pendingBindings)]
    pub async fn pending_bindings(&self, bearer: String) -> Result<JsValue, JsValue> {
        let pending = self.broker.pending_bindings(&bearer).await.map_err(to_js)?;
        serde_wasm_bindgen::to_value(&pending).map_err(to_js)
    }

    #[wasm_bindgen(js_name = ackBinding)]
    pub async fn ack_binding(
        &self,
        bearer: String,
        request_id: String,
    ) -> Result<JsValue, JsValue> {
        let ack = self
            .broker
            .ack_binding(&bearer, &request_id)
            .await
            .map_err(to_js)?;
        serde_wasm_bindgen::to_value(&ack).map_err(to_js)
    }
}

// ── the browser DEVICE actor (#675) ──────────────────────────────────────────
//
// `apps/device-display` (a shared kitchen tablet) is its OWN device actor: the
// K10 lives in the page, pairing + resolve + channel caps + the worker calls
// all go through these bindings, and the card/command wire shapes are the
// protocol crate's — compiled in, never re-typed in TypeScript.

use crate::broker::{ChannelWorkerClient, PairingPollBody, PairingRequestBody, ResolveBody};
use agentkeys_protocol::{CardCommand, CardDocument, ChannelPollBody, ChannelPublishBody};
use base64::Engine as _;
use serde::Serialize;

/// JSON-compatible JS values (plain objects, not ES Maps) for serde maps.
fn to_js_json<T: Serialize + ?Sized>(v: &T) -> Result<JsValue, JsValue> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(to_js)
}

/// The page-held K10 (see `device.rs`). Construct from the persisted secret,
/// or mint one from 32 bytes of `crypto.getRandomValues` entropy.
#[wasm_bindgen]
pub struct DeviceIdentity {
    inner: crate::device::DeviceIdentity,
}

#[wasm_bindgen]
impl DeviceIdentity {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_hex: String) -> Result<DeviceIdentity, JsValue> {
        Ok(Self {
            inner: crate::device::DeviceIdentity::from_secret_hex(&secret_hex).map_err(to_js)?,
        })
    }

    #[wasm_bindgen(js_name = fromRandomBytes)]
    pub fn from_random_bytes(bytes: &[u8]) -> Result<DeviceIdentity, JsValue> {
        Ok(Self {
            inner: crate::device::DeviceIdentity::from_random_bytes(bytes).map_err(to_js)?,
        })
    }

    #[wasm_bindgen(js_name = secretHex)]
    pub fn secret_hex(&self) -> String {
        self.inner.secret_hex()
    }

    pub fn address(&self) -> String {
        self.inner.address()
    }

    #[wasm_bindgen(js_name = deviceKeyHash)]
    pub fn device_key_hash(&self) -> Result<String, JsValue> {
        self.inner.device_key_hash().map_err(to_js)
    }

    #[wasm_bindgen(js_name = agentPopSig)]
    pub fn agent_pop_sig(&self) -> Result<String, JsValue> {
        self.inner.agent_pop_sig().map_err(to_js)
    }

    #[wasm_bindgen(js_name = capPopSig)]
    #[allow(clippy::too_many_arguments)]
    pub fn cap_pop_sig(
        &self,
        operator_omni: String,
        actor_omni: String,
        service: String,
        op: String,
        data_class: String,
        client_nonce: String,
        client_ts: u64,
    ) -> Result<String, JsValue> {
        self.inner
            .cap_pop_sig(
                &operator_omni,
                &actor_omni,
                &service,
                &op,
                &data_class,
                &client_nonce,
                client_ts,
            )
            .map_err(to_js)
    }
}

#[wasm_bindgen]
impl WebCore {
    // ── the device side of §10.2 (no bearer: PoP-gated) ──

    #[wasm_bindgen(js_name = pairingRequest)]
    pub async fn pairing_request(&self, req: JsValue) -> Result<JsValue, JsValue> {
        let req: PairingRequestBody = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let out = self.broker.pairing_request(&req).await.map_err(to_js)?;
        to_js_json(&out)
    }

    #[wasm_bindgen(js_name = pairingPoll)]
    pub async fn pairing_poll(&self, req: JsValue) -> Result<JsValue, JsValue> {
        let req: PairingPollBody = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let out = self.broker.pairing_poll(&req).await.map_err(to_js)?;
        to_js_json(&out)
    }

    #[wasm_bindgen(js_name = agentResolve)]
    pub async fn agent_resolve(&self, req: JsValue) -> Result<JsValue, JsValue> {
        let req: ResolveBody = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let out = self.broker.agent_resolve(&req).await.map_err(to_js)?;
        to_js_json(&out)
    }

    // ── channel caps, minted with the DEVICE's own session ──

    #[wasm_bindgen(js_name = capChannelSub)]
    pub async fn cap_channel_sub(&self, bearer: String, req: JsValue) -> Result<JsValue, JsValue> {
        let req: CapRequest = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let cap = self
            .broker
            .cap_channel_sub(&bearer, &req)
            .await
            .map_err(to_js)?;
        to_js_json(&cap)
    }

    #[wasm_bindgen(js_name = capChannelPub)]
    pub async fn cap_channel_pub(&self, bearer: String, req: JsValue) -> Result<JsValue, JsValue> {
        let req: CapRequest = serde_wasm_bindgen::from_value(req).map_err(to_js)?;
        let cap = self
            .broker
            .cap_channel_pub(&bearer, &req)
            .await
            .map_err(to_js)?;
        to_js_json(&cap)
    }
}

/// The channel worker (poll + publish), one per worker base URL.
#[wasm_bindgen]
pub struct ChannelWorker {
    inner: ChannelWorkerClient,
}

#[wasm_bindgen]
impl ChannelWorker {
    #[wasm_bindgen(constructor)]
    pub fn new(worker_base_url: String) -> ChannelWorker {
        ChannelWorker {
            inner: ChannelWorkerClient::new(worker_base_url),
        }
    }

    /// `{ cap, after, wait_seconds }` → `{ ok, events, cursor }`.
    pub async fn poll(&self, body: JsValue) -> Result<JsValue, JsValue> {
        let body: ChannelPollBody = serde_wasm_bindgen::from_value(body).map_err(to_js)?;
        let out = self.inner.poll(&body).await.map_err(to_js)?;
        to_js_json(&out)
    }

    /// A `ChannelPublishBody`-shaped object → `{ ok, event_id, … }`.
    pub async fn publish(&self, body: JsValue) -> Result<JsValue, JsValue> {
        let body: ChannelPublishBody = serde_wasm_bindgen::from_value(body).map_err(to_js)?;
        let out = self.inner.publish(&body).await.map_err(to_js)?;
        to_js_json(&out)
    }
}

/// `https://channel-test.agentterrier.cn` from `https://test-broker.agentterrier.cn`
/// — the ONE derivation (`agentkeys_protocol::derive_worker_url`).
#[wasm_bindgen(js_name = deriveWorkerUrl)]
pub fn derive_worker_url(broker_url: String, worker: String) -> Option<String> {
    agentkeys_protocol::derive_worker_url(&broker_url, &worker)
}

/// Validate a `doc` event body (the card JSON, already base64-decoded) through
/// the protocol's own parser and hand it to the renderer as a plain object.
#[wasm_bindgen(js_name = parseCardJson)]
pub fn parse_card_json(json: String) -> Result<JsValue, JsValue> {
    let card = agentkeys_protocol::parse_card(json.as_bytes()).map_err(to_js)?;
    to_js_json(&card)
}

/// The `command` event body (base64 JSON of the protocol's `CardCommand`) for
/// tapping `action_id` on `card` — the same bytes the console publishes.
#[wasm_bindgen(js_name = buildCardCommandBodyB64)]
pub fn build_card_command_body_b64(card: JsValue, action_id: String) -> Result<String, JsValue> {
    let card: CardDocument = serde_wasm_bindgen::from_value(card).map_err(to_js)?;
    let action = card
        .actions
        .iter()
        .find(|a| a.id == action_id)
        .ok_or_else(|| to_js(format!("unknown card action id: {action_id}")))?;
    let cmd = CardCommand::for_action(&card, action);
    let bytes = serde_json::to_vec(&cmd).map_err(to_js)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}
