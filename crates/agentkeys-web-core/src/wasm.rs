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

fn to_js<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// The host-agnostic master-plane core, exposed to the browser. One per broker
/// base URL; holds no secret.
#[wasm_bindgen]
pub struct WebCore {
    broker: BrokerClient,
}

#[wasm_bindgen]
impl WebCore {
    /// `new WebCore("https://broker.litentry.org")`.
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
