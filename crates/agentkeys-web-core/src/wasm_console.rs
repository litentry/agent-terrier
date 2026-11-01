use crate::{console::ConsoleService, data::DataSession, device::DeviceIdentity};
use serde::Serialize;
use wasm_bindgen::prelude::*;
fn js(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
fn value<T: Serialize>(body: &T) -> Result<JsValue, JsValue> {
    body.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js)
}

#[wasm_bindgen(js_name=consoleConfiguration)]
pub async fn configuration(broker_url: String) -> Result<JsValue, JsValue> {
    value(
        &ConsoleService::configuration(&crate::broker::BrokerClient::new(broker_url))
            .await
            .map_err(js)?,
    )
}

#[wasm_bindgen]
pub struct ConsoleClient {
    inner: ConsoleService,
}
#[wasm_bindgen]
impl ConsoleClient {
    #[wasm_bindgen(constructor)]
    pub fn new(broker_url: String, config: JsValue) -> Result<ConsoleClient, JsValue> {
        Ok(Self {
            inner: ConsoleService::new(
                broker_url,
                serde_wasm_bindgen::from_value(config).map_err(js)?,
            ),
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn request(
        &self,
        bearer: String,
        omni: String,
        master_secret: String,
        console_secret: String,
        now: u64,
        method: String,
        path: String,
        body: JsValue,
    ) -> Result<JsValue, JsValue> {
        let device = DeviceIdentity::from_secret_hex(&master_secret).map_err(js)?;
        let console = DeviceIdentity::from_secret_hex(&console_secret).map_err(js)?;
        let session = DataSession {
            bearer: &bearer,
            operator_omni: &omni,
            actor_omni: &omni,
            device: &device,
            now_unix_seconds: now,
        };
        value(
            &self
                .inner
                .request(
                    &session,
                    Some(&console),
                    &method,
                    &path,
                    serde_wasm_bindgen::from_value(body).map_err(js)?,
                )
                .await
                .map_err(js)?,
        )
    }
    #[wasm_bindgen(js_name=configRead)]
    pub async fn config_read(
        &self,
        bearer: String,
        omni: String,
        master_secret: String,
        now: u64,
        service: String,
    ) -> Result<JsValue, JsValue> {
        let device = DeviceIdentity::from_secret_hex(&master_secret).map_err(js)?;
        let session = DataSession {
            bearer: &bearer,
            operator_omni: &omni,
            actor_omni: &omni,
            device: &device,
            now_unix_seconds: now,
        };
        match self
            .inner
            .data
            .config_get(&session, &service)
            .await
            .map_err(js)?
        {
            Some(document) => value(
                &serde_json::json!({"value":serde_json::from_slice::<serde_json::Value>(&document.plaintext).map_err(js)?,"revision":document.revision}),
            ),
            None => Ok(JsValue::NULL),
        }
    }
    #[wasm_bindgen(js_name=configWrite)]
    #[allow(clippy::too_many_arguments)]
    pub async fn config_write(
        &self,
        bearer: String,
        omni: String,
        master_secret: String,
        now: u64,
        service: String,
        document: JsValue,
        revision: String,
    ) -> Result<(), JsValue> {
        let device = DeviceIdentity::from_secret_hex(&master_secret).map_err(js)?;
        let session = DataSession {
            bearer: &bearer,
            operator_omni: &omni,
            actor_omni: &omni,
            device: &device,
            now_unix_seconds: now,
        };
        let document: serde_json::Value = serde_wasm_bindgen::from_value(document).map_err(js)?;
        self.inner
            .data
            .config_put(
                &session,
                &service,
                &serde_json::to_vec(&document).map_err(js)?,
                &revision,
            )
            .await
            .map_err(js)
    }
}

#[wasm_bindgen(js_name=gatewayContactsService)]
pub fn gateway_contacts_service() -> String {
    agentkeys_protocol::console::GATEWAY_CONTACTS_SERVICE.into()
}
