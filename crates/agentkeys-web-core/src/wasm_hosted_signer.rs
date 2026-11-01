use crate::broker::BrokerClient;
use agentkeys_protocol::hosted_signer::*;
use wasm_bindgen::prelude::*;
fn js(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
fn value<T: serde::Serialize>(body: &T) -> Result<JsValue, JsValue> {
    body.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js)
}

#[wasm_bindgen]
pub struct HostedSignerClient {
    broker: BrokerClient,
}
#[wasm_bindgen]
impl HostedSignerClient {
    #[wasm_bindgen(constructor)]
    pub fn new(broker_url: String) -> Self {
        Self {
            broker: BrokerClient::new(broker_url),
        }
    }
    pub async fn start(&self, bearer: String, request: JsValue) -> Result<JsValue, JsValue> {
        value(
            &self
                .broker
                .hosted_signer_start(
                    &bearer,
                    &serde_wasm_bindgen::from_value(request).map_err(js)?,
                )
                .await
                .map_err(js)?,
        )
    }
    pub async fn status(&self, bearer: String, request: JsValue) -> Result<JsValue, JsValue> {
        value(
            &self
                .broker
                .hosted_signer_status(
                    &bearer,
                    &serde_wasm_bindgen::from_value(request).map_err(js)?,
                )
                .await
                .map_err(js)?,
        )
    }
    pub async fn prepare(&self, bearer: String, request: JsValue) -> Result<JsValue, JsValue> {
        value(
            &self
                .broker
                .hosted_signer_prepare(
                    &bearer,
                    &serde_wasm_bindgen::from_value(request).map_err(js)?,
                )
                .await
                .map_err(js)?,
        )
    }
    pub async fn build(&self, bearer: String, request: JsValue) -> Result<JsValue, JsValue> {
        value(
            &self
                .broker
                .hosted_signer_build(
                    &bearer,
                    &serde_wasm_bindgen::from_value(request).map_err(js)?,
                )
                .await
                .map_err(js)?,
        )
    }
    pub async fn publish(&self, bearer: String, request: JsValue) -> Result<JsValue, JsValue> {
        value(
            &self
                .broker
                .hosted_signer_publish(
                    &bearer,
                    &serde_wasm_bindgen::from_value(request).map_err(js)?,
                )
                .await
                .map_err(js)?,
        )
    }
    pub async fn pending(&self, bearer: String) -> Result<JsValue, JsValue> {
        value(
            &self
                .broker
                .hosted_signer_pending(&bearer)
                .await
                .map_err(js)?,
        )
    }
    pub async fn dismiss(&self, bearer: String, id: String) -> Result<JsValue, JsValue> {
        value(
            &self
                .broker
                .hosted_signer_dismiss(&bearer, &HostedSignerRequestId { id })
                .await
                .map_err(js)?,
        )
    }
    #[wasm_bindgen(js_name=passkeyStart)]
    pub async fn passkey_start(&self, omni: String) -> Result<JsValue, JsValue> {
        value(&self.broker.hosted_passkey_start(&omni).await.map_err(js)?)
    }
    #[wasm_bindgen(js_name=passkeyFinish)]
    pub async fn passkey_finish(
        &self,
        challenge: String,
        assertion: JsValue,
    ) -> Result<JsValue, JsValue> {
        value(
            &self
                .broker
                .hosted_passkey_finish(&HostedPasskeyVerify {
                    challenge,
                    assertion: serde_wasm_bindgen::from_value(assertion).map_err(js)?,
                })
                .await
                .map_err(js)?,
        )
    }
}
#[wasm_bindgen(js_name=hostedEnrollmentDeviceProof)]
pub fn enrollment_device_proof(
    secret_hex: String,
    challenge_hex: String,
) -> Result<String, JsValue> {
    let challenge = hex::decode(challenge_hex.trim_start_matches("0x")).map_err(js)?;
    if challenge.len() != 32 {
        return Err(js("enrollment challenge must be 32 bytes"));
    }
    crate::device::DeviceIdentity::from_secret_hex(&secret_hex)
        .map_err(js)?
        .sign(&challenge)
        .map_err(js)
}
#[wasm_bindgen(js_name=parseHostedSignerApproval)]
pub fn parse_approval(json: String) -> Result<JsValue, JsValue> {
    let approval: HostedSignerApproval = serde_json::from_str(&json).map_err(js)?;
    value(&approval)
}
