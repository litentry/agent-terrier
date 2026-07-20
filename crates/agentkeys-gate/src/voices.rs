//! #527 — the gate's TTS voices catalog: `GET /v1/audio/voices` returns the
//! account's Doubao bigmodel speakers via the V4-signed `ListBigModelTTSTimbres`
//! OpenAPI.
//!
//! CUSTODY DECISION (recorded in docs/spec/stacks/ve-sts-signing-split.md):
//! the catalog needs a Volcengine IAM AK/SK (the app tokens the speech relay
//! holds can't sign an OpenAPI call), so this is the ONE place the gate holds an
//! IAM credential — consistent with the #386 gate-held-key posture (the
//! credential lives on the gate, never in a sandbox or on a device). The AK/SK
//! MUST be a sub-user/role scoped to `speech_saas_prod:ListBigModelTTSTimbres`
//! (read-only, no synthesis, no account mutation), so a gate compromise leaks a
//! list-voices key, not account control. The rejected alternative — a periodic
//! operator-side `volcano-probe voices` snapshot shipped as config — is staler
//! and adds an operator job; live-but-scoped won.
//!
//! Unconfigured (no IAM AK/SK) ⇒ the endpoint 503s `NotConfigured`, loudly —
//! never a silent empty list. The device/fleet pickers keep their static
//! real-id fallback (#524) until this is provisioned.

use agentkeys_core::ve_sign::{now_x_date, sign, VeSignRequest};
use serde::Serialize;

use crate::error::{GateError, GateResult};

const HOST: &str = "open.volcengineapi.com";
const REGION: &str = "cn-beijing";
const SERVICE: &str = "speech_saas_prod";
const QUERY: &str = "Action=ListBigModelTTSTimbres&Version=2025-05-20";

/// The gate-held IAM credential for the voices OpenAPI. `None` = unconfigured
/// (the endpoint 503s). Scope it to `ListBigModelTTSTimbres` at the IAM layer.
#[derive(Clone)]
pub struct VoicesConfig {
    pub access_key: String,
    pub secret_key: String,
}

impl VoicesConfig {
    /// From `VOLCENGINE_ACCESS_KEY` / `VOLCENGINE_SECRET_KEY` (the same names the
    /// probe + the veFaaS/STS planes read). Both present ⇒ `Some`; either
    /// missing ⇒ `None` (unconfigured, not an error).
    pub fn from_env() -> Option<Self> {
        let access_key = std::env::var("VOLCENGINE_ACCESS_KEY").ok()?;
        let secret_key = std::env::var("VOLCENGINE_SECRET_KEY").ok()?;
        if access_key.trim().is_empty() || secret_key.trim().is_empty() {
            return None;
        }
        Some(Self {
            access_key,
            secret_key,
        })
    }
}

/// One catalog entry the picker consumes.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Voice {
    pub id: String,
    pub name: String,
    pub scenario: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VoicesResponse {
    pub voices: Vec<Voice>,
}

/// Parse the `ListBigModelTTSTimbres` JSON into the catalog. Split out so it is
/// unit-tested without a live call.
fn parse_timbres(v: &serde_json::Value) -> Vec<Voice> {
    v["Result"]["Timbres"]
        .as_array()
        .map(|timbres| {
            timbres
                .iter()
                .filter_map(|t| {
                    let id = t["SpeakerID"].as_str().unwrap_or_default().to_string();
                    if id.is_empty() {
                        return None;
                    }
                    let info = &t["TimbreInfos"][0];
                    Some(Voice {
                        id,
                        name: info["SpeakerName"].as_str().unwrap_or_default().to_string(),
                        scenario: info["Categories"][0]["Category"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Fetch the catalog. `None` config ⇒ 503 `NotConfigured` (loud, never empty).
pub async fn fetch_voices(cfg: Option<&VoicesConfig>) -> GateResult<VoicesResponse> {
    let cfg = cfg.ok_or_else(|| {
        GateError::NotConfigured(
            "voices catalog not configured on this gate (no VOLCENGINE_ACCESS_KEY / \
             VOLCENGINE_SECRET_KEY — scope a sub-user to speech_saas_prod:ListBigModelTTSTimbres)"
                .into(),
        )
    })?;
    let body = b"{}";
    let x_date = now_x_date();
    let signed = sign(&VeSignRequest {
        access_key_id: &cfg.access_key,
        secret_access_key: &cfg.secret_key,
        session_token: None,
        region: REGION,
        service: SERVICE,
        host: HOST,
        method: "POST",
        path: "/",
        query: QUERY,
        body,
        content_type: "application/json",
        x_date: &x_date,
    });
    let resp = reqwest::Client::new()
        .post(format!("https://{HOST}/?{QUERY}"))
        .header("X-Date", &signed.x_date)
        .header("X-Content-Sha256", &signed.x_content_sha256)
        .header("Authorization", &signed.authorization)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| GateError::Upstream(format!("list-voices request failed: {e}")))?;
    let status = resp.status();
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| GateError::Upstream(format!("list-voices response not JSON: {e}")))?;
    if v["ResponseMetadata"]["Error"].is_object() {
        tracing::error!(status = %status, error = %v["ResponseMetadata"]["Error"], "ListBigModelTTSTimbres error");
        return Err(GateError::Upstream(format!(
            "ListBigModelTTSTimbres returned an error (http {status})"
        )));
    }
    Ok(VoicesResponse {
        voices: parse_timbres(&v),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_is_503_not_empty() {
        let err = fetch_voices(None).await.unwrap_err();
        assert!(matches!(err, GateError::NotConfigured(_)), "{err}");
        assert_eq!(err.status(), 503);
    }

    #[test]
    fn parse_timbres_extracts_id_name_scenario() {
        let v = serde_json::json!({
            "Result": { "Timbres": [
                { "SpeakerID": "zh_female_meilinvyou_moon_bigtts",
                  "TimbreInfos": [{ "SpeakerName": "魅力女友",
                                    "Categories": [{ "Category": "通用" }] }] },
                { "SpeakerID": "", "TimbreInfos": [{}] } // skipped (empty id)
            ] }
        });
        let voices = parse_timbres(&v);
        assert_eq!(voices.len(), 1);
        assert_eq!(voices[0].id, "zh_female_meilinvyou_moon_bigtts");
        assert_eq!(voices[0].name, "魅力女友");
        assert_eq!(voices[0].scenario, "通用");
    }
}
