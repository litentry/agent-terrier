//! `GateTurn` (op_kind 90) emission — one row per proxied turn, into the
//! anchored two-tier audit via the shared `BackendClient` (the #203 one-owner
//! client; the relay never re-types a wire body).
//!
//! Envelope attribution: `actor_omni` = `operator_omni` = the OWNING USER's
//! omni — usage always accumulates to one user (#384); the per-device /
//! per-api-key attribution lives in the typed body.

use agentkeys_backend_client::{AuditAppendInput, BackendClient};
use agentkeys_core::audit::{AuditOpKind, GateTurnBody, SpeechAsrBody, SpeechTtsBody};

pub struct Auditor {
    client: BackendClient,
}

/// Envelope `result` byte for a turn outcome (arch.md §15.3a: 0=Success,
/// 1=Failure, 2=NotPermitted).
pub fn result_code(outcome: &str) -> u8 {
    match outcome {
        "ok" => 0,
        "denied:budget_exceeded" => 2,
        _ => 1,
    }
}

impl Auditor {
    pub fn new(audit_url: String, aws_region: String) -> Self {
        Self {
            client: BackendClient::new(
                None,
                None,
                Some(audit_url),
                None,
                None,
                None,
                None,
                aws_region,
            ),
        }
    }

    pub async fn emit_turn(&self, user_omni: &str, body: GateTurnBody) -> Result<(), String> {
        let result = result_code(&body.outcome);
        let op_body = serde_json::to_value(&body).map_err(|e| e.to_string())?;
        self.emit(user_omni, AuditOpKind::GateTurn, op_body, result)
            .await
    }

    /// #519 — one ASR transcription through the speech relay (op_kind 91).
    pub async fn emit_speech_asr(
        &self,
        user_omni: &str,
        body: SpeechAsrBody,
    ) -> Result<(), String> {
        let result = result_code(&body.outcome);
        let op_body = serde_json::to_value(&body).map_err(|e| e.to_string())?;
        self.emit(user_omni, AuditOpKind::SpeechAsr, op_body, result)
            .await
    }

    /// #519 — one TTS synthesis through the speech relay (op_kind 92).
    pub async fn emit_speech_tts(
        &self,
        user_omni: &str,
        body: SpeechTtsBody,
    ) -> Result<(), String> {
        let result = result_code(&body.outcome);
        let op_body = serde_json::to_value(&body).map_err(|e| e.to_string())?;
        self.emit(user_omni, AuditOpKind::SpeechTts, op_body, result)
            .await
    }

    async fn emit(
        &self,
        user_omni: &str,
        op_kind: AuditOpKind,
        op_body: serde_json::Value,
        result: u8,
    ) -> Result<(), String> {
        let input = AuditAppendInput {
            operator_omni: user_omni.to_string(),
            actor_omni: user_omni.to_string(),
            op_kind: op_kind as u8,
            op_body,
            result,
            intent_text: None,
        };
        self.client
            .audit_append(input)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_maps_to_result_byte() {
        assert_eq!(result_code("ok"), 0);
        assert_eq!(result_code("denied:budget_exceeded"), 2);
        assert_eq!(result_code("upstream_error"), 1);
    }
}
