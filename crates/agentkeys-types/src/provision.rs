use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TripwireKind {
    SelectorTimeout,
    UnexpectedNav,
    Http5xx,
    EmailTimeout,
    VerificationFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionErrorCode {
    ProvisionInProgress,
    TripwireExhausted,
    EmailBackendDown,
    VerificationEndpointDown,
    StoreFailed,
    MalformedEvent,
    Timeout,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProvisionEvent {
    Progress {
        step: String,
    },
    Tripwire {
        kind: TripwireKind,
        step: String,
        elapsed_ms: u64,
    },
    Success {
        api_key: String,
    },
    Error {
        code: ProvisionErrorCode,
        details: String,
    },
}

impl ProvisionEvent {
    pub fn progress(step: impl Into<String>) -> Self {
        Self::Progress { step: step.into() }
    }

    pub fn tripwire(kind: TripwireKind, step: impl Into<String>, elapsed_ms: u64) -> Self {
        Self::Tripwire {
            kind,
            step: step.into(),
            elapsed_ms,
        }
    }

    pub fn success(api_key: impl Into<String>) -> Self {
        Self::Success {
            api_key: api_key.into(),
        }
    }

    pub fn error(code: ProvisionErrorCode, details: impl Into<String>) -> Self {
        Self::Error {
            code,
            details: details.into(),
        }
    }

    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provision_event_tagged_serialization() {
        let e = ProvisionEvent::progress("creating_account");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"type\":\"progress\""));
        assert!(json.contains("\"step\":\"creating_account\""));
    }

    #[test]
    fn provision_event_roundtrip_every_variant() {
        let variants = vec![
            ProvisionEvent::progress("waiting_for_email"),
            ProvisionEvent::tripwire(TripwireKind::SelectorTimeout, "submit_button", 15_000),
            ProvisionEvent::tripwire(TripwireKind::EmailTimeout, "otp_fetch", 60_000),
            ProvisionEvent::tripwire(TripwireKind::VerificationFailed, "post_key_verify", 800),
            ProvisionEvent::success("sk-or-v1-abcd1234"),
            ProvisionEvent::error(ProvisionErrorCode::StoreFailed, "backend returned 500"),
            ProvisionEvent::error(ProvisionErrorCode::MalformedEvent, "invalid json line"),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ProvisionEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(v, &back, "roundtrip failed for {:?}", v);
        }
    }

    #[test]
    fn tripwire_kind_variants_distinct() {
        let kinds = [
            TripwireKind::SelectorTimeout,
            TripwireKind::UnexpectedNav,
            TripwireKind::Http5xx,
            TripwireKind::EmailTimeout,
            TripwireKind::VerificationFailed,
        ];
        let jsons: Vec<String> = kinds
            .iter()
            .map(|k| serde_json::to_string(k).unwrap())
            .collect();
        let unique: std::collections::HashSet<_> = jsons.iter().collect();
        assert_eq!(
            unique.len(),
            kinds.len(),
            "tripwire kinds collide: {:?}",
            jsons
        );
    }

    #[test]
    fn provision_error_code_variants_distinct() {
        let codes = [
            ProvisionErrorCode::ProvisionInProgress,
            ProvisionErrorCode::TripwireExhausted,
            ProvisionErrorCode::EmailBackendDown,
            ProvisionErrorCode::VerificationEndpointDown,
            ProvisionErrorCode::StoreFailed,
            ProvisionErrorCode::MalformedEvent,
            ProvisionErrorCode::Timeout,
            ProvisionErrorCode::Internal,
        ];
        let jsons: Vec<String> = codes
            .iter()
            .map(|c| serde_json::to_string(c).unwrap())
            .collect();
        let unique: std::collections::HashSet<_> = jsons.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "error codes collide: {:?}",
            jsons
        );
    }

    #[test]
    fn to_json_line_is_single_line() {
        let e = ProvisionEvent::progress("step with spaces and \"quotes\"");
        let line = e.to_json_line().unwrap();
        assert!(
            !line.contains('\n'),
            "json line contains newline: {:?}",
            line
        );
    }
}
