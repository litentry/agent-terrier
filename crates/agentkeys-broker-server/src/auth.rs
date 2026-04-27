use crate::error::{BrokerError, BrokerResult};

#[derive(Debug, Clone)]
pub struct ValidatedSession {
    pub wallet: String,
}

pub fn extract_bearer_token(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ")
}

pub async fn validate_bearer_token(
    http: &reqwest::Client,
    backend_url: &str,
    token: &str,
) -> BrokerResult<ValidatedSession> {
    let url = format!("{}/session/validate", backend_url.trim_end_matches('/'));
    let response = http
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| BrokerError::BackendUnreachable(e.to_string()))?;

    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
        let msg = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("session not valid")
            .to_string();
        return Err(BrokerError::Unauthorized(msg));
    }
    if !status.is_success() {
        return Err(BrokerError::BackendUnreachable(format!(
            "backend returned {}",
            status
        )));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| BrokerError::BackendUnreachable(format!("parse validate response: {}", e)))?;
    let wallet = body
        .get("wallet")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            BrokerError::BackendUnreachable("validate response missing wallet field".into())
        })?
        .to_string();

    Ok(ValidatedSession { wallet })
}
