use super::{AuditEnvelope, AuditError};
pub use agentkeys_protocol::AuditAppendV2Resp as AppendV2Response;
pub use agentkeys_web_core::audit::client::envelope_for;
use agentkeys_web_core::audit::client::envelope_to_json;
use std::time::Duration;

pub const MAX_ARCHIVE_RESPONSE_BYTES: usize = 32 * 1024;
pub struct AuditClient {
    base_url: String,
    http: reqwest::Client,
    bearer: Result<Option<zeroize::Zeroizing<String>>, String>,
    service_credential: bool,
}
impl AuditClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let bearer = std::env::var_os("AGENTKEYS_AUDIT_TOKEN_FILE")
            .map(|path| {
                crate::protected_file::read_token(std::path::Path::new(&path))
                    .map_err(|_| "audit service credential is unavailable".to_owned())
            })
            .transpose();
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .expect("audit HTTP client"),
            bearer,
            service_credential: std::env::var_os("AGENTKEYS_AUDIT_TOKEN_FILE").is_some(),
        }
    }
    pub fn from_env() -> Self {
        Self::new(std::env::var("AGENTKEYS_AUDIT_WORKER_URL").unwrap_or_default())
    }
    pub fn with_bearer(base_url: impl Into<String>, bearer: String) -> Self {
        let mut client = Self::new(base_url);
        client.bearer = Ok(Some(zeroize::Zeroizing::new(bearer)));
        client.service_credential = false;
        client
    }
    fn request(
        &self,
        method: reqwest::Method,
        route: &str,
    ) -> Result<reqwest::RequestBuilder, AuditError> {
        if self.base_url.is_empty() {
            return Err(AuditError::Invalid(
                "audit archive is not configured".into(),
            ));
        }
        if self.service_credential
            && !crate::chain_profile::is_loopback_http_endpoint(&self.base_url)
        {
            return Err(AuditError::Invalid(
                "audit service credential requires loopback transport".into(),
            ));
        }
        let mut request = self
            .http
            .request(method, format!("{}{route}", self.base_url));
        if let Some(token) = self
            .bearer
            .as_ref()
            .map_err(|message| AuditError::Invalid(message.clone()))?
        {
            request = request.bearer_auth(token.as_str());
        }
        Ok(request)
    }
    async fn response(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Option<Vec<u8>>, AuditError> {
        let mut response = request
            .send()
            .await
            .map_err(|_| AuditError::Invalid("audit archive transport failed".into()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(AuditError::Invalid(format!(
                "audit archive HTTP {}",
                response.status().as_u16()
            )));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuditError::Invalid("audit response failed".into()))?
        {
            if bytes.len() + chunk.len() > MAX_ARCHIVE_RESPONSE_BYTES {
                return Err(AuditError::Invalid("audit response exceeds limit".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Some(bytes))
    }
    pub async fn append_json(
        &self,
        envelope: &agentkeys_protocol::AuditAppendV2,
    ) -> Result<AppendV2Response, AuditError> {
        let request = self
            .request(reqwest::Method::POST, "/v1/audit/append/v2")?
            .json(envelope);
        let bytes = self
            .response(request)
            .await?
            .ok_or_else(|| AuditError::Invalid("audit append was not accepted".into()))?;
        let receipt: AppendV2Response = serde_json::from_slice(&bytes)
            .map_err(|_| AuditError::Invalid("invalid audit receipt".into()))?;
        if !receipt.ok || !valid_hash(&receipt.envelope_hash) {
            return Err(AuditError::Invalid("invalid audit receipt".into()));
        }
        Ok(receipt)
    }
    pub async fn append(&self, envelope: &AuditEnvelope) -> Result<AppendV2Response, AuditError> {
        let body = serde_json::from_value(envelope_to_json(envelope)?)
            .map_err(|_| AuditError::Invalid("invalid audit envelope".into()))?;
        self.append_json(&body).await
    }
    pub async fn list_envelopes(
        &self,
        operator: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<agentkeys_protocol::AuditArchivePage, AuditError> {
        if limit == 0 || limit > 100 || cursor.is_some_and(|value| !valid_hash(value)) {
            return Err(AuditError::Invalid("invalid audit page selection".into()));
        }
        let mut request = self
            .request(reqwest::Method::GET, "/v1/audit/envelopes")?
            .query(&[("limit", limit)]);
        if let Some(operator) = operator {
            request = request.query(&[("operator_omni", operator)]);
        }
        if let Some(cursor) = cursor {
            request = request.query(&[("cursor", cursor)]);
        }
        let bytes = self
            .response(request)
            .await?
            .ok_or_else(|| AuditError::Invalid("audit index unavailable".into()))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| AuditError::Invalid("invalid audit index".into()))
    }
    pub async fn get_envelope(&self, hash: &str) -> Result<Option<Vec<u8>>, AuditError> {
        self.get_envelope_for_operator(hash, None).await
    }
    pub async fn get_envelope_for_operator(
        &self,
        hash: &str,
        operator: Option<&str>,
    ) -> Result<Option<Vec<u8>>, AuditError> {
        if !valid_hash(hash) {
            return Err(AuditError::Invalid("invalid audit hash".into()));
        }
        let mut request =
            self.request(reqwest::Method::GET, &format!("/v1/audit/envelope/{hash}"))?;
        if let Some(operator) = operator {
            request = request.query(&[("operator_omni", operator)]);
        }
        let bytes = self.response(request).await?;
        if let Some(bytes) = &bytes {
            let envelope = AuditEnvelope::from_canonical_cbor(bytes)?;
            if format!("0x{}", hex::encode(envelope.envelope_hash()?)) != hash.to_ascii_lowercase()
            {
                return Err(AuditError::Invalid("audit envelope hash mismatch".into()));
            }
        }
        Ok(bytes)
    }
}
fn valid_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_credential_cannot_be_sent_to_a_remote_or_credentialed_endpoint() {
        let credential = format!("{:064x}", 7);
        let mut client = AuditClient::with_bearer("http://127.0.0.1:12345", credential.clone());
        client.service_credential = true;
        let request = client
            .request(reqwest::Method::GET, "/v1/audit/envelopes")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request.headers()["authorization"],
            format!("Bearer {credential}")
        );
        for endpoint in [
            "https://archive.example",
            "http://user:password@127.0.0.1:12345",
            "http://192.0.2.1",
        ] {
            client.base_url = endpoint.into();
            assert!(client
                .request(reqwest::Method::GET, "/v1/audit/envelopes")
                .is_err());
        }
    }
}
