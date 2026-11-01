//! Broker client for provisioning and disabling per-delegate model relay credentials.

use agentkeys_core::{models, protected_file};
pub use agentkeys_protocol::model_relay::ProvisionedKey;
use agentkeys_protocol::model_relay::{DisableKeyResponse, ProvisionKeyRequest};

pub struct GateAdminConfig {
    pub admin_url: String,
    pub admin_token: String,
    pub turn_url: String,
    pub model_id: String,
    pub delegate_budget_tokens: Option<u64>,
}

pub fn load_gate_admin_config() -> Option<Result<GateAdminConfig, String>> {
    GateAdminConfig::from_lookup(|name| std::env::var(name).ok())
}

impl GateAdminConfig {
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Option<Result<Self, String>> {
        let admin_url = lookup("AGENTKEYS_GATE_ADMIN_URL");
        let inline_token = lookup("AGENTKEYS_GATE_ADMIN_TOKEN");
        let token_file = lookup("AGENTKEYS_GATE_ADMIN_TOKEN_FILE");
        let turn_url = lookup("AGENTKEYS_GATE_TURN_URL");
        let model_id = lookup("AGENTKEYS_GATE_DEFAULT_MODEL");
        let budget = lookup("AGENTKEYS_GATE_DELEGATE_BUDGET_TOKENS");
        if [
            &admin_url,
            &inline_token,
            &token_file,
            &turn_url,
            &model_id,
            &budget,
        ]
        .iter()
        .all(|value| value.is_none())
        {
            return None;
        }
        Some((|| {
            let admin_url = admin_url.ok_or("model relay admin URL is required")?;
            let turn_url = turn_url.ok_or("model relay turn URL is required")?;
            agentkeys_protocol::model_config::base_url(&admin_url)?;
            agentkeys_protocol::model_config::base_url(&turn_url)?;
            let admin_token = match (inline_token, token_file) {
                (Some(token), None) => token,
                (None, Some(path)) => protected_file::read_token(std::path::Path::new(&path))
                    .map_err(|_| "model relay admin credential file is missing or unsafe")?
                    .to_string(),
                _ => return Err("choose exactly one model relay admin credential source".into()),
            };
            if admin_token.is_empty()
                || admin_token
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            {
                return Err("model relay admin credential must be one nonempty token".into());
            }
            let model_id = model_id.unwrap_or_else(|| models::default_chat_model().to_owned());
            if model_id.trim().is_empty() || model_id.bytes().any(|byte| byte.is_ascii_control()) {
                return Err("model relay identifier is empty or invalid".into());
            }
            let delegate_budget_tokens = budget
                .map(|value| {
                    value.parse::<u64>().map_err(|_| {
                        "model relay delegate budget must be an unsigned integer".to_owned()
                    })
                })
                .transpose()?;
            Ok(Self {
                admin_url: admin_url.trim_end_matches('/').to_owned(),
                admin_token,
                turn_url: turn_url.trim_end_matches('/').to_owned(),
                model_id,
                delegate_budget_tokens,
            })
        })())
    }
}

/// Provision a per-delegate relay key at spawn. Idempotent on the gate side
/// (re-provisioning an existing enabled `key_id` rotates its secret).
pub async fn provision_delegate(
    http: &reqwest::Client,
    cfg: &GateAdminConfig,
    operator_omni: &str,
    delegate_omni: &str,
    device_key_hash: &str,
    label: &str,
) -> Result<ProvisionedKey, String> {
    let body = ProvisionKeyRequest {
        key_id: device_key_hash.into(),
        user_omni: operator_omni.into(),
        delegate_omni: Some(delegate_omni.into()),
        device_id: device_key_hash.into(),
        label: label.into(),
        budget_tokens: cfg.delegate_budget_tokens,
    };
    let resp = http
        .post(format!("{}/v1/admin/keys", cfg.admin_url))
        .bearer_auth(&cfg.admin_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("gate provision send: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("gate provision refused with {status}"));
    }
    resp.json::<ProvisionedKey>()
        .await
        .map_err(|e| format!("gate provision decode: {e}"))
}

/// Disable a delegate's relay key at archive (turns stop; usage history and
/// the key row remain for rollups). Idempotent — disabling a disabled or
/// unknown key returns Ok(false).
pub async fn deprovision_delegate(
    http: &reqwest::Client,
    cfg: &GateAdminConfig,
    device_key_hash: &str,
) -> Result<bool, String> {
    let resp = http
        .post(format!(
            "{}/v1/admin/keys/{}/disable",
            cfg.admin_url, device_key_hash
        ))
        .bearer_auth(&cfg.admin_token)
        .send()
        .await
        .map_err(|e| format!("gate deprovision send: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("gate deprovision refused with {status}"));
    }
    let response = resp
        .json::<DisableKeyResponse>()
        .await
        .map_err(|e| format!("gate deprovision decode: {e}"))?;
    if !response.key_id.eq_ignore_ascii_case(device_key_hash) {
        return Err("model relay returned a different key identity".into());
    }
    Ok(response.disabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[tokio::test]
    async fn relay_revocation_requires_matching_success_and_recovers_after_failure() {
        use axum::{
            http::{HeaderMap, StatusCode},
            routing::post,
            Json, Router,
        };
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let stage = Arc::new(AtomicUsize::new(0));
        let handler_stage = stage.clone();
        let router = Router::new().route(
            "/v1/admin/keys/fixture/disable",
            post(move |headers: HeaderMap| {
                let stage = handler_stage.clone();
                async move {
                    assert_eq!(headers["authorization"], "Bearer synthetic-admin");
                    match stage.load(Ordering::SeqCst) {
                        0 => (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(serde_json::json!({"error":"synthetic-private-body"})),
                        ),
                        1 => (
                            StatusCode::OK,
                            Json(serde_json::json!({"key_id":"another-key","disabled":true})),
                        ),
                        2 => (
                            StatusCode::OK,
                            Json(serde_json::json!({"key_id":"fixture","disabled":true})),
                        ),
                        _ => (
                            StatusCode::OK,
                            Json(serde_json::json!({"key_id":"fixture","disabled":false})),
                        ),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let configuration = GateAdminConfig {
            admin_url: endpoint.clone(),
            admin_token: "synthetic-admin".into(),
            turn_url: endpoint,
            model_id: models::default_chat_model().into(),
            delegate_budget_tokens: None,
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for step in [0, 1] {
            stage.store(step, Ordering::SeqCst);
            let error = deprovision_delegate(&client, &configuration, "fixture")
                .await
                .unwrap_err();
            assert!(
                !error.contains("synthetic-private-body") && !error.contains("synthetic-admin")
            );
        }
        stage.store(2, Ordering::SeqCst);
        assert!(deprovision_delegate(&client, &configuration, "fixture")
            .await
            .unwrap());
        stage.store(3, Ordering::SeqCst);
        assert!(!deprovision_delegate(&client, &configuration, "fixture")
            .await
            .unwrap());
        server.abort();
    }

    #[test]
    fn protected_admin_source_is_explicit_and_partial_configuration_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.key");
        protected_file::write(path.to_str().unwrap(), b"synthetic-admin-token\n", true).unwrap();
        let values = BTreeMap::from([
            (
                "AGENTKEYS_GATE_ADMIN_URL",
                "http://127.0.0.1:8077".to_owned(),
            ),
            (
                "AGENTKEYS_GATE_TURN_URL",
                "http://127.0.0.1:8077/v1/".to_owned(),
            ),
            (
                "AGENTKEYS_GATE_ADMIN_TOKEN_FILE",
                path.to_str().unwrap().to_owned(),
            ),
        ]);
        let load = |values: &BTreeMap<&str, String>| {
            GateAdminConfig::from_lookup(|name| values.get(name).cloned())
        };
        assert!(load(&BTreeMap::new()).is_none());
        let configuration = load(&values).unwrap().unwrap();
        assert_eq!(configuration.admin_token, "synthetic-admin-token");
        assert_eq!(configuration.turn_url, "http://127.0.0.1:8077/v1");
        assert_eq!(configuration.model_id, models::default_chat_model());
        for name in values.keys() {
            let mut partial = values.clone();
            partial.remove(name);
            assert!(load(&partial).unwrap().is_err());
        }
        for (name, value) in [
            ("AGENTKEYS_GATE_ADMIN_TOKEN", "synthetic-admin-token"),
            (
                "AGENTKEYS_GATE_ADMIN_URL",
                "http://synthetic-admin-token@localhost",
            ),
            (
                "AGENTKEYS_GATE_TURN_URL",
                "http://localhost?key=synthetic-admin-token",
            ),
            ("AGENTKEYS_GATE_DEFAULT_MODEL", ""),
            ("AGENTKEYS_GATE_DELEGATE_BUDGET_TOKENS", "invalid"),
        ] {
            let mut invalid = values.clone();
            invalid.insert(name, value.into());
            let error = load(&invalid)
                .unwrap()
                .err()
                .expect("invalid configuration must fail");
            assert!(!error.contains("synthetic-admin-token"));
        }
        let alias = directory.path().join("linked");
        symlink(&path, &alias).unwrap();
        let mut linked = values.clone();
        linked.insert(
            "AGENTKEYS_GATE_ADMIN_TOKEN_FILE",
            alias.to_str().unwrap().into(),
        );
        assert!(load(&linked).unwrap().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&values).unwrap().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic-admin-token\n");
    }
}
