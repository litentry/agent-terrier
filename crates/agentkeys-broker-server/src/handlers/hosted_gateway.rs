use agentkeys_protocol::{
    hosted_gateway::{HostedGatewayRequest, GATEWAY_CONSOLE_ROUTE},
    GatewayDeviceStatus,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::time::Duration;

use crate::{
    handlers::{
        accept::{aerr, bearer, eth_call, norm_omni, selector},
        revoke::parse_device_probe,
    },
    state::SharedState,
};

type GatewayError = (StatusCode, Json<serde_json::Value>);
const GATEWAY_TIMEOUT_SECS: u64 = 60;
const GATEWAY_DEVICE_TIER: u8 = 3;

#[derive(Debug, Clone)]
pub struct HostedGatewayConfig {
    pub gateway_url: String,
    pub chain_rpc_http: String,
    pub registry: [u8; 20],
}

impl HostedGatewayConfig {
    pub fn from_lookup(
        issuer: &str,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        let gateway_url = lookup("AGENTKEYS_WORKER_WEIXIN_URL")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| agentkeys_protocol::derive_worker_url(issuer, "weixin"))
            .ok_or("gateway_not_configured")?;
        if !agentkeys_protocol::worker_override_matches_broker(&gateway_url, issuer) {
            return Err("gateway_url_outside_broker_zone".into());
        }
        let chain_rpc_http = lookup("AGENTKEYS_CHAIN_RPC_HTTP")
            .filter(|value| !value.trim().is_empty())
            .ok_or("gateway_chain_not_configured")?;
        let profile = lookup("AGENTKEYS_CHAIN")
            .unwrap_or_else(|| agentkeys_core::chain_profile::DEFAULT_PROFILE.into())
            .to_uppercase()
            .replace('-', "_");
        let registry_name = format!("SIDECAR_REGISTRY_ADDRESS_{profile}");
        let registry = lookup(&registry_name).ok_or("gateway_registry_not_configured")?;
        let registry = hex::decode(registry.trim_start_matches("0x"))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or("gateway_registry_invalid")?;
        Ok(Self {
            gateway_url,
            chain_rpc_http,
            registry,
        })
    }
}

fn authenticate_master(
    keypair: &crate::jwt::SessionKeypair,
    issuer: &str,
    headers: &HeaderMap,
) -> Result<(String, String), GatewayError> {
    let token = bearer(headers)?;
    let claims = crate::jwt::verify::verify_session_jwt(keypair, issuer, &token)
        .map_err(|_| aerr(StatusCode::UNAUTHORIZED, "master_session_invalid"))?;
    let identity = claims.agentkeys;
    if identity.parent_omni.is_some()
        || identity.device_pubkey.is_some()
        || !matches!(identity.identity_type.as_str(), "evm" | "passkey")
    {
        return Err(aerr(StatusCode::FORBIDDEN, "master_session_required"));
    }
    let operator_omni = norm_omni(&identity.omni_account);
    if hex::decode(&operator_omni).map(|bytes| bytes.len()).ok() != Some(32) {
        return Err(aerr(StatusCode::UNAUTHORIZED, "master_session_invalid"));
    }
    Ok((token, operator_omni))
}

async fn gate_request(
    http: &reqwest::Client,
    config: &HostedGatewayConfig,
    token: &str,
    request: &HostedGatewayRequest,
) -> Result<reqwest::Response, GatewayError> {
    http.post(format!(
        "{}{GATEWAY_CONSOLE_ROUTE}",
        config.gateway_url.trim_end_matches('/')
    ))
    .bearer_auth(token)
    .json(request)
    .timeout(Duration::from_secs(GATEWAY_TIMEOUT_SECS))
    .send()
    .await
    .map_err(|_| aerr(StatusCode::BAD_GATEWAY, "contact_gate_unreachable"))
}

pub async fn gateway(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<HostedGatewayRequest>,
) -> Result<Response, GatewayError> {
    let (token, operator_omni) =
        authenticate_master(&state.session_keypair, &state.config.oidc_issuer, &headers)?;
    state
        .config
        .login_access
        .require_omni(&state, &operator_omni)
        .await
        .map_err(|_| aerr(StatusCode::FORBIDDEN, "master_login_not_approved"))?;
    let config = HostedGatewayConfig::from_lookup(&state.config.oidc_issuer, &|name| {
        std::env::var(name).ok()
    })
    .map_err(|reason| aerr(StatusCode::SERVICE_UNAVAILABLE, reason))?;
    forward(&state.http, &config, &token, &operator_omni, &request).await
}

async fn forward(
    http: &reqwest::Client,
    config: &HostedGatewayConfig,
    token: &str,
    operator_omni: &str,
    request: &HostedGatewayRequest,
) -> Result<Response, GatewayError> {
    let identity = gate_request(http, config, token, &HostedGatewayRequest::DeviceStatus).await?;
    if !identity.status().is_success() {
        return relay_response(identity).await;
    }
    let identity: GatewayDeviceStatus = identity
        .json()
        .await
        .map_err(|_| aerr(StatusCode::BAD_GATEWAY, "gateway_identity_invalid"))?;
    let actor = identity
        .actor_omni
        .as_deref()
        .ok_or_else(|| aerr(StatusCode::CONFLICT, "gateway_not_enrolled"))?;
    let device_key_hash = identity
        .device_key_hash
        .as_deref()
        .ok_or_else(|| aerr(StatusCode::CONFLICT, "gateway_not_enrolled"))?;
    let hash = hex::decode(norm_omni(device_key_hash))
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| aerr(StatusCode::BAD_GATEWAY, "gateway_identity_invalid"))?;
    let data = format!("0x{}{}", selector("getDevice(bytes32)"), hex::encode(hash));
    let raw = eth_call(http, &config.chain_rpc_http, &config.registry, &data)
        .await
        .map_err(|_| aerr(StatusCode::BAD_GATEWAY, "gateway_chain_verification_failed"))?;
    let binding = parse_device_probe(&raw)
        .map_err(|_| aerr(StatusCode::BAD_GATEWAY, "gateway_chain_verification_failed"))?;
    if !binding.is_registered()
        || binding.revoked
        || binding.tier != GATEWAY_DEVICE_TIER
        || hex::encode(binding.actor_omni) != norm_omni(actor)
    {
        return Err(aerr(StatusCode::FORBIDDEN, "gateway_binding_inactive"));
    }
    if hex::encode(binding.operator_omni) != norm_omni(operator_omni) {
        return Err(aerr(StatusCode::FORBIDDEN, "gateway_operator_mismatch"));
    }
    relay_response(gate_request(http, config, token, request).await?).await
}

async fn relay_response(response: reqwest::Response) -> Result<Response, GatewayError> {
    let status = StatusCode::from_u16(response.status().as_u16())
        .map_err(|_| aerr(StatusCode::BAD_GATEWAY, "contact_gate_response_invalid"))?;
    let body = response
        .bytes()
        .await
        .map_err(|_| aerr(StatusCode::BAD_GATEWAY, "contact_gate_response_invalid"))?;
    Ok((
        status,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_config_uses_the_shared_worker_derivation_and_explicit_chain() {
        let values = std::collections::HashMap::from([
            ("AGENTKEYS_CHAIN_RPC_HTTP", "https://rpc.example.test"),
            ("AGENTKEYS_CHAIN", "heima"),
            (
                "SIDECAR_REGISTRY_ADDRESS_HEIMA",
                "0x1111111111111111111111111111111111111111",
            ),
        ]);
        let config =
            HostedGatewayConfig::from_lookup("https://test-broker.example.test", &|name| {
                values.get(name).map(|value| value.to_string())
            })
            .unwrap();
        assert_eq!(config.gateway_url, "https://weixin-test.example.test");
        assert!(
            HostedGatewayConfig::from_lookup("https://broker.example.test", &|_| None).is_err()
        );
    }
    #[test]
    fn only_a_verified_master_jwt_authenticates_the_gateway_relay() {
        use crate::jwt::issue::{mint_agent_session_jwt, mint_session_jwt};
        let directory = tempfile::tempdir().unwrap();
        let keypair = crate::jwt::SessionKeypair::generate_and_persist(
            &directory.path().join("session.json"),
        )
        .unwrap();
        let issuer = "https://broker.example.test";
        let owner = format!("0x{}", "ab".repeat(32));
        let master =
            mint_session_jwt(&keypair, issuer, &owner, "wallet", "evm", "wallet", 300).unwrap();
        let email = mint_session_jwt(
            &keypair,
            issuer,
            &owner,
            "",
            "email",
            "allowed@example.test",
            300,
        )
        .unwrap();
        let device =
            mint_agent_session_jwt(&keypair, issuer, &owner, &owner, "//device", "device", 300)
                .unwrap();
        for (token, expected) in [
            (master, true),
            (email, false),
            (device, false),
            ("forged".into(), false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
            assert_eq!(
                authenticate_master(&keypair, issuer, &headers).is_ok(),
                expected
            );
        }
        assert!(authenticate_master(&keypair, issuer, &HeaderMap::new()).is_err());
    }

    #[derive(Clone)]
    struct UpstreamFixture {
        owner: String,
        registered: bool,
        revoked: bool,
        enrolled: bool,
        tier: u8,
        dispatched: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn fixture_gateway(
        State(fixture): State<UpstreamFixture>,
        headers: HeaderMap,
        Json(request): Json<HostedGatewayRequest>,
    ) -> Json<serde_json::Value> {
        assert_eq!(headers["authorization"], "Bearer request-scoped-session");
        if matches!(request, HostedGatewayRequest::DeviceStatus) {
            Json(
                serde_json::to_value(GatewayDeviceStatus {
                    ok: true,
                    enrolled: fixture.enrolled,
                    actor_omni: fixture.enrolled.then(|| format!("0x{}", "11".repeat(32))),
                    device_key_hash: fixture.enrolled.then(|| format!("0x{}", "22".repeat(32))),
                    ..Default::default()
                })
                .unwrap(),
            )
        } else {
            fixture
                .dispatched
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Json(serde_json::json!({"ok":true,"marker":"owner-registry"}))
        }
    }

    async fn fixture_chain(
        State(fixture): State<UpstreamFixture>,
        Json(request): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        assert_eq!(request["method"], "eth_call");
        assert!(request["params"][0]["data"]
            .as_str()
            .unwrap()
            .ends_with(&"22".repeat(32)));
        let mut words: [String; 11] = std::array::from_fn(|_| "00".repeat(32));
        words[0] = fixture.owner;
        words[1] = "11".repeat(32);
        words[6] = format!("{:064x}", fixture.tier);
        words[8] = format!("{:064x}", u8::from(fixture.registered));
        words[10] = format!("{:064x}", u8::from(fixture.revoked));
        Json(
            serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "result":format!("0x{}", words.join(""))}),
        )
    }

    #[tokio::test]
    async fn broker_rechecks_chain_owner_before_forwarding_every_management_operation() {
        use axum::{routing::post, Router};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        for (owner, registered, revoked, enrolled, tier, expected) in [
            ("ab", true, false, true, 3, StatusCode::OK),
            ("cd", true, false, true, 3, StatusCode::FORBIDDEN),
            ("ab", false, false, true, 3, StatusCode::FORBIDDEN),
            ("ab", true, true, true, 3, StatusCode::FORBIDDEN),
            ("ab", true, false, false, 3, StatusCode::CONFLICT),
            ("ab", true, false, true, 1, StatusCode::FORBIDDEN),
        ] {
            let dispatched = Arc::new(AtomicUsize::new(0));
            let fixture = UpstreamFixture {
                owner: owner.repeat(32),
                registered,
                revoked,
                enrolled,
                tier,
                dispatched: dispatched.clone(),
            };
            let router = Router::new()
                .route(GATEWAY_CONSOLE_ROUTE, post(fixture_gateway))
                .route("/rpc", post(fixture_chain))
                .with_state(fixture);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            let config = HostedGatewayConfig {
                gateway_url: base.clone(),
                chain_rpc_http: format!("{base}/rpc"),
                registry: [0x33; 20],
            };
            for request in [
                HostedGatewayRequest::Status,
                HostedGatewayRequest::RegistryExport,
                HostedGatewayRequest::ContactsRevoke(
                    agentkeys_protocol::GatewayContactRevokeRequest {
                        contact_id: "contact".into(),
                    },
                ),
            ] {
                let response = forward(
                    &reqwest::Client::new(),
                    &config,
                    "request-scoped-session",
                    &"ab".repeat(32),
                    &request,
                )
                .await;
                let actual = match response {
                    Ok(response) => response.status(),
                    Err((status, _)) => status,
                };
                assert_eq!(actual, expected);
            }
            assert_eq!(
                dispatched.load(Ordering::SeqCst),
                if expected == StatusCode::OK { 3 } else { 0 }
            );
            server.abort();
        }
    }
}
