use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Endpoint {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Endpoint {
    async fn start(router: axum::Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, task }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn bridge_state(broker: Option<String>, direct: Option<String>) -> SharedUiBridgeState {
    build_state(
        "localhost",
        "http://localhost:3113",
        "Agent Terrier Test",
        broker,
        None,
        84532,
        None,
        None,
        None,
        None,
        direct,
        Some("synthetic-bridge-proof".into()),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap()
}

async fn owner_session(state: &SharedUiBridgeState) {
    *state.onboarding_session.write().await = Some(OnboardingSession {
        email: "owner@example.com".into(),
        omni: "0xbb".into(),
        j1: "synthetic-owner-session".into(),
        wallet: String::new(),
        identity_only_reason: None,
    });
}

async fn delegate_binding(state: &SharedUiBridgeState, device_key_hash: &str) {
    let mut manifest = BindingManifest::default();
    manifest.upsert(BindingManifestEntry {
        actor_omni: "0xaa".into(),
        device_key_hash: device_key_hash.into(),
        ..Default::default()
    });
    *state.binding_manifest.write().await = Some(manifest);
}

#[tokio::test]
async fn managed_bridge_never_falls_back_to_a_direct_endpoint() {
    let requests = Arc::new(AtomicUsize::new(0));
    let observed_requests = requests.clone();
    let endpoint = Endpoint::start(axum::Router::new().fallback(move || {
        let observed_requests = observed_requests.clone();
        async move {
            observed_requests.fetch_add(1, Ordering::SeqCst);
            Json(serde_json::json!({"phase": "ready"}))
        }
    }))
    .await;
    let mut state = bridge_state(None, Some(endpoint.url.clone()));
    let request = |state: SharedUiBridgeState, delegate: Option<&'static str>| {
        let direct_url = endpoint.url.clone();
        async move {
            sandbox_bridge_exchange_instanced(
                &state,
                reqwest::Method::POST,
                "/v1/context/apply",
                Some(serde_json::json!({"files": {}})),
                Some("owned-instance"),
                Some(&direct_url),
                delegate,
            )
            .await
        }
    };
    assert_eq!(
        request(state.clone(), Some("0xaa")).await.unwrap_err(),
        "sandbox_unconfigured: broker is required for managed requests"
    );
    Arc::get_mut(&mut state).unwrap().broker_url = Some(endpoint.url.clone());
    assert_eq!(
        request(state.clone(), None).await.unwrap_err(),
        "sandbox_delegate_missing"
    );
    assert_eq!(
        request(state.clone(), Some("0xaa")).await.unwrap_err(),
        "sandbox_owner_session_required"
    );
    owner_session(&state).await;
    assert_eq!(
        request(state.clone(), Some("0xaa")).await.unwrap_err(),
        "sandbox_delegate_unbound"
    );
    delegate_binding(&state, "").await;
    assert_eq!(
        request(state.clone(), Some("0xaa")).await.unwrap_err(),
        "sandbox_device_binding_missing"
    );
    delegate_binding(&state, "0xdd").await;
    Arc::get_mut(&mut state).unwrap().config_url = Some(endpoint.url.clone());
    assert_eq!(
        request(state.clone(), Some("0xaa")).await.unwrap_err(),
        "sandbox_binding_unavailable"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 0);

    Arc::get_mut(&mut state).unwrap().config_url = None;
    let (_, status, _) = sandbox_bridge_exchange_instanced(
        &state,
        reqwest::Method::GET,
        "/healthz",
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(
        status.is_success(),
        "the explicit standalone endpoint remains usable"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn managed_bridge_uses_shared_broker_route_and_preserves_refusals() {
    let direct_requests = Arc::new(AtomicUsize::new(0));
    let direct_count = direct_requests.clone();
    let direct = Endpoint::start(axum::Router::new().fallback(move || {
        let direct_count = direct_count.clone();
        async move {
            direct_count.fetch_add(1, Ordering::SeqCst);
            Json(serde_json::json!({"phase": "unexpected-direct"}))
        }
    }))
    .await;
    let observations = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let observed = observations.clone();
    let response_mode = Arc::new(AtomicUsize::new(0));
    let mode = response_mode.clone();
    let redirect_url = direct.url.clone();
    let broker = Endpoint::start(axum::Router::new().route(
        "/v1/agent/bridge",
        axum::routing::post(
            move |headers: axum::http::HeaderMap,
                  Json(body): Json<agentkeys_protocol::BridgeProxyBody>| {
                let observed = observed.clone();
                let mode = mode.clone();
                let redirect_url = redirect_url.clone();
                async move {
                    assert_eq!(
                        headers.get(axum::http::header::AUTHORIZATION).unwrap(),
                        "Bearer synthetic-owner-session"
                    );
                    observed.lock().await.push(body);
                    match mode.load(Ordering::SeqCst) {
                        1 => (
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({"error": "not_owned"})),
                        )
                            .into_response(),
                        2 => (
                            StatusCode::TEMPORARY_REDIRECT,
                            [(axum::http::header::LOCATION, redirect_url)],
                            Json(serde_json::json!({"error": "redirect_refused"})),
                        )
                            .into_response(),
                        _ => (
                            StatusCode::OK,
                            Json(serde_json::json!({"phase": "ready", "restarted": true})),
                        )
                            .into_response(),
                    }
                }
            },
        ),
    ))
    .await;
    let state = bridge_state(Some(broker.url.clone()), Some(direct.url.clone()));
    owner_session(&state).await;
    delegate_binding(&state, "0xdd").await;
    for (response, expected_status) in [(0, 200), (1, 403), (2, 307)] {
        response_mode.store(response, Ordering::SeqCst);
        let (_, status, _) = sandbox_bridge_exchange_instanced(
            &state,
            reqwest::Method::POST,
            "/v1/context/apply",
            Some(serde_json::json!({"files": {}})),
            Some("owned-instance"),
            Some(&direct.url),
            Some("0xaa"),
        )
        .await
        .unwrap();
        assert_eq!(status.as_u16(), expected_status);
    }
    response_mode.store(0, Ordering::SeqCst);
    sandbox_bridge_reachable(&state, None, Some(&direct.url), Some("0xaa"))
        .await
        .unwrap();
    let mut observations = observations.lock().await;
    assert_eq!(observations.len(), 4);
    let health = observations.pop().unwrap();
    assert!(health.sandbox_id.is_none());
    assert_eq!(health.method.as_deref(), Some("GET"));
    assert_eq!(health.path, "/healthz");
    for body in observations.iter() {
        assert_eq!(body.operator_omni, "0xbb");
        assert_eq!(body.device_key_hash, "0xdd");
        assert_eq!(body.sandbox_id.as_deref(), Some("owned-instance"));
        assert_eq!(body.method.as_deref(), Some("POST"));
        assert_eq!(body.path, "/v1/context/apply");
        assert_eq!(body.body, Some(serde_json::json!({"files": {}})));
    }
    drop(observations);
    assert_eq!(direct_requests.load(Ordering::SeqCst), 0);

    let mut state = state;
    Arc::get_mut(&mut state).unwrap().sandbox_bridge_url = None;
    let (applied, _) = apply_persona_to_sandbox(&state, "0xaa", "test persona", None, None).await;
    assert!(
        applied,
        "managed persona application needs no direct bridge URL"
    );
    assert_eq!(direct_requests.load(Ordering::SeqCst), 0);
}
