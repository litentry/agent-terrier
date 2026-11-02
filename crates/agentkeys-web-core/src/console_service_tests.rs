use super::*;
use crate::console::ConsoleService;
use agentkeys_protocol::{console::*, console_chain::*, *};
use axum::routing::get;

const DELEGATE: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const DELEGATE_DEVICE: &str = "dededededededededededededededededededededededededededededededede";
const FOREIGN_ACTOR: &str = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

struct ConsoleFixture {
    fleet: ConsoleFleet,
    builds: Vec<BuildScopeUserOpRequest>,
    submissions: usize,
    receipt_polls: usize,
    bridges: Vec<BridgeProxyBody>,
    bridge_receipt: Value,
    replace_confirmed_device: bool,
}
type SharedConsole = Arc<Mutex<ConsoleFixture>>;

fn hash(service: &str) -> String {
    format!(
        "0x{}",
        hex::encode(agentkeys_device_core::keccak256(service.as_bytes()))
    )
}
fn session(device: &DeviceIdentity) -> DataSession<'_> {
    DataSession {
        bearer: "test-session",
        operator_omni: "ab",
        actor_omni: "ab",
        device,
        now_unix_seconds: 1234,
    }
}
fn device_entry(actor: &str, device: &str, tier: u8) -> ConsoleFleetEntry {
    ConsoleFleetEntry {
        device: ConsoleChainDevice {
            device_key_hash: device.into(),
            operator_omni: "0xab".into(),
            actor_omni: actor.into(),
            tier,
            revoked: false,
        },
        scope: ConsoleChainScope {
            service_ids: vec![
                hash("knowledge:old"),
                hash("tool:web"),
                hash("cred:private"),
            ],
            read_only: false,
            exists: true,
            per_tx: "12345678901234567890".into(),
            period_cap: "22345678901234567890".into(),
            max_total: "32345678901234567890".into(),
            period_seconds: 86400,
        },
    }
}
fn operation() -> WireUserOp {
    WireUserOp {
        sender: format!("0x{}", "12".repeat(20)),
        nonce: "0x1".into(),
        init_code: "0x".into(),
        call_data: "0x1234".into(),
        account_gas_limits: "0x01".into(),
        pre_verification_gas: "0x02".into(),
        gas_fees: "0x03".into(),
        paymaster_and_data: "0x".into(),
        signature: "0x".into(),
    }
}
fn submit_body(operation: WireUserOp) -> Value {
    serde_json::to_value(SubmitAcceptUserOpRequest {
        user_op: operation,
        assertion: AcceptAssertion {
            authenticator_data: "assertion-data".into(),
            client_data_json: "assertion-client".into(),
            signature: "assertion-signature".into(),
            credential_id: "assertion-id".into(),
        },
    })
    .unwrap()
}
fn receipt(pending: bool) -> SubmitAcceptUserOpResponse {
    SubmitAcceptUserOpResponse {
        ok: true,
        tx_hash: if pending {
            String::new()
        } else {
            "0xconfirmed".into()
        },
        block_number: if pending {
            String::new()
        } else {
            "0x42".into()
        },
        user_op_hash: "0xoperation".into(),
        audit_envelope_hashes: None,
        pending: pending.then_some(true),
        ceremony: None,
    }
}
async fn fleet(State(state): State<SharedConsole>, headers: HeaderMap) -> Json<ConsoleFleet> {
    bearer(&headers);
    Json(state.lock().unwrap().fleet.clone())
}
async fn scope_build(
    State(state): State<SharedConsole>,
    headers: HeaderMap,
    Json(body): Json<BuildScopeUserOpRequest>,
) -> Json<BuildAcceptUserOpResponse> {
    bearer(&headers);
    state.lock().unwrap().builds.push(body);
    Json(BuildAcceptUserOpResponse {
        user_op: operation(),
        user_op_hash: "0xoperation".into(),
        entry_point: "0xentry".into(),
        chain_id: 1,
    })
}
async fn scope_submit(
    State(state): State<SharedConsole>,
    headers: HeaderMap,
    Json(body): Json<SubmitAcceptUserOpRequest>,
) -> Json<SubmitAcceptUserOpResponse> {
    bearer(&headers);
    assert_eq!(body.assertion.credential_id, "assertion-id");
    state.lock().unwrap().submissions += 1;
    Json(receipt(true))
}
async fn poll_receipt(
    State(state): State<SharedConsole>,
    headers: HeaderMap,
    Json(body): Json<console_apps::AcceptReceiptRequest>,
) -> Json<SubmitAcceptUserOpResponse> {
    bearer(&headers);
    assert_eq!(body.user_op.call_data, operation().call_data);
    let mut state = state.lock().unwrap();
    state.receipt_polls += 1;
    let build = state.builds.last().unwrap();
    let mut services = build
        .services
        .iter()
        .map(|name| hash(name))
        .collect::<Vec<_>>();
    services.extend(build.preserve_service_ids.clone());
    let replace_device = state.replace_confirmed_device;
    let target = state
        .fleet
        .devices
        .iter_mut()
        .find(|entry| entry.device.actor_omni == DELEGATE)
        .unwrap();
    target.scope.service_ids = services;
    if replace_device {
        target.device.device_key_hash = "replacement-device".into();
    }
    Json(receipt(false))
}
async fn bridge_request(
    State(state): State<SharedConsole>,
    headers: HeaderMap,
    Json(body): Json<BridgeProxyBody>,
) -> Json<Value> {
    bearer(&headers);
    assert_eq!(body.operator_omni, "ab");
    assert_eq!(body.device_key_hash, DELEGATE_DEVICE);
    let mut state = state.lock().unwrap();
    state.bridges.push(body);
    Json(state.bridge_receipt.clone())
}
async fn console_setup() -> (
    ConsoleService,
    SharedFixture,
    SharedConsole,
    tokio::task::JoinHandle<()>,
) {
    let mut revoked = device_entry(FOREIGN_ACTOR, "revoked-device", 2);
    revoked.device.revoked = true;
    let console = Arc::new(Mutex::new(ConsoleFixture {
        fleet: ConsoleFleet {
            operator_omni: "0xab".into(),
            account: format!("0x{}", "12".repeat(20)),
            devices: vec![
                device_entry("ab", "master-device", 1),
                device_entry(DELEGATE, DELEGATE_DEVICE, 2),
                revoked,
            ],
        },
        builds: Vec::new(),
        submissions: 0,
        receipt_polls: 0,
        bridges: Vec::new(),
        bridge_receipt: json!({"ok":true,"files_written":["SOUL.md"]}),
        replace_confirmed_device: false,
    }));
    let routes = Router::new()
        .route("/v1/console/fleet", get(fleet))
        .route("/v1/scope/build", post(scope_build))
        .route("/v1/scope/submit", post(scope_submit))
        .route("/v1/accept/receipt", post(poll_receipt))
        .route("/v1/agent/bridge", post(bridge_request))
        .with_state(console.clone());
    let (data, storage, task) = setup_with_routes(routes).await;
    let endpoint = data.endpoints.broker_url.clone();
    let config = ConsoleConfig {
        chain: ConsoleChainInfo {
            name: "fixture".into(),
            display: "Fixture".into(),
            chain_id: 1,
            rpc: String::new(),
            wss: String::new(),
            explorer: String::new(),
            token_symbol: "TEST".into(),
            token_decimals: 18,
            finality: "fixture".into(),
            contracts: vec![],
            daemon_chain: "fixture".into(),
            daemon_broker: endpoint.clone(),
        },
        signer_url: endpoint.clone(),
        config_url: endpoint.clone(),
        memory_url: endpoint.clone(),
        credential_url: endpoint.clone(),
        audit_url: Some(endpoint.clone()),
        channel_url: endpoint.clone(),
        classify_url: endpoint.clone(),
    };
    (
        ConsoleService::new(endpoint, config),
        storage,
        console,
        task,
    )
}
async fn save_manifest(
    service: &ConsoleService,
    session: &DataSession<'_>,
    label: &str,
    preset: &str,
) {
    let (_, revision) = service
        .read_config::<BindingManifest>(session, BINDING_MANIFEST_SERVICE)
        .await
        .unwrap();
    let mut manifest = BindingManifest::default();
    manifest.upsert(BindingManifestEntry {
        actor_omni: DELEGATE.into(),
        device_key_hash: DELEGATE_DEVICE.into(),
        label: label.into(),
        kind: "delegate".into(),
        preset_id: Some(preset.into()),
        granted_service_names: vec!["knowledge:old".into(), "tool:web".into()],
        ..Default::default()
    });
    service
        .data
        .config_put(
            session,
            BINDING_MANIFEST_SERVICE,
            &serde_json::to_vec(&manifest).unwrap(),
            &revision,
        )
        .await
        .unwrap();
}
fn scope_body(actor: &str) -> Value {
    json!({"actor_omni":actor,"services":["knowledge:recipes"],"preserve_service_ids":[hash("tool:web"),hash("cred:private")],"read_only":true})
}

#[tokio::test]
async fn actors_and_scope_resume_preserve_limits_grants_and_concurrent_metadata() {
    let (service, storage, console, task) = console_setup().await;
    let device = DeviceIdentity::from_random_bytes(&[31; 32]).unwrap();
    let session = session(&device);
    save_manifest(&service, &session, "Kitchen", "initial-preset").await;
    let response = service
        .request(&session, None, "GET", "/v1/actors", Value::Null)
        .await
        .unwrap();
    let actors: Vec<ApiActor> = serde_json::from_value(response["actors"].clone()).unwrap();
    assert_eq!(actors.len(), 2);
    assert_eq!(actors[0].id, "master");
    assert_eq!(actors[1].omni_hex, DELEGATE);
    assert_eq!(actors[1].label, "Kitchen");
    assert!(actors[1]
        .scope_unknown_service_ids
        .as_ref()
        .unwrap()
        .contains(&hash("cred:private")));
    let build: BuildAcceptUserOpResponse = serde_json::from_value(
        service
            .request(
                &session,
                None,
                "POST",
                "/v1/scope/build",
                scope_body(DELEGATE),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    {
        let state = console.lock().unwrap();
        let request = &state.builds[0];
        assert_eq!(request.operator_omni, "0xab");
        assert_eq!(request.max_per_call, "12345678901234567890");
        assert_eq!(request.max_per_period, "22345678901234567890");
        assert_eq!(request.max_total, "32345678901234567890");
        assert_eq!(request.period_seconds, 86400);
        assert_eq!(
            request.preserve_service_ids,
            vec![hash("tool:web"), hash("cred:private")]
        );
        assert!(request.read_only);
    }
    let approval = submit_body(build.user_op);
    let pending = service
        .request(&session, None, "POST", "/v1/scope/submit", approval.clone())
        .await
        .unwrap();
    assert_eq!(pending["pending"], true);
    assert_eq!(storage.lock().unwrap().writes, 1);
    save_manifest(&service, &session, "Renamed concurrently", "new-preset").await;
    storage.lock().unwrap().config_conflicts = 1;
    let conflict = service
        .request(&session, None, "POST", "/v1/scope/submit", approval.clone())
        .await
        .unwrap_err();
    assert!(conflict
        .to_string()
        .contains("chain transaction confirmed; metadata save failed"));
    assert_eq!(storage.lock().unwrap().writes, 2);
    let confirmed = service
        .request(&session, None, "POST", "/v1/scope/submit", approval.clone())
        .await
        .unwrap();
    assert_eq!(confirmed["tx_hash"], "0xconfirmed");
    let (manifest, _) = service
        .read_config::<BindingManifest>(&session, BINDING_MANIFEST_SERVICE)
        .await
        .unwrap();
    let row = &manifest.bindings[0];
    assert_eq!(row.label, "Renamed concurrently");
    assert_eq!(row.preset_id.as_deref(), Some("new-preset"));
    assert_eq!(
        row.granted_service_names,
        vec!["knowledge:recipes", "tool:web"]
    );
    assert_eq!(row.device_key_hash, normalize_omni_0x(DELEGATE_DEVICE));
    assert_eq!(storage.lock().unwrap().writes, 3);
    {
        let state = console.lock().unwrap();
        assert_eq!(state.submissions, 1);
        assert_eq!(state.receipt_polls, 1);
    }
    assert!(service
        .request(&session, None, "POST", "/v1/scope/submit", approval)
        .await
        .unwrap_err()
        .to_string()
        .contains("rebuild"));
    task.abort();
}

#[tokio::test]
async fn foreign_or_replaced_device_never_reaches_runtime_or_saves_approval_metadata() {
    let (service, storage, console, task) = console_setup().await;
    let device = DeviceIdentity::from_random_bytes(&[32; 32]).unwrap();
    let session = session(&device);
    for path in ["/v1/scope/build", "/v1/master/agent/restart"] {
        assert!(service
            .request(&session, None, "POST", path, scope_body(FOREIGN_ACTOR))
            .await
            .is_err());
    }
    assert!(console.lock().unwrap().builds.is_empty());
    assert!(console.lock().unwrap().bridges.is_empty());
    let built = service
        .request(
            &session,
            None,
            "POST",
            "/v1/scope/build",
            scope_body(DELEGATE),
        )
        .await
        .unwrap();
    let build: BuildAcceptUserOpResponse = serde_json::from_value(built).unwrap();
    let approval = submit_body(build.user_op);
    let other_session = DataSession {
        operator_omni: FOREIGN_ACTOR,
        ..session
    };
    let error = service
        .request(
            &other_session,
            None,
            "POST",
            "/v1/scope/submit",
            approval.clone(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("another session"));
    assert_eq!(console.lock().unwrap().submissions, 0);
    service
        .request(&session, None, "POST", "/v1/scope/submit", approval.clone())
        .await
        .unwrap();
    console.lock().unwrap().replace_confirmed_device = true;
    let error = service
        .request(&session, None, "POST", "/v1/scope/submit", approval)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("not reflected in the chain fleet"));
    assert_eq!(storage.lock().unwrap().writes, 0);
    task.abort();
}

#[tokio::test]
async fn persona_applies_exact_saved_body_and_returns_canonical_partial_success() {
    let (service, storage, console, task) = console_setup().await;
    let device = DeviceIdentity::from_random_bytes(&[33; 32]).unwrap();
    let session = session(&device);
    let body = "You are a thoughtful kitchen assistant.\nAsk before making changes.";
    let value = service
        .request(
            &session,
            None,
            "POST",
            "/v1/master/persona",
            json!({"delegate_omni":DELEGATE,"body":body}),
        )
        .await
        .unwrap();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["applied", "apply_detail", "ok", "version"]
    );
    let result: ApiPersonaEditResponse = serde_json::from_value(value).unwrap();
    assert!(result.ok && result.applied);
    assert_eq!(result.version, 1);
    {
        let state = console.lock().unwrap();
        let forwarded = &state.bridges[0];
        assert_eq!(forwarded.path, "/v1/context/apply");
        assert_eq!(forwarded.method.as_deref(), Some("POST"));
        let payload = forwarded.body.as_ref().unwrap();
        assert_eq!(
            STANDARD
                .decode(payload["files"]["soul"].as_str().unwrap())
                .unwrap(),
            body.as_bytes()
        );
        assert_eq!(payload["restart"], true);
    }
    console.lock().unwrap().bridge_receipt = json!({"ok":true,"files_written":["USER.md"]});
    let value = service
        .request(
            &session,
            None,
            "POST",
            "/v1/master/persona",
            json!({"delegate_omni":DELEGATE,"body":"A second saved persona."}),
        )
        .await
        .unwrap();
    let partial: ApiPersonaEditResponse = serde_json::from_value(value).unwrap();
    assert!(partial.ok && !partial.applied);
    assert_eq!(partial.version, 2);
    assert!(partial
        .apply_detail
        .contains("Persona saved; runtime application failed"));
    let saved = service
        .request(
            &session,
            None,
            "GET",
            &format!("/v1/master/persona?delegate={DELEGATE}"),
            Value::Null,
        )
        .await
        .unwrap();
    assert_eq!(saved["current"]["body"], "A second saved persona.");
    assert_eq!(saved["sandbox_configured"], true);
    assert_eq!(storage.lock().unwrap().memory_writes, 2);
    assert!(service
        .request(
            &session,
            None,
            "POST",
            "/v1/master/persona",
            json!({"delegate_omni":DELEGATE,"body":"You are AgentKeys"})
        )
        .await
        .is_err());
    assert_eq!(console.lock().unwrap().bridges.len(), 2);
    assert_eq!(storage.lock().unwrap().memory_writes, 2);
    task.abort();
}

#[tokio::test]
async fn scope_connection_loss_recovers_by_receipt_without_resubmitting() {
    use tokio::io::AsyncReadExt;
    let (mut service, storage, console, task) = console_setup().await;
    let device = DeviceIdentity::from_random_bytes(&[34; 32]).unwrap();
    let session = session(&device);
    let build: BuildAcceptUserOpResponse = serde_json::from_value(
        service
            .request(
                &session,
                None,
                "POST",
                "/v1/scope/build",
                scope_body(DELEGATE),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let approval = submit_body(build.user_op);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let submission_state = console.clone();
    let dropped_response = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0, "approval request ended before its full body");
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
                assert!(header.starts_with("POST /v1/scope/submit HTTP/1.1"));
                let body_len: usize = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                if bytes.len() >= header_end + 4 + body_len {
                    let request: SubmitAcceptUserOpRequest =
                        serde_json::from_slice(&bytes[header_end + 4..header_end + 4 + body_len])
                            .unwrap();
                    assert_eq!(request.user_op.call_data, operation().call_data);
                    submission_state.lock().unwrap().submissions += 1;
                    break;
                }
            }
        }
    });
    let broker = service.broker.clone();
    service.broker = crate::broker::BrokerClient::new(endpoint);
    assert!(matches!(
        service
            .request(&session, None, "POST", "/v1/scope/submit", approval.clone())
            .await,
        Err(DataError::Transport(_))
    ));
    dropped_response.await.unwrap();
    assert_eq!(storage.lock().unwrap().writes, 0);
    service.broker = broker;
    let confirmed = service
        .request(&session, None, "POST", "/v1/scope/submit", approval)
        .await
        .unwrap();
    assert_eq!(confirmed["tx_hash"], "0xconfirmed");
    assert_eq!(storage.lock().unwrap().writes, 1);
    let state = console.lock().unwrap();
    assert_eq!(state.submissions, 1);
    assert_eq!(state.receipt_polls, 1);
    task.abort();
}
