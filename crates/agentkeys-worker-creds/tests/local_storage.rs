use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use agentkeys_core::{
    capability_verify::AuthorityConfig,
    device_crypto::{fresh_cap_pop_nonce_ts, DeviceKey},
    object_store::{HttpObjectStore, ObjectClient, ObjectError, ObjectStore},
};
use agentkeys_local_store::LocalStore;
use agentkeys_protocol::{
    capability::{CapOp, CapPayload, CapToken, DataClass},
    object_store::{ObjectAction, ObjectRequest, ObjectResponse},
};
use agentkeys_worker_creds::{audit::AuditEmitter, handlers, WorkerConfig, WorkerState};
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{EncodePublicKey, LineEnding},
};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const SERVICE: &str = "example";
const PLAINTEXT: &[u8] = b"synthetic-local-credential";

struct ChainState {
    owner_hash: String,
    agent_hash: String,
    revoked: bool,
    allowed: bool,
    roles: u8,
    epoch: u64,
}

struct ObservedStore {
    http: HttpObjectStore,
    calls: AtomicUsize,
    fail_delete: AtomicUsize,
}

#[async_trait]
impl ObjectStore for ObservedStore {
    async fn execute(&self, request: ObjectRequest) -> Result<ObjectResponse, ObjectError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.action == ObjectAction::Delete && self.fail_delete.load(Ordering::SeqCst) == 1 {
            return Err(ObjectError::Unavailable);
        }
        self.http.execute(request).await
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    signer: SigningKey,
    owner: DeviceKey,
    agent: DeviceKey,
    chain: Arc<Mutex<ChainState>>,
    storage: Arc<ObservedStore>,
    worker: Router,
    data_class: DataClass,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::new_for(DataClass::Credentials, handlers::build_router, true).await
    }

    async fn new_for(
        data_class: DataClass,
        router: fn(Arc<WorkerState>) -> Router,
        development_encryption: bool,
    ) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner =
            DeviceKey::load_or_generate(directory.path().join("owner").to_str().unwrap(), false)
                .unwrap();
        let agent =
            DeviceKey::load_or_generate(directory.path().join("agent").to_str().unwrap(), false)
                .unwrap();
        let signer = SigningKey::random(&mut rand_core::OsRng);
        let public = p256::PublicKey::from(*signer.verifying_key())
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let chain = Arc::new(Mutex::new(ChainState {
            owner_hash: owner.device_key_hash().unwrap(),
            agent_hash: agent.device_key_hash().unwrap(),
            revoked: false,
            allowed: true,
            roles: 1,
            epoch: 1,
        }));
        let rpc = Router::new()
            .route(
                "/",
                post(
                    |State(chain): State<Arc<Mutex<ChainState>>>,
                     Json(body): Json<serde_json::Value>| async move {
                        let chain = chain.lock().unwrap();
                        let data = body["params"][0]["data"].as_str().unwrap();
                        let selector = |signature| {
                            format!(
                                "0x{}",
                                hex::encode(agentkeys_core::audit::calldata::selector(signature))
                            )
                        };
                        let result = if data.starts_with(&selector("getDevice(bytes32)")) {
                            let mut bytes = [0; 11 * 32];
                            let hash = &data[10..];
                            let owner = hash == chain.owner_hash.trim_start_matches("0x");
                            assert!(owner || hash == chain.agent_hash.trim_start_matches("0x"));
                            bytes[..32].fill(0x11);
                            bytes[32..64].fill(if owner { 0x11 } else { 0x22 });
                            bytes[6 * 32 + 31] = if owner { 1 } else { 2 };
                            bytes[7 * 32 + 31] = chain.roles;
                            bytes[8 * 32 + 31] = 1;
                            bytes[10 * 32 + 31] = u8::from(chain.revoked);
                            format!("0x{}", hex::encode(bytes))
                        } else if data
                            .starts_with(&selector("isServiceInScope(bytes32,bytes32,bytes32)"))
                        {
                            format!("0x{:064x}", u8::from(chain.allowed))
                        } else {
                            assert_eq!(data, selector("currentEpoch()"));
                            format!("0x{:064x}", chain.epoch)
                        };
                        Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}))
                    },
                ),
            )
            .with_state(chain.clone());
        let (rpc_url, rpc_task) = serve(rpc).await;
        let authority = AuthorityConfig {
            broker_public_key: public,
            rpc_url,
            registry: format!("0x{:040x}", 1),
            scope: format!("0x{:040x}", 2),
            epoch: format!("0x{:040x}", 3),
        };
        let database = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("credentials.db");
        let store = Arc::new(LocalStore::open(&database, data_class, authority.clone()).unwrap());
        let (storage_url, storage_task) = serve(agentkeys_local_store::router(store)).await;
        let storage = Arc::new(ObservedStore {
            http: HttpObjectStore::new(&storage_url).unwrap(),
            calls: AtomicUsize::new(0),
            fail_delete: AtomicUsize::new(0),
        });
        let key: [u8; 32] = {
            use rand_core::RngCore;
            let mut key = [0; 32];
            rand_core::OsRng.fill_bytes(&mut key);
            key
        };
        let config = WorkerConfig {
            authority,
            storage_url,
            chain_profile: "anvil".into(),
            development_kek: development_encryption.then(|| hex::encode(key).into()),
            browser_origins: String::new(),
        };
        let state = WorkerState {
            config,
            storage: ObjectClient::new(storage.clone()),
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            audit: AuditEmitter::new("http://127.0.0.1:1", false),
        };
        Self {
            directory,
            signer,
            owner,
            agent,
            chain,
            storage,
            worker: router(Arc::new(state)),
            data_class,
            tasks: vec![rpc_task, storage_task],
        }
    }

    fn cap(&self, owner: bool, op: CapOp) -> CapToken {
        let mut cap = cap_for(
            &self.signer,
            if owner { &self.owner } else { &self.agent },
            &"11".repeat(32),
            &if owner { "11" } else { "22" }.repeat(32),
            op,
        );
        cap.payload.data_class = self.data_class;
        self.sign(&mut cap, owner);
        cap
    }

    fn sign(&self, cap: &mut CapToken, owner: bool) {
        sign_cap(
            &self.signer,
            if owner { &self.owner } else { &self.agent },
            cap,
        );
    }

    async fn call(
        &self,
        route: &str,
        cap: CapToken,
        plaintext: bool,
    ) -> (StatusCode, serde_json::Value) {
        let mut body = serde_json::json!({"cap":cap});
        if plaintext {
            body["plaintext_b64"] = STANDARD.encode(PLAINTEXT).into();
        }
        self.call_body(route, body).await
    }

    async fn call_body(
        &self,
        route: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = self
            .worker
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(route)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn snapshot(&self) -> Vec<(String, Vec<u8>)> {
        let connection = rusqlite::Connection::open_with_flags(
            self.directory.path().join("credentials.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut statement = connection
            .prepare("SELECT key,value FROM objects ORDER BY key")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    async fn denied(&self, route: &str, cap: CapToken, reason: &str) {
        let before = self.snapshot();
        let calls = self.storage.calls.load(Ordering::SeqCst);
        let (status, body) = self
            .call(
                route,
                cap,
                route.ends_with("/store") || route.ends_with("/put"),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["reason"], reason);
        assert!(body.get("plaintext_b64").is_none());
        assert_eq!(
            self.storage.calls.load(Ordering::SeqCst),
            calls,
            "denial reached storage"
        );
        assert_eq!(self.snapshot(), before, "denial changed data");
    }
}

fn cap_for(
    signer: &SigningKey,
    key: &DeviceKey,
    operator: &str,
    actor: &str,
    op: CapOp,
) -> CapToken {
    let (_, now) = fresh_cap_pop_nonce_ts();
    let mut cap = CapToken {
        payload: CapPayload {
            operator_omni: operator.into(),
            actor_omni: actor.into(),
            service: SERVICE.into(),
            op,
            data_class: DataClass::Credentials,
            device_key_hash: key.device_key_hash().unwrap(),
            k3_epoch: 1,
            issued_at: now,
            expires_at: now + 60,
            nonce: "fixture".into(),
        },
        broker_sig: String::new(),
        client_sig: None,
        client_nonce: None,
        client_ts: None,
        delegation_path: None,
    };
    sign_cap(signer, key, &mut cap);
    cap
}

fn sign_cap(signer: &SigningKey, key: &DeviceKey, cap: &mut CapToken) {
    let (nonce, timestamp) = fresh_cap_pop_nonce_ts();
    let payload = &cap.payload;
    cap.client_sig = Some(
        key.cap_pop_sig(
            &payload.operator_omni,
            &payload.actor_omni,
            &payload.service,
            payload.op.as_str(),
            payload.data_class.as_str(),
            &nonce,
            timestamp,
        )
        .unwrap(),
    );
    cap.client_nonce = Some(nonce);
    cap.client_ts = Some(timestamp);
    let signature: Signature = signer.sign(&Sha256::digest(serde_json::to_vec(payload).unwrap()));
    cap.broker_sig = URL_SAFE_NO_PAD.encode(signature.to_bytes());
}

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (
        url,
        tokio::spawn(async {
            axum::serve(listener, app).await.unwrap();
        }),
    )
}

#[tokio::test]
async fn real_sqlite_http_worker_flow_and_authority_denials() {
    let fixture = Fixture::new().await;
    let (status, _) = fixture
        .call("/v1/cred/store", fixture.cap(true, CapOp::Store), true)
        .await;
    assert_eq!(status, StatusCode::OK);
    let stored = fixture.snapshot();
    assert_eq!(stored.len(), 1);
    assert!(!stored[0]
        .1
        .windows(PLAINTEXT.len())
        .any(|bytes| bytes == PLAINTEXT));
    for owner in [true, false] {
        let (status, fetched) = fixture
            .call("/v1/cred/fetch", fixture.cap(owner, CapOp::Fetch), false)
            .await;
        assert_eq!(status, StatusCode::OK, "{fetched}");
        assert_eq!(
            STANDARD
                .decode(fetched["plaintext_b64"].as_str().unwrap())
                .unwrap(),
            PLAINTEXT
        );
    }
    let (status, list) = fixture
        .call("/v1/cred/list", fixture.cap(true, CapOp::Fetch), false)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["services"], serde_json::json!([SERVICE]));
    let mut cap = fixture.cap(false, CapOp::Fetch);
    cap.client_sig = None;
    fixture
        .denied("/v1/cred/fetch", cap, "cap_pop_invalid")
        .await;
    let mut cap = fixture.cap(false, CapOp::Fetch);
    cap.payload.data_class = DataClass::Memory;
    fixture.sign(&mut cap, false);
    fixture
        .denied("/v1/cred/fetch", cap, "cap_data_class_mismatch")
        .await;
    let mut cap = fixture.cap(false, CapOp::Fetch);
    cap.payload.actor_omni = "33".repeat(32);
    fixture.sign(&mut cap, false);
    fixture
        .denied("/v1/cred/fetch", cap, "device_binding_mismatch")
        .await;
    let mut cap = fixture.cap(false, CapOp::Fetch);
    cap.payload.expires_at = 0;
    fixture.sign(&mut cap, false);
    fixture
        .denied("/v1/cred/fetch", cap, "cap_freshness_failed")
        .await;
    fixture.chain.lock().unwrap().allowed = false;
    fixture
        .denied(
            "/v1/cred/fetch",
            fixture.cap(false, CapOp::Fetch),
            "service_not_in_scope",
        )
        .await;
    fixture.chain.lock().unwrap().allowed = true;
    fixture.chain.lock().unwrap().revoked = true;
    fixture
        .denied(
            "/v1/cred/fetch",
            fixture.cap(false, CapOp::Fetch),
            "device_inactive",
        )
        .await;
    fixture.chain.lock().unwrap().revoked = false;
    fixture.chain.lock().unwrap().epoch = 2;
    fixture
        .denied(
            "/v1/cred/fetch",
            fixture.cap(false, CapOp::Fetch),
            "k3_epoch_mismatch",
        )
        .await;
    fixture.chain.lock().unwrap().epoch = 1;
    fixture
        .denied(
            "/v1/cred/store",
            fixture.cap(false, CapOp::Store),
            "cred_store_not_master_self",
        )
        .await;
    fixture
        .denied(
            "/v1/cred/list",
            fixture.cap(false, CapOp::Fetch),
            "list_not_master_self",
        )
        .await;
    fixture
        .denied(
            "/v1/cred/teardown",
            fixture.cap(false, CapOp::Teardown),
            "teardown_not_master_self",
        )
        .await;

    let client = ObjectClient::new(fixture.storage.clone());
    let cap = fixture.cap(false, CapOp::Fetch);
    let other_key = stored[0].0.replace("11", "33");
    assert!(matches!(
        client.get(&cap, &other_key).await,
        Err(ObjectError::Denied)
    ));
    fixture.chain.lock().unwrap().allowed = false;
    assert!(matches!(
        client.get(&cap, &stored[0].0).await,
        Err(ObjectError::Denied)
    ));
    fixture.chain.lock().unwrap().allowed = true;
    assert_eq!(fixture.snapshot(), stored);

    fixture.storage.fail_delete.store(1, Ordering::SeqCst);
    let (status, body) = fixture
        .call(
            "/v1/cred/teardown",
            fixture.cap(true, CapOp::Teardown),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "storage_unavailable");
    assert_eq!(fixture.snapshot(), stored);
    fixture.storage.fail_delete.store(0, Ordering::SeqCst);
    let (status, body) = fixture
        .call(
            "/v1/cred/teardown",
            fixture.cap(true, CapOp::Teardown),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keys_deleted"], 1);
    assert!(fixture.snapshot().is_empty());
    let (status, body) = fixture
        .call("/v1/cred/fetch", fixture.cap(true, CapOp::Fetch), false)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "object_not_found");
}

#[tokio::test]
async fn configuration_is_owner_only_and_competing_updates_are_atomic() {
    let fixture = Fixture::new_for(
        DataClass::Config,
        agentkeys_worker_config::handlers::build_router,
        true,
    )
    .await;
    let (status, body) = fixture
        .call("/v1/config/put", fixture.cap(true, CapOp::Store), true)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fixture
        .call("/v1/config/get", fixture.cap(true, CapOp::Fetch), false)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        STANDARD
            .decode(body["plaintext_b64"].as_str().unwrap())
            .unwrap(),
        PLAINTEXT
    );
    let original_revision = body["revision"].clone();
    let stored = fixture.snapshot();
    assert!(!stored[0]
        .1
        .windows(PLAINTEXT.len())
        .any(|bytes| bytes == PLAINTEXT));
    for (route, op) in [
        ("/v1/config/get", CapOp::Fetch),
        ("/v1/config/put", CapOp::Store),
        ("/v1/config/teardown", CapOp::Teardown),
    ] {
        fixture
            .denied(route, fixture.cap(false, op), "config_not_master_self")
            .await;
    }
    let mut missing = fixture.cap(true, CapOp::Fetch);
    missing.client_sig = None;
    fixture
        .denied("/v1/config/get", missing, "cap_pop_invalid")
        .await;
    let mut wrong_class = fixture.cap(true, CapOp::Fetch);
    wrong_class.payload.data_class = DataClass::Credentials;
    fixture.sign(&mut wrong_class, true);
    fixture
        .denied("/v1/config/get", wrong_class, "cap_data_class_mismatch")
        .await;
    let mut wrong_actor = fixture.cap(true, CapOp::Fetch);
    wrong_actor.payload.actor_omni = "33".repeat(32);
    fixture.sign(&mut wrong_actor, true);
    fixture
        .denied("/v1/config/get", wrong_actor, "device_binding_mismatch")
        .await;
    fixture.chain.lock().unwrap().epoch = 2;
    fixture
        .denied(
            "/v1/config/get",
            fixture.cap(true, CapOp::Fetch),
            "k3_epoch_mismatch",
        )
        .await;
    fixture.chain.lock().unwrap().epoch = 1;
    fixture.chain.lock().unwrap().revoked = true;
    fixture
        .denied(
            "/v1/config/get",
            fixture.cap(true, CapOp::Fetch),
            "device_inactive",
        )
        .await;
    fixture.chain.lock().unwrap().revoked = false;
    let client = ObjectClient::new(fixture.storage.clone());
    assert!(matches!(
        client
            .get(&fixture.cap(false, CapOp::Fetch), &stored[0].0)
            .await,
        Err(ObjectError::Denied)
    ));
    assert_eq!(fixture.snapshot(), stored);

    let first = serde_json::json!({"cap":fixture.cap(true, CapOp::Store), "plaintext_b64":STANDARD.encode(b"first"), "expected_revision":original_revision});
    let second = serde_json::json!({"cap":fixture.cap(true, CapOp::Store), "plaintext_b64":STANDARD.encode(b"second"), "expected_revision":original_revision});
    let (first, second) = tokio::join!(
        fixture.call_body("/v1/config/put", first),
        fixture.call_body("/v1/config/put", second)
    );
    let statuses = [first.0, second.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1
    );
    let loser = if first.0 == StatusCode::CONFLICT {
        &first.1
    } else {
        &second.1
    };
    assert_eq!(loser["reason"], "stale_base");
    let winner = if first.0 == StatusCode::OK {
        b"first".as_slice()
    } else {
        b"second".as_slice()
    };
    let (status, fetched) = fixture
        .call("/v1/config/get", fixture.cap(true, CapOp::Fetch), false)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        STANDARD
            .decode(fetched["plaintext_b64"].as_str().unwrap())
            .unwrap(),
        winner
    );
    let current = fixture.snapshot();
    let (status, body) = fixture.call_body("/v1/config/put", serde_json::json!({"cap":fixture.cap(true, CapOp::Store), "plaintext_b64":STANDARD.encode(PLAINTEXT), "expected_revision":""})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "stale_base");
    assert_eq!(fixture.snapshot(), current);
    fixture.storage.fail_delete.store(1, Ordering::SeqCst);
    let (status, body) = fixture
        .call(
            "/v1/config/teardown",
            fixture.cap(true, CapOp::Teardown),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["reason"], "storage_unavailable");
    assert_eq!(fixture.snapshot(), current);
    fixture.storage.fail_delete.store(0, Ordering::SeqCst);
    let (status, body) = fixture
        .call(
            "/v1/config/teardown",
            fixture.cap(true, CapOp::Teardown),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keys_deleted"], 1);
    assert!(fixture.snapshot().is_empty());
    let (status, body) = fixture
        .call("/v1/config/get", fixture.cap(true, CapOp::Fetch), false)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "object_not_found");
}

#[tokio::test]
async fn configuration_without_development_key_only_accepts_client_encrypted_objects() {
    let fixture = Fixture::new_for(
        DataClass::Config,
        agentkeys_worker_config::handlers::build_router,
        false,
    )
    .await;
    let mut key = [0; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);
    let encrypted = agentkeys_core::envelope_v3::encrypt_v3(
        &key,
        PLAINTEXT,
        &agentkeys_core::envelope_v3::aad_v3(&"11".repeat(32), SERVICE),
    )
    .unwrap();
    let (status, body) = fixture.call_body("/v1/config/put", serde_json::json!({"cap":fixture.cap(true, CapOp::Store), "envelope_b64":STANDARD.encode(&encrypted), "expected_revision":""})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fixture
        .call("/v1/config/get", fixture.cap(true, CapOp::Fetch), false)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["plaintext_b64"].is_null());
    assert_eq!(
        STANDARD
            .decode(body["envelope_b64"].as_str().unwrap())
            .unwrap(),
        encrypted
    );
    fixture
        .denied(
            "/v1/config/put",
            fixture.cap(true, CapOp::Store),
            "plaintext_put_disabled",
        )
        .await;
    let stored = fixture.snapshot();
    let calls = fixture.storage.calls.load(Ordering::SeqCst);
    let (status, body) = fixture.call_body("/v1/config/put", serde_json::json!({"cap":fixture.cap(true, CapOp::Store), "envelope_b64":STANDARD.encode([3u8]), "expected_revision":""})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "envelope_truncated");
    assert_eq!(fixture.storage.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fixture.snapshot(), stored);
}

struct WorkerProcess {
    child: tokio::process::Child,
    url: String,
}

impl WorkerProcess {
    async fn start(
        profile: &std::path::Path,
        public_key: &std::path::Path,
        storage_url: &str,
        encryption_key: &std::path::Path,
    ) -> Self {
        use std::{process::Stdio, time::Duration};
        use tokio::io::AsyncBufReadExt;
        let mut child = tokio::process::Command::new(
            std::env::var("AGENT_TERRIER_QUALIFICATION_WORKER")
                .unwrap_or_else(|_| env!("CARGO_BIN_EXE_agentkeys-worker-creds").into()),
        )
        .env_clear()
        .arg("--development")
        .arg("--profile")
        .arg(profile)
        .arg("--broker-public-key")
        .arg(public_key)
        .arg("--storage-url")
        .arg(storage_url)
        .arg("--development-kek-file")
        .arg(encryption_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
        let mut output = tokio::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let startup: serde_json::Value =
            serde_json::from_str(&line).expect("worker did not report startup");
        assert_eq!(startup["development_only"], true);
        Self {
            child,
            url: format!("http://{}", startup["listen"].as_str().unwrap()),
        }
    }

    async fn stop(&mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
    }

    async fn call(
        &self,
        route: &str,
        cap: CapToken,
        store: bool,
    ) -> (StatusCode, serde_json::Value) {
        let mut body = serde_json::json!({"cap":cap});
        if store {
            body["plaintext_b64"] = STANDARD.encode(PLAINTEXT).into();
        }
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("{}{route}", self.url))
            .json(&body)
            .send()
            .await
            .unwrap();
        (response.status(), response.json().await.unwrap())
    }
}

#[tokio::test]
#[ignore = "requires the explicit real-chain credential qualification fixture"]
async fn real_chain_credential_worker() {
    qualify_real_worker(DataClass::Credentials).await;
}

#[tokio::test]
#[ignore = "requires the explicit real-chain configuration qualification fixture"]
async fn real_chain_config_worker() {
    qualify_real_worker(DataClass::Config).await;
}

async fn qualify_real_worker(data_class: DataClass) {
    use agentkeys_core::{chain_profile::ChainProfile, protected_file};
    use rand_core::RngCore;
    use std::path::PathBuf;
    let required =
        |name| PathBuf::from(std::env::var(name).expect("explicit qualification input missing"));
    let profile_path = required("AGENT_TERRIER_QUALIFICATION_PROFILE");
    let directory = required("AGENT_TERRIER_QUALIFICATION_STORE");
    let owner_key = required("AGENT_TERRIER_QUALIFICATION_OWNER_KEY");
    let agent_key = required("AGENT_TERRIER_QUALIFICATION_DEVICE_KEY");
    let phase = std::env::var("AGENT_TERRIER_QUALIFICATION_PHASE").unwrap();
    let operator = std::env::var("AGENT_TERRIER_QUALIFICATION_OPERATOR").unwrap();
    let enrollment: agentkeys_protocol::EndpointEnrollment = serde_json::from_slice(
        &std::fs::read(required("AGENT_TERRIER_QUALIFICATION_ENROLLMENT")).unwrap(),
    )
    .unwrap();
    protected_file::open_read(owner_key.to_str().unwrap()).unwrap();
    protected_file::open_read(agent_key.to_str().unwrap()).unwrap();
    let owner = DeviceKey::load_or_generate(owner_key.to_str().unwrap(), false).unwrap();
    let agent = DeviceKey::load_or_generate(agent_key.to_str().unwrap(), false).unwrap();
    let signer = SigningKey::random(&mut rand_core::OsRng);
    let public = p256::PublicKey::from(*signer.verifying_key())
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let public_key_file = directory.join("issuer-public.pem");
    protected_file::write(public_key_file.to_str().unwrap(), public.as_bytes(), false).unwrap();
    let encryption_key_file = directory.join("worker-encryption.key");
    if !encryption_key_file.exists() {
        assert_eq!(phase, "active");
        let mut key = [0; 32];
        rand_core::OsRng.fill_bytes(&mut key);
        protected_file::write(
            encryption_key_file.to_str().unwrap(),
            hex::encode(key).as_bytes(),
            true,
        )
        .unwrap();
    }
    let profile = ChainProfile::load_from_file(&profile_path).unwrap();
    profile.require_local_development(true, None).unwrap();
    let database = directory.join(format!("{}.db", data_class.as_str()));
    let store = Arc::new(
        LocalStore::open(
            &database,
            data_class,
            AuthorityConfig::from_profile(&profile, public).unwrap(),
        )
        .unwrap(),
    );
    let (storage_url, storage_task) = serve(agentkeys_local_store::router(store)).await;
    let mut worker = WorkerProcess::start(
        &profile_path,
        &public_key_file,
        &storage_url,
        &encryption_key_file,
    )
    .await;
    let cap = |key: &DeviceKey, actor: &str, op| {
        let mut cap = cap_for(&signer, key, &operator, actor, op);
        cap.payload.data_class = data_class;
        sign_cap(&signer, key, &mut cap);
        cap
    };
    let owner_cap = |op| cap(&owner, &operator, op);
    let agent_cap = |op| cap(&agent, &enrollment.actor_omni, op);
    let (put_route, get_route) = if data_class == DataClass::Config {
        ("/v1/config/put", "/v1/config/get")
    } else {
        ("/v1/cred/store", "/v1/cred/fetch")
    };
    let snapshot = || {
        let connection = rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut statement = connection
            .prepare("SELECT key,value FROM objects ORDER BY key")
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    if phase == "active" {
        let (status, body) = worker.call(put_route, owner_cap(CapOp::Store), true).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = worker.call(get_route, agent_cap(CapOp::Fetch), false).await;
        if data_class == DataClass::Config {
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert_eq!(body["reason"], "config_not_master_self");
        } else {
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(
                STANDARD
                    .decode(body["plaintext_b64"].as_str().unwrap())
                    .unwrap(),
                PLAINTEXT
            );
        }
        let before = snapshot();
        assert_eq!(before.len(), 1);
        assert!(!before[0]
            .1
            .windows(PLAINTEXT.len())
            .any(|bytes| bytes == PLAINTEXT));
        for (mutation, reason) in [
            (0, "cap_pop_invalid"),
            (1, "device_binding_mismatch"),
            (2, "service_not_in_scope"),
            (3, "cap_data_class_mismatch"),
        ] {
            let mut cap = agent_cap(CapOp::Fetch);
            match mutation {
                0 => cap.client_sig = None,
                1 => {
                    cap.payload.actor_omni = format!("0x{}", "33".repeat(32));
                    sign_cap(&signer, &agent, &mut cap);
                }
                2 => {
                    cap.payload.service = "ungranted".into();
                    sign_cap(&signer, &agent, &mut cap);
                }
                _ => {
                    cap.payload.data_class = DataClass::Memory;
                    sign_cap(&signer, &agent, &mut cap);
                }
            }
            let (status, body) = worker.call(get_route, cap, false).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert_eq!(body["reason"], reason);
            assert!(body.get("plaintext_b64").is_none());
            assert_eq!(snapshot(), before);
        }
        worker.stop().await;
        worker = WorkerProcess::start(
            &profile_path,
            &public_key_file,
            &storage_url,
            &encryption_key_file,
        )
        .await;
    } else {
        let before = snapshot();
        let (status, body) = worker.call(get_route, agent_cap(CapOp::Fetch), false).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            body["reason"],
            match phase.as_str() {
                "scope_revoked" => "service_not_in_scope",
                "device_revoked" => "device_inactive",
                _ => panic!("unknown qualification phase"),
            }
        );
        assert!(body.get("plaintext_b64").is_none());
        assert_eq!(snapshot(), before);
    }
    let (status, body) = worker.call(get_route, owner_cap(CapOp::Fetch), false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        STANDARD
            .decode(body["plaintext_b64"].as_str().unwrap())
            .unwrap(),
        PLAINTEXT
    );
    worker.stop().await;
    storage_task.abort();
}
