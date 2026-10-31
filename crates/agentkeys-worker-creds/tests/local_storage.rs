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
        let store = Arc::new(
            LocalStore::open(&database, DataClass::Credentials, authority.clone()).unwrap(),
        );
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
            development_kek: hex::encode(key).into(),
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
            worker: handlers::build_router(Arc::new(state)),
            tasks: vec![rpc_task, storage_task],
        }
    }

    fn cap(&self, owner: bool, op: CapOp) -> CapToken {
        let (_, now) = fresh_cap_pop_nonce_ts();
        let mut cap = CapToken {
            payload: CapPayload {
                operator_omni: "11".repeat(32),
                actor_omni: if owner { "11" } else { "22" }.repeat(32),
                service: SERVICE.into(),
                op,
                data_class: DataClass::Credentials,
                device_key_hash: if owner { &self.owner } else { &self.agent }
                    .device_key_hash()
                    .unwrap(),
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
        self.sign(&mut cap, owner);
        cap
    }

    fn sign(&self, cap: &mut CapToken, owner: bool) {
        let (nonce, timestamp) = fresh_cap_pop_nonce_ts();
        let payload = &cap.payload;
        cap.client_sig = Some(
            if owner { &self.owner } else { &self.agent }
                .cap_pop_sig(
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
        let signature: Signature = self
            .signer
            .sign(&Sha256::digest(serde_json::to_vec(payload).unwrap()));
        cap.broker_sig = URL_SAFE_NO_PAD.encode(signature.to_bytes());
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
        let (status, body) = self.call(route, cap, route.ends_with("/store")).await;
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
