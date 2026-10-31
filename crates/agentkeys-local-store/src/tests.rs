use super::*;
use agentkeys_core::device_crypto::DeviceKey;
use agentkeys_protocol::capability::{CapPayload, CapToken};
use axum::body::Body;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{EncodePublicKey, LineEnding},
};
use std::sync::atomic::Ordering;
use tower::ServiceExt;

const SERVICE: &str = "knowledge:notes";

struct ChainFixture {
    actor: String,
    operator: String,
    revoked: bool,
    allowed: bool,
    epoch: u64,
}

struct Fixture {
    directory: tempfile::TempDir,
    signer: SigningKey,
    device: DeviceKey,
    chain: Arc<Mutex<ChainFixture>>,
    server: tokio::task::JoinHandle<()>,
    store: Arc<LocalStore>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let device =
            DeviceKey::load_or_generate(directory.path().join("actor").to_str().unwrap(), false)
                .unwrap();
        let signer = SigningKey::random(&mut rand_core::OsRng);
        let public = p256::PublicKey::from(*signer.verifying_key())
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let chain = Arc::new(Mutex::new(ChainFixture {
            operator: "11".repeat(32),
            actor: "22".repeat(32),
            revoked: false,
            allowed: true,
            epoch: 1,
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route(
                "/",
                post(
                    |State(chain): State<Arc<Mutex<ChainFixture>>>,
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
                            bytes[..32].copy_from_slice(&hex::decode(&chain.operator).unwrap());
                            bytes[32..64].copy_from_slice(&hex::decode(&chain.actor).unwrap());
                            bytes[6 * 32 + 31] = 2;
                            bytes[7 * 32 + 31] = 1;
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
                        Json(serde_json::json!({"jsonrpc":"2.0", "id":1, "result":result}))
                    },
                ),
            )
            .with_state(chain.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let authority = AuthorityConfig {
            broker_public_key: public,
            rpc_url,
            registry: address(1),
            scope: address(2),
            epoch: address(3),
        };
        let database = directory.path().canonicalize().unwrap().join("objects.db");
        let store = Arc::new(LocalStore::open(&database, DataClass::Memory, authority).unwrap());
        Self {
            directory,
            signer,
            device,
            chain,
            server,
            store,
        }
    }

    fn request(&self, action: ObjectAction) -> ObjectRequest {
        let cap = CapToken {
            payload: CapPayload {
                operator_omni: "11".repeat(32),
                actor_omni: "22".repeat(32),
                service: SERVICE.into(),
                op: if action == ObjectAction::Put {
                    CapOp::Store
                } else {
                    CapOp::Fetch
                },
                data_class: DataClass::Memory,
                device_key_hash: self.device.device_key_hash().unwrap(),
                k3_epoch: 1,
                issued_at: now(),
                expires_at: now() + 60,
                nonce: "fixture".into(),
            },
            broker_sig: String::new(),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        };
        let mut request = ObjectRequest {
            cap,
            action,
            key: format!("bots/{}/memory/{SERVICE}.enc", "22".repeat(32)),
            value_b64: if action == ObjectAction::Put {
                Some(STANDARD.encode([7; 48]))
            } else {
                None
            },
            expected_revision: None,
            after: None,
        };
        sign(&mut request, &self.signer, &self.device);
        request
    }

    fn snapshot(&self) -> Vec<(String, Vec<u8>, String)> {
        let connection = self.store.connection.lock().unwrap();
        let mut statement = connection
            .prepare("SELECT key,value,revision FROM objects ORDER BY key")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    async fn deny(&self, request: ObjectRequest, expected: &str) {
        let before = self.snapshot();
        let operations = self.store.storage_operations.load(Ordering::SeqCst);
        let response = router(self.store.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/objects")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({"code":expected})
        );
        assert_eq!(
            self.store.storage_operations.load(Ordering::SeqCst),
            operations,
            "denial reached storage"
        );
        assert_eq!(self.snapshot(), before);
    }
}

fn address(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 20]))
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign(request: &mut ObjectRequest, signer: &SigningKey, device: &DeviceKey) {
    let (nonce, timestamp) = agentkeys_core::device_crypto::fresh_cap_pop_nonce_ts();
    let payload = &request.cap.payload;
    request.cap.client_sig = Some(
        device
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
    request.cap.client_nonce = Some(nonce);
    request.cap.client_ts = Some(timestamp);
    sign_broker(request, signer);
}

fn sign_broker(request: &mut ObjectRequest, signer: &SigningKey) {
    let signature: Signature = signer.sign(&Sha256::digest(
        serde_json::to_vec(&request.cap.payload).unwrap(),
    ));
    request.cap.broker_sig = URL_SAFE_NO_PAD.encode(signature.to_bytes());
}

#[tokio::test]
async fn authorized_round_trip_and_denials_do_not_touch_storage() {
    let fixture = Fixture::new().await;
    fixture
        .store
        .execute(fixture.request(ObjectAction::Put))
        .await
        .unwrap();
    let fetched = fixture
        .store
        .execute(fixture.request(ObjectAction::Get))
        .await
        .unwrap();
    assert_eq!(fetched.value_b64, Some(STANDARD.encode([7; 48])));
    let base = fixture.request(ObjectAction::Get);
    let mut wrong_actor = base.clone();
    wrong_actor.key = wrong_actor.key.replace(&"22".repeat(32), &"11".repeat(32));
    fixture.deny(wrong_actor, "storage_scope_denied").await;
    let mut wrong_class = base.clone();
    wrong_class.cap.payload.data_class = DataClass::Config;
    sign(&mut wrong_class, &fixture.signer, &fixture.device);
    fixture.deny(wrong_class, "cap_data_class_mismatch").await;
    let mut wrong_prefix = base.clone();
    wrong_prefix.key = wrong_prefix.key.replace("memory", "credentials");
    fixture.deny(wrong_prefix, "storage_scope_denied").await;
    let mut wrong_op = base.clone();
    wrong_op.action = ObjectAction::Put;
    wrong_op.value_b64 = Some(STANDARD.encode([8; 48]));
    fixture.deny(wrong_op, "storage_scope_denied").await;
    let mut absent = base.clone();
    absent.cap.client_sig = None;
    fixture.deny(absent, "cap_pop_invalid").await;
    let mut tampered = base.clone();
    tampered.cap.payload.service = "knowledge:other".into();
    fixture.deny(tampered, "broker_sig_invalid").await;
    let other_device = DeviceKey::load_or_generate(
        fixture.directory.path().join("other").to_str().unwrap(),
        false,
    )
    .unwrap();
    let mut forged = base.clone();
    sign(&mut forged, &fixture.signer, &other_device);
    fixture.deny(forged, "cap_pop_invalid").await;
    let mut expired = base.clone();
    expired.cap.payload.expires_at = 1;
    sign_broker(&mut expired, &fixture.signer);
    fixture.deny(expired, "cap_freshness_failed").await;
    let mut unauthorized = base.clone();
    unauthorized.cap.payload.actor_omni = "44".repeat(32);
    unauthorized.key = unauthorized.key.replace(&"22".repeat(32), &"44".repeat(32));
    sign(&mut unauthorized, &fixture.signer, &fixture.device);
    fixture.deny(unauthorized, "device_binding_mismatch").await;
    fixture.chain.lock().unwrap().revoked = true;
    fixture.deny(base.clone(), "device_inactive").await;
    fixture.chain.lock().unwrap().revoked = false;
    fixture.chain.lock().unwrap().allowed = false;
    fixture.deny(base.clone(), "service_not_in_scope").await;
    fixture.chain.lock().unwrap().allowed = true;
    fixture.chain.lock().unwrap().epoch = 2;
    fixture.deny(base, "cap_epoch_mismatch").await;
}

#[tokio::test]
async fn restart_and_concurrent_compare_and_swap_preserve_committed_data() {
    let fixture = Fixture::new().await;
    let initial = fixture
        .store
        .execute(fixture.request(ObjectAction::Put))
        .await
        .unwrap()
        .revision
        .unwrap();
    let mut first = fixture.request(ObjectAction::Put);
    first.expected_revision = Some(initial.clone());
    first.value_b64 = Some(STANDARD.encode([8; 48]));
    let mut second = first.clone();
    second.value_b64 = Some(STANDARD.encode([9; 48]));
    let (first, second) = tokio::join!(fixture.store.execute(first), fixture.store.execute(second));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let error = first.err().or_else(|| second.err()).unwrap();
    assert_eq!(error.code, "object_revision_conflict");
    let reopened = Arc::new(
        LocalStore::open(
            &fixture
                .directory
                .path()
                .canonicalize()
                .unwrap()
                .join("objects.db"),
            DataClass::Memory,
            fixture.store.authority.clone(),
        )
        .unwrap(),
    );
    let saved = fixture
        .store
        .execute(fixture.request(ObjectAction::Get))
        .await
        .unwrap();
    let restored = reopened
        .execute(fixture.request(ObjectAction::Get))
        .await
        .unwrap();
    assert_eq!(saved.value_b64, restored.value_b64);
    assert_ne!(restored.revision, Some(initial));
    assert!(LocalStore::open(
        &fixture
            .directory
            .path()
            .canonicalize()
            .unwrap()
            .join("objects.db"),
        DataClass::Credentials,
        fixture.store.authority.clone()
    )
    .is_err());
}

#[tokio::test]
async fn append_is_create_only_and_never_reads_or_replaces_an_existing_proposal() {
    let fixture = Fixture::new().await;
    let mut request = fixture.request(ObjectAction::Put);
    request.cap.payload.op = CapOp::Append;
    request.cap.payload.service = "proposal:notes".into();
    request.key = format!(
        "bots/{}/inbox/{}/proposal:notes/item.enc",
        "11".repeat(32),
        "22".repeat(32)
    );
    sign(&mut request, &fixture.signer, &fixture.device);
    fixture.store.execute(request.clone()).await.unwrap();
    let before = fixture.snapshot();
    request.value_b64 = Some(STANDARD.encode([9; 48]));
    assert_eq!(
        fixture
            .store
            .execute(request.clone())
            .await
            .unwrap_err()
            .code,
        "object_revision_conflict"
    );
    assert_eq!(fixture.snapshot(), before);
    request.action = ObjectAction::Get;
    request.value_b64 = None;
    fixture.deny(request, "storage_scope_denied").await;
}

#[cfg(unix)]
#[tokio::test]
async fn unsafe_database_files_are_rejected_without_modifying_the_target() {
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
    let fixture = Fixture::new().await;
    let directory = fixture.directory.path().canonicalize().unwrap();
    let target = directory.join("sentinel");
    agentkeys_core::protected_file::write(target.to_str().unwrap(), b"unchanged", true).unwrap();
    let link = directory.join("linked.db");
    symlink(&target, &link).unwrap();
    assert!(LocalStore::open(&link, DataClass::Memory, fixture.store.authority.clone()).is_err());
    fs::remove_file(&link).unwrap();
    fs::hard_link(&target, &link).unwrap();
    assert!(LocalStore::open(&link, DataClass::Memory, fixture.store.authority.clone()).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    fs::remove_file(&link).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LocalStore::open(&target, DataClass::Memory, fixture.store.authority.clone()).is_err());
    let foreign = directory.join("foreign.db");
    {
        let connection = rusqlite::Connection::open(&foreign).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE unrelated (value TEXT); INSERT INTO unrelated VALUES ('sentinel');",
            )
            .unwrap();
    }
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
    let preserved = fs::read(&foreign).unwrap();
    assert!(
        LocalStore::open(&foreign, DataClass::Memory, fixture.store.authority.clone()).is_err()
    );
    assert_eq!(fs::read(&foreign).unwrap(), preserved);
    let mut invalid_authority = fixture.store.authority.clone();
    invalid_authority.broker_public_key = "invalid".into();
    assert!(LocalStore::open(
        &directory.join("invalid-key.db"),
        DataClass::Memory,
        invalid_authority
    )
    .is_err());
    assert!(!directory.join("invalid-key.db").exists());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(LocalStore::open(
        &directory.join("new.db"),
        DataClass::Memory,
        fixture.store.authority.clone()
    )
    .is_err());
    assert!(!directory.join("new.db").exists());
}
