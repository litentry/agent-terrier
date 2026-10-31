use agentkeys_core::{chain_profile::ChainProfile, device_crypto::DeviceKey};
use agentkeys_protocol::{
    capability::{CapOp, CapPayload, CapToken, DataClass},
    object_store::{ObjectAction, ObjectRequest, ObjectResponse},
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
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncBufReadExt;

struct StoreProcess {
    child: tokio::process::Child,
    url: String,
}

impl StoreProcess {
    async fn start(profile: &Path, database: &Path, public_key: &Path) -> Self {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentkeys-local-store"));
        command
            .env_clear()
            .args(["--development", "--data-class", "memory", "--profile"])
            .arg(profile)
            .arg("--database")
            .arg(database)
            .arg("--broker-public-key")
            .arg(public_key)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().unwrap();
        let mut output = tokio::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let ready: serde_json::Value =
            serde_json::from_str(&line).expect("store did not report startup");
        Self {
            child,
            url: format!("http://{}/v1/objects", ready["listen"].as_str().unwrap()),
        }
    }

    async fn stop(&mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
    }
}

struct Client {
    http: reqwest::Client,
    signer: SigningKey,
    device: DeviceKey,
    operator: String,
    actor: String,
}

impl Client {
    fn request(&self, action: ObjectAction) -> ObjectRequest {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut request = ObjectRequest {
            cap: CapToken {
                payload: CapPayload {
                    operator_omni: self.operator.clone(),
                    actor_omni: self.actor.clone(),
                    service: "knowledge:notes".into(),
                    op: if action == ObjectAction::Put {
                        CapOp::Store
                    } else {
                        CapOp::Fetch
                    },
                    data_class: DataClass::Memory,
                    device_key_hash: self.device.device_key_hash().unwrap(),
                    k3_epoch: 1,
                    issued_at: now,
                    expires_at: now + 60,
                    nonce: "qualification".into(),
                },
                broker_sig: String::new(),
                client_sig: None,
                client_nonce: None,
                client_ts: None,
                delegation_path: None,
            },
            action,
            key: format!(
                "bots/{}/memory/knowledge:notes.enc",
                self.actor.trim_start_matches("0x")
            ),
            value_b64: if action == ObjectAction::Put {
                Some(STANDARD.encode([7; 48]))
            } else {
                None
            },
            expected_revision: None,
            after: None,
        };
        self.sign(&mut request);
        request
    }

    fn sign(&self, request: &mut ObjectRequest) {
        let (nonce, timestamp) = agentkeys_core::device_crypto::fresh_cap_pop_nonce_ts();
        let payload = &request.cap.payload;
        request.cap.client_sig = Some(
            self.device
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
        let signature: Signature = self
            .signer
            .sign(&Sha256::digest(serde_json::to_vec(payload).unwrap()));
        request.cap.broker_sig = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    }

    async fn success(&self, process: &StoreProcess, request: ObjectRequest) -> ObjectResponse {
        let response = self
            .http
            .post(&process.url)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.json().await.unwrap()
    }

    async fn denied(
        &self,
        process: &StoreProcess,
        database: &Path,
        request: ObjectRequest,
        code: &str,
    ) {
        let before = snapshot(database);
        let response = self
            .http
            .post(&process.url)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap(),
            serde_json::json!({"code":code})
        );
        assert_eq!(
            snapshot(database),
            before,
            "denied operation changed storage"
        );
    }
}

fn snapshot(database: &Path) -> Vec<(String, Vec<u8>, String)> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut query = connection
        .prepare("SELECT key,value,revision FROM objects ORDER BY key")
        .unwrap();
    query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[tokio::test]
#[ignore = "requires the explicit local-chain storage qualification fixture"]
async fn real_chain_storage_authority() {
    let required =
        |name| PathBuf::from(std::env::var(name).expect("explicit qualification input missing"));
    let profile_path = required("AGENT_TERRIER_QUALIFICATION_PROFILE");
    let directory = required("AGENT_TERRIER_QUALIFICATION_STORE");
    let key = required("AGENT_TERRIER_QUALIFICATION_DEVICE_KEY");
    let enrollment_path = required("AGENT_TERRIER_QUALIFICATION_ENROLLMENT");
    let phase = std::env::var("AGENT_TERRIER_QUALIFICATION_PHASE").unwrap();
    let profile = ChainProfile::load_from_file(&profile_path).unwrap();
    profile.require_local_development(true, None).unwrap();
    let enrollment: agentkeys_protocol::EndpointEnrollment =
        serde_json::from_slice(&std::fs::read(enrollment_path).unwrap()).unwrap();
    agentkeys_core::protected_file::open_read(key.to_str().unwrap()).unwrap();
    let client = Client {
        http: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap(),
        signer: SigningKey::random(&mut rand_core::OsRng),
        device: DeviceKey::load_or_generate(key.to_str().unwrap(), false).unwrap(),
        operator: std::env::var("AGENT_TERRIER_QUALIFICATION_OPERATOR").unwrap(),
        actor: enrollment.actor_omni,
    };
    let temporary = tempfile::tempdir_in(&directory).unwrap();
    let public_path = temporary.path().join("issuer-public.pem");
    let public = p256::PublicKey::from(*client.signer.verifying_key())
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    agentkeys_core::protected_file::write(public_path.to_str().unwrap(), public.as_bytes(), true)
        .unwrap();
    let database = directory.join("memory.db");
    let mut process = StoreProcess::start(&profile_path, &database, &public_path).await;
    if phase == "active" {
        client
            .success(&process, client.request(ObjectAction::Put))
            .await;
        let saved = client
            .success(&process, client.request(ObjectAction::Get))
            .await;
        assert_eq!(saved.value_b64, Some(STANDARD.encode([7; 48])));
        let mut wrong_key = client.request(ObjectAction::Put);
        wrong_key.key = wrong_key.key.replace(
            client.actor.trim_start_matches("0x"),
            client.operator.trim_start_matches("0x"),
        );
        client
            .denied(&process, &database, wrong_key, "storage_scope_denied")
            .await;
        let mut wrong_class = client.request(ObjectAction::Put);
        wrong_class.cap.payload.data_class = DataClass::Config;
        client.sign(&mut wrong_class);
        client
            .denied(&process, &database, wrong_class, "cap_data_class_mismatch")
            .await;
        let mut expired = client.request(ObjectAction::Put);
        expired.cap.payload.expires_at = 1;
        client.sign(&mut expired);
        client
            .denied(&process, &database, expired, "cap_freshness_failed")
            .await;
        let mut absent = client.request(ObjectAction::Put);
        absent.cap.client_sig = None;
        client
            .denied(&process, &database, absent, "cap_pop_invalid")
            .await;
        let mut forged_binding = client.request(ObjectAction::Put);
        forged_binding.cap.payload.actor_omni = "44".repeat(32);
        forged_binding.key = forged_binding
            .key
            .replace(client.actor.trim_start_matches("0x"), &"44".repeat(32));
        client.sign(&mut forged_binding);
        client
            .denied(
                &process,
                &database,
                forged_binding,
                "device_binding_mismatch",
            )
            .await;
        let mut unauthorized_service = client.request(ObjectAction::Put);
        unauthorized_service.cap.payload.service = "knowledge:ungranted".into();
        unauthorized_service.key = unauthorized_service
            .key
            .replace("knowledge:notes", "knowledge:ungranted");
        client.sign(&mut unauthorized_service);
        client
            .denied(
                &process,
                &database,
                unauthorized_service,
                "service_not_in_scope",
            )
            .await;
        process.stop().await;
        process = StoreProcess::start(&profile_path, &database, &public_path).await;
        assert_eq!(
            client
                .success(&process, client.request(ObjectAction::Get))
                .await
                .value_b64,
            saved.value_b64
        );
    } else {
        let code = match phase.as_str() {
            "scope_revoked" => "service_not_in_scope",
            "device_revoked" => "device_inactive",
            _ => panic!("unknown qualification phase"),
        };
        client
            .denied(&process, &database, client.request(ObjectAction::Get), code)
            .await;
        client
            .denied(&process, &database, client.request(ObjectAction::Put), code)
            .await;
    }
    process.stop().await;
}
