use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use agentkeys_backend_client::protocol::hosted_signer::*;
use agentkeys_core::device_crypto::{device_key_hash, eip191_sign, evm_address};
use agentkeys_web_core::broker::BrokerClient;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Stack {
    temporary: Option<tempfile::TempDir>,
    state: PathBuf,
    repository: PathBuf,
}

impl Stack {
    fn new() -> Self {
        let temporary = tempfile::Builder::new()
            .prefix("terrier-browser-")
            .tempdir()
            .unwrap();
        Self {
            state: temporary.path().join("state"),
            temporary: Some(temporary),
            repository: Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap(),
        }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new("python3")
            .arg(self.repository.join("terrier"))
            .args(arguments)
            .current_dir(&self.repository)
            .env("AGENT_TERRIER_STATE_DIR", &self.state)
            .env("AGENT_TERRIER_CLI", env!("CARGO_BIN_EXE_agentkeys"))
            .output()
            .expect("run canonical local CLI")
    }

    fn success(&self, arguments: &[&str]) -> Value {
        let output = self.run(arguments);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("CLI JSON receipt")
    }

    fn approve(&self, approval: &HostedSignerApproval, owner: &str, confirmed: &str) -> Output {
        let request = self
            .temporary
            .as_ref()
            .unwrap()
            .path()
            .join("browser-request.json");
        std::fs::write(&request, serde_json::to_vec(approval).unwrap()).unwrap();
        self.run(&[
            "browser",
            "approve",
            "--name",
            owner,
            "--request-file",
            request.to_str().unwrap(),
            "--confirm-device-key-hash",
            confirmed,
        ])
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let stopped = self.run(&["stack", "stop"]).status.success();
        if !stopped || std::thread::panicking() {
            if let Some(temporary) = self.temporary.take() {
                eprintln!(
                    "Private browser diagnostic directory: {}",
                    temporary.keep().display()
                );
            }
        }
    }
}

fn assertion(
    key: &SigningKey,
    challenge: &[u8],
    credential_id: &str,
    origin: &str,
) -> BrowserAssertion {
    let mut authenticator = Sha256::digest(b"localhost").to_vec();
    authenticator.extend_from_slice(&[5, 0, 0, 0, 0]);
    #[derive(serde::Serialize)]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
        challenge: String,
        origin: &'a str,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
    }
    let client = serde_json::to_vec(&ClientData {
        kind: "webauthn.get",
        challenge: URL_SAFE_NO_PAD.encode(challenge),
        origin,
        cross_origin: false,
    })
    .unwrap();
    let signature: Signature =
        key.sign(&[authenticator.as_slice(), Sha256::digest(&client).as_slice()].concat());
    BrowserAssertion {
        authenticator_data: URL_SAFE_NO_PAD.encode(authenticator),
        client_data_json: URL_SAFE_NO_PAD.encode(client),
        signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        credential_id: credential_id.into(),
    }
}

fn signed(
    mut enrollment: HostedSignerChallenge,
    key: &SigningKey,
    device: &k256::ecdsa::SigningKey,
) -> HostedSignerApproval {
    let challenge = agentkeys_core::browser_enrollment::challenge(&enrollment.intent).unwrap();
    enrollment.challenge = format!("0x{}", hex::encode(challenge));
    let proof = assertion(
        key,
        &challenge,
        &enrollment.intent.credential_id,
        &enrollment.intent.origin,
    );
    HostedSignerApproval {
        enrollment,
        proof,
        device_proof: eip191_sign(device, &challenge).unwrap(),
    }
}

async fn rpc(endpoint: &str, method: &str, parameters: Value) -> Value {
    let response: Value = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
        .post(endpoint)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":parameters}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(response.get("error").is_none(), "local RPC failed");
    response["result"].clone()
}

#[tokio::test]
#[ignore = "explicit real-chain CLI qualification; requires prepared contracts, native services and built website"]
async fn local_browser_approval_denials_passkey_login_and_read_only_recovery() {
    let stack = Stack::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    drop(listener);
    let started = stack.success(&[
        "stack",
        "start",
        "--chain-port",
        &port,
        "--website",
        "--web-host",
        "localhost",
    ]);
    let broker_url = started["services"]["services"]["broker"]["url"]
        .as_str()
        .unwrap();
    let origin = started["services"]["services"]["website"]["url"]
        .as_str()
        .unwrap();
    let chain_url = started["chain"]["rpc_http"].as_str().unwrap();
    let owner = stack.success(&["owner", "register", "--name", "alice"]);
    stack.success(&["owner", "register", "--name", "bob"]);
    for name in ["alice", "bob"] {
        stack.success(&["owner", "login", "--name", name, "--broker-url", broker_url]);
    }
    let key = SigningKey::random(&mut rand_core::OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    let device = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let confirmed = device_key_hash(&evm_address(device.verifying_key())).unwrap();
    let broker = BrokerClient::with_client(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .unwrap(),
        broker_url,
    );
    let enrollment = broker
        .local_browser_start(&LocalBrowserStartRequest {
            operator_omni: owner["operator_omni"].as_str().unwrap().into(),
            enrollment: HostedSignerStartRequest {
                credential_id: URL_SAFE_NO_PAD.encode(point.as_bytes()),
                public_key_x: format!("0x{}", hex::encode(point.x().unwrap())),
                public_key_y: format!("0x{}", hex::encode(point.y().unwrap())),
                device_key_hash: confirmed.clone(),
                origin: origin.into(),
                rp_id: "localhost".into(),
            },
        })
        .await
        .unwrap();
    let approval = signed(enrollment.clone(), &key, &device);
    let before = rpc(chain_url, "eth_blockNumber", json!([])).await;
    for (name, fingerprint, expected) in [
        ("bob", confirmed.clone(), "another owner"),
        ("alice", format!("0x{}", "01".repeat(32)), "fingerprint"),
    ] {
        let denied = stack.approve(&approval, name, &fingerprint);
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains(expected));
        assert_eq!(rpc(chain_url, "eth_blockNumber", json!([])).await, before);
    }
    for (field, expected) in [
        ("origin", "website origin"),
        ("expiry", "expired"),
        ("nonce", "stale operator nonce"),
        ("signature", "signature rejected"),
    ] {
        let mut altered = enrollment.clone();
        match field {
            "origin" => altered.intent.origin = "http://localhost:1".into(),
            "expiry" => altered.intent.expires_at = 1,
            "nonce" => altered.intent.operator_nonce = format!("0x{}", "01".repeat(32)),
            _ => {}
        }
        let mut invalid = signed(altered, &key, &device);
        if field == "signature" {
            invalid.proof = assertion(
                &SigningKey::random(&mut rand_core::OsRng),
                &agentkeys_core::browser_enrollment::challenge(&invalid.enrollment.intent).unwrap(),
                &invalid.enrollment.intent.credential_id,
                origin,
            );
        }
        let denied = stack.approve(&invalid, "alice", &confirmed);
        assert!(!denied.status.success());
        assert!(
            String::from_utf8_lossy(&denied.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&denied.stderr)
        );
        assert_eq!(rpc(chain_url, "eth_blockNumber", json!([])).await, before);
    }
    let completed = stack.approve(&approval, "alice", &confirmed);
    assert!(
        completed.status.success(),
        "{}",
        String::from_utf8_lossy(&completed.stderr)
    );
    let receipt: Value = serde_json::from_slice(&completed.stdout).unwrap();
    assert_eq!(receipt["complete"], true);
    assert_eq!(receipt["account"], owner["account"]);
    assert_eq!(receipt["device_key_hash"], confirmed);
    assert!(receipt.get("session_jwt").is_none());
    let login = broker
        .hosted_passkey_start(owner["operator_omni"].as_str().unwrap())
        .await
        .unwrap();
    let browser_session = broker
        .hosted_passkey_finish(&HostedPasskeyVerify {
            challenge: login.challenge.clone(),
            assertion: assertion(
                &key,
                &hex::decode(login.challenge.trim_start_matches("0x")).unwrap(),
                &enrollment.intent.credential_id,
                origin,
            ),
        })
        .await
        .unwrap();
    assert_eq!(
        browser_session.omni_account.trim_start_matches("0x"),
        owner["operator_omni"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x")
    );
    let status = broker
        .hosted_signer_status(
            &browser_session.session_jwt,
            &HostedSignerStatusRequest {
                credential_id: enrollment.intent.credential_id,
                device_key_hash: confirmed.clone(),
            },
        )
        .await
        .unwrap();
    assert!(status.active && status.device_active);
    let recorded_height = rpc(chain_url, "eth_blockNumber", json!([])).await;
    let passkey = stack.state.join("owners/alice/passkey.pem");
    std::fs::rename(&passkey, passkey.with_extension("unavailable")).unwrap();
    let recovered = stack.approve(&approval, "alice", &confirmed);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let recovered: Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(recovered["user_op_hash"], receipt["user_op_hash"]);
    assert_eq!(
        rpc(chain_url, "eth_blockNumber", json!([])).await,
        recorded_height
    );
}
