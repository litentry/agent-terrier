#![cfg(unix)]

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agentkeys_core::chain_profile::ChainProfile;
use p256::pkcs8::EncodePublicKey;

fn refused(directory: &Path, arguments: &[&str]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentkeys-local-signer"))
        .env_clear()
        .env(
            "DEV_KEY_SERVICE_MASTER_SECRET",
            "synthetic-ambient-secret-must-not-enable-signing",
        )
        .args([
            "--profile",
            directory.join("profile.json").to_str().unwrap(),
            "--broker-public-key",
            directory.join("broker.pem").to_str().unwrap(),
            "--master-secret-file",
            directory.join("master.key").to_str().unwrap(),
        ])
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("invalid signer configuration unexpectedly started a service");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(!diagnostic.contains("synthetic-ambient-secret"));
    diagnostic
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let profile = ChainProfile::load_builtin("anvil").unwrap();
    std::fs::write(
        directory.path().join("profile.json"),
        serde_json::to_vec(&profile).unwrap(),
    )
    .unwrap();
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    std::fs::write(
        directory.path().join("broker.pem"),
        signing_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap(),
    )
    .unwrap();
    directory
}

#[test]
fn explicit_development_and_loopback_are_required_before_loading_secrets() {
    let directory = fixture();
    assert!(refused(directory.path(), &[]).contains("development"));
    assert!(refused(
        directory.path(),
        &["--development", "--listen", "0.0.0.0:0"]
    )
    .contains("loopback"));
    let path = directory.path().join("profile.json");
    let mut profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    profile["rpc"]["http"] = serde_json::json!("https://example.invalid");
    std::fs::write(path, serde_json::to_vec(&profile).unwrap()).unwrap();
    assert!(refused(directory.path(), &["--development"]).contains("development"));
}

#[test]
fn missing_unsafe_or_malformed_original_keys_never_start_or_regenerate() {
    let directory = fixture();
    let path = directory.path().join("master.key");
    refused(directory.path(), &["--development"]);
    assert!(!path.exists());
    let original = "synthetic-invalid-key-canary";
    agentkeys_core::protected_file::write(path.to_str().unwrap(), original.as_bytes(), true)
        .unwrap();
    let diagnostic = refused(directory.path(), &["--development"]);
    assert!(diagnostic.contains("32 hex-encoded bytes"));
    assert!(!diagnostic.contains(original));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(refused(directory.path(), &["--development"]).contains("owner-only"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let original_path = directory.path().join("original.key");
    std::fs::rename(&path, &original_path).unwrap();
    symlink(&original_path, &path).unwrap();
    refused(directory.path(), &["--development"]);
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&original_path, &path).unwrap();
    assert!(refused(directory.path(), &["--development"]).contains("no hard links"));
    assert_eq!(std::fs::read_to_string(original_path).unwrap(), original);
}
