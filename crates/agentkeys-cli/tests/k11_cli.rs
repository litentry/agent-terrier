use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

fn isolated_cmd() -> (Command, TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::cargo_bin("agentkeys").unwrap();
    command
        .env("HOME", directory.path())
        .env("AGENTKEYS_CHAIN", "anvil")
        .env("AGENT_TERRIER_LOCAL_DEV", "1")
        .env_remove("AGENTKEYS_CHAIN_PROFILE_FILE")
        .env_remove("AGENTKEYS_CHAIN_RPC_HTTP")
        .env_remove("AGENTKEYS_CHAIN_RPC_HTTP_ANVIL")
        .env_remove("AGENTKEYS_K11_STUB")
        .env_remove("AGENTKEYS_ALLOW_STAGE1_STUBS")
        .args(["--backend", "http://localhost:0"]);
    (command, directory)
}

fn enroll(command: &mut Command) {
    command.args([
        "k11",
        "enroll",
        "--operator-omni",
        &format!("0x{}", "a".repeat(64)),
    ]);
}

#[test]
fn stub_requires_explicit_opt_in() {
    let (mut command, directory) = isolated_cmd();
    enroll(&mut command);
    command
        .assert()
        .failure()
        .stderr(contains("AGENTKEYS_K11_STUB"));
    assert!(!directory.path().join(".agentkeys/k11").exists());
}

#[test]
fn explicitly_enabled_local_stub_enrolls_and_asserts() {
    let (mut command, _directory) = isolated_cmd();
    command.env("AGENTKEYS_K11_STUB", "1");
    enroll(&mut command);
    command.assert().success().stdout(contains("stage1-stub"));
    let (mut command, _directory) = isolated_cmd();
    command.env("AGENTKEYS_K11_STUB", "1").args([
        "k11",
        "assert",
        "--operator-omni",
        &format!("0x{}", "a".repeat(64)),
        "--message-hex",
        "deadbeef",
    ]);
    command
        .assert()
        .success()
        .stdout(contains("0x7374616765312d6b31312d737475623a"));
}

#[test]
fn stub_without_local_development_marker_cannot_write_credentials() {
    let (mut command, directory) = isolated_cmd();
    command
        .env("AGENTKEYS_K11_STUB", "1")
        .env_remove("AGENT_TERRIER_LOCAL_DEV");
    enroll(&mut command);
    command
        .assert()
        .failure()
        .stderr(contains("development signing requires"));
    assert!(!directory.path().join(".agentkeys/k11").exists());
}

#[test]
fn remote_custom_profile_cannot_be_overridden_by_anvil_name_or_legacy_opt_in() {
    let (mut command, directory) = isolated_cmd();
    let mut profile = agentkeys_core::chain_profile::ChainProfile::load_builtin("anvil").unwrap();
    profile.chain_kind = agentkeys_core::chain_profile::ChainKind::EthereumL1;
    let path = directory.path().join("remote.json");
    std::fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
    command
        .env("AGENTKEYS_CHAIN_PROFILE_FILE", path)
        .env("AGENTKEYS_K11_STUB", "1")
        .env("AGENTKEYS_ALLOW_STAGE1_STUBS", "1")
        .args(["--chain", "anvil"]);
    enroll(&mut command);
    command
        .assert()
        .failure()
        .stderr(contains("development signing requires"));
    assert!(!directory.path().join(".agentkeys/k11").exists());
}

#[test]
fn software_keygen_needs_local_marker_and_does_not_touch_existing_file_on_denial() {
    let (mut command, directory) = isolated_cmd();
    let key_path = directory.path().join("test-passkey.pem");
    std::fs::write(&key_path, "existing canary").unwrap();
    command
        .env_remove("AGENT_TERRIER_LOCAL_DEV")
        .args(["k11", "software-keygen", "--key-file"])
        .arg(&key_path);
    command
        .assert()
        .failure()
        .stderr(contains("development signing requires"));
    assert_eq!(
        std::fs::read_to_string(key_path).unwrap(),
        "existing canary"
    );
}

#[test]
fn remote_rpc_override_cannot_create_a_development_key() {
    for variable in ["AGENTKEYS_CHAIN_RPC_HTTP", "AGENTKEYS_CHAIN_RPC_HTTP_ANVIL"] {
        let (mut command, directory) = isolated_cmd();
        let key_path = directory.path().join("test-passkey.pem");
        command
            .env(variable, "https://rpc.example.test")
            .args(["k11", "software-keygen", "--key-file"])
            .arg(&key_path);
        command
            .assert()
            .failure()
            .stderr(contains("development signing requires"));
        assert!(!key_path.exists());
    }
}

#[test]
fn software_sign_is_fenced_before_key_file_access() {
    let (mut command, directory) = isolated_cmd();
    command
        .env_remove("AGENT_TERRIER_LOCAL_DEV")
        .args(["k11", "software-sign", "--key-file"])
        .arg(directory.path().join("missing.pem"))
        .args(["--userop-hash", &format!("0x{}", "b".repeat(64))]);
    command
        .assert()
        .failure()
        .stderr(contains("development signing requires"));
}

#[test]
fn local_software_keygen_emits_public_coordinates_only() {
    let (mut command, directory) = isolated_cmd();
    let key_path = directory.path().join("test-passkey.pem");
    command
        .args(["k11", "software-keygen", "--key-file"])
        .arg(&key_path);
    let output = command.assert().success().get_output().stdout.clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("PUBX=0x"));
    assert!(stdout.contains("RPIDHASH=0x"));
    assert!(!stdout.contains("PRIVATE"));
    assert!(key_path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn explicit_unknown_chain_does_not_fall_back_to_local_default() {
    let (mut command, directory) = isolated_cmd();
    command
        .env("AGENTKEYS_K11_STUB", "1")
        .args(["--chain", "unknown-chain"]);
    enroll(&mut command);
    command
        .assert()
        .failure()
        .stderr(contains("unknown chain profile"));
    assert!(!directory.path().join(".agentkeys/k11").exists());
}

#[cfg(unix)]
#[test]
fn software_keys_reject_public_permissions_and_links_without_changing_the_key() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (mut command, directory) = isolated_cmd();
    let key_path = directory.path().join("passkey.pem");
    command
        .args(["k11", "software-keygen", "--key-file"])
        .arg(&key_path);
    command.assert().success();
    let original = std::fs::read(&key_path).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(agentkeys_cli::k11_webauthn::software_webauthn_keygen(
        key_path.to_str().unwrap(),
        "localhost"
    )
    .is_err());
    assert!(agentkeys_cli::k11_webauthn::software_webauthn_sign(
        key_path.to_str().unwrap(),
        &format!("0x{}", "b".repeat(64)),
        "localhost"
    )
    .is_err());
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link_path = directory.path().join("link.pem");
    symlink(&key_path, &link_path).unwrap();
    assert!(agentkeys_cli::k11_webauthn::software_webauthn_keygen(
        link_path.to_str().unwrap(),
        "localhost"
    )
    .is_err());
    let hardlink_path = directory.path().join("hardlink.pem");
    std::fs::hard_link(&key_path, &hardlink_path).unwrap();
    assert!(agentkeys_cli::k11_webauthn::software_webauthn_keygen(
        key_path.to_str().unwrap(),
        "localhost"
    )
    .is_err());
    assert_eq!(std::fs::read(key_path).unwrap(), original);
}
