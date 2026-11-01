use assert_cmd::Command;
use predicates::str::contains;

fn isolated_command(directory: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("agentkeys").unwrap();
    command.env_clear().env("HOME", directory);
    command
}

#[test]
fn removed_storage_backends_and_flags_fail_before_loading_state() {
    let directory = tempfile::tempdir().unwrap();
    isolated_command(directory.path())
        .args(["local", "--help"])
        .assert()
        .success()
        .stdout(contains("credential"));
    for backend in ["s3", "S3", "unknown"] {
        isolated_command(directory.path())
            .args(["--credential-backend", backend, "whoami"])
            .assert()
            .failure()
            .stderr(contains("unknown --credential-backend"));
    }
    isolated_command(directory.path())
        .env("AGENTKEYS_CREDENTIAL_BACKEND", "s3")
        .arg("whoami")
        .assert()
        .failure()
        .stderr(contains("unknown --credential-backend"));
    for option in ["--bucket", "--envelope-version"] {
        isolated_command(directory.path())
            .args([option, "unused", "whoami"])
            .assert()
            .failure()
            .stderr(contains("unexpected argument"));
    }
    isolated_command(directory.path())
        .args(["speech", "creds"])
        .assert()
        .failure()
        .stderr(contains("unrecognized subcommand 'speech'"));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
