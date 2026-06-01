//! End-to-end `agentkeys k11 ...` subcommand tests.
//!
//! Codex review pass 2 flagged that the prior k11 module tests only
//! verified the underlying functions; this file proves the clap
//! subcommand actually parses + dispatches.

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

fn test_omni() -> String {
    format!("0x{}", "a".repeat(64))
}

/// An `agentkeys` `Command` with `HOME` rooted at a throwaway tempdir. The
/// subprocess's k11 enrollment writes to `$HOME/.agentkeys/k11/<omni>.json`
/// (see `enroll()` → `k11_dir()` in `src/k11.rs`), so without this every run would
/// pollute the developer's real home and leave a stale `<omni>.json` behind —
/// the same shared-FS-path smell that flaked `k11::tests::enroll_writes_file_*`.
/// Keep the returned `TempDir` in scope until after `cmd.assert()`; dropping it
/// deletes the directory mid-run.
fn isolated_cmd() -> (Command, TempDir) {
    let home = tempfile::tempdir().expect("create temp HOME");
    let mut cmd = Command::cargo_bin("agentkeys").expect("agentkeys binary");
    cmd.env("HOME", home.path());
    (cmd, home)
}

#[test]
fn k11_enroll_stub_mode_emits_json() {
    let omni = test_omni();
    let (mut cmd, _home) = isolated_cmd();
    // Stub mode is the default; explicitly set AGENTKEYS_K11_STUB=1 to be
    // resilient to env leaks from CI.
    cmd.env("AGENTKEYS_K11_STUB", "1")
        // Stub mode is dev-chain-only without explicit opt-in
        // (arch.md §22b.1 fail-loud on mainnet).
        .env("AGENTKEYS_CHAIN", "heima-paseo")
        // The `backend` top-level CLI flag is required for the CLI to
        // parse, even though k11 doesn't use it. Hand it a dummy.
        .arg("--backend")
        .arg("http://localhost:0")
        .arg("k11")
        .arg("enroll")
        .arg("--operator-omni")
        .arg(&omni);
    cmd.assert()
        .success()
        .stdout(contains("\"mode\": \"stage1-stub\""))
        .stdout(contains(&omni));
}

#[test]
fn k11_assert_stub_mode_emits_hex() {
    let omni = test_omni();
    let (mut cmd, _home) = isolated_cmd();
    cmd.env("AGENTKEYS_K11_STUB", "1")
        // Stub mode is dev-chain-only without explicit opt-in
        // (arch.md §22b.1 fail-loud on mainnet).
        .env("AGENTKEYS_CHAIN", "heima-paseo")
        .arg("--backend")
        .arg("http://localhost:0")
        .arg("k11")
        .arg("assert")
        .arg("--operator-omni")
        .arg(&omni)
        .arg("--message-hex")
        .arg("deadbeef");
    cmd.assert()
        .success()
        // Stage-1 stub assertion starts with `"stage1-k11-stub:"` ASCII =
        // hex `7374616765312d6b31312d737475623a` (16 chars × 2 hex each).
        .stdout(contains("0x7374616765312d6b31312d737475623a"));
}

#[test]
fn k11_non_stub_mode_without_webauthn_errors_with_actionable_hint() {
    // AGENTKEYS_K11_STUB=0 + no --webauthn → error pointing at the two
    // ways to proceed (either pass --webauthn or set STUB=1). Real
    // ceremony lives behind --webauthn (no more "stage 2 not shipped").
    let omni = test_omni();
    let (mut cmd, _home) = isolated_cmd();
    cmd.env("AGENTKEYS_K11_STUB", "0")
        .env("AGENTKEYS_CHAIN", "heima-paseo")
        .arg("--backend")
        .arg("http://localhost:0")
        .arg("k11")
        .arg("enroll")
        .arg("--operator-omni")
        .arg(&omni);
    cmd.assert()
        .failure()
        .stderr(contains("--webauthn"))
        .stderr(contains("AGENTKEYS_K11_STUB"));
}

#[test]
fn k11_stub_mode_on_mainnet_hard_errors_without_opt_in() {
    // Codex audit fix: AGENTKEYS_CHAIN=heima + stub mode + no opt-in must
    // HARD ERROR (not just warn) so operators can't silently sign master
    // mutations against mainnet with stub bytes.
    let omni = test_omni();
    let (mut cmd, _home) = isolated_cmd();
    cmd.env("AGENTKEYS_K11_STUB", "1")
        .env("AGENTKEYS_CHAIN", "heima")
        .env_remove("AGENTKEYS_ALLOW_STAGE1_STUBS")
        .arg("--backend")
        .arg("http://localhost:0")
        .arg("k11")
        .arg("enroll")
        .arg("--operator-omni")
        .arg(&omni);
    cmd.assert()
        .failure()
        .stderr(contains("permitted on chain=heima"))
        .stderr(contains("AGENTKEYS_ALLOW_STAGE1_STUBS"));
}

#[test]
fn k11_stub_mode_on_mainnet_opt_in_warns_but_succeeds() {
    // With explicit opt-in, mainnet stub mode is allowed but loudly
    // warned. For staging / smoke tests against mainnet that can't yet
    // use Touch ID (CI runners, headless boxes).
    let omni = test_omni();
    let (mut cmd, _home) = isolated_cmd();
    cmd.env("AGENTKEYS_K11_STUB", "1")
        .env("AGENTKEYS_CHAIN", "heima")
        .env("AGENTKEYS_ALLOW_STAGE1_STUBS", "1")
        .arg("--backend")
        .arg("http://localhost:0")
        .arg("k11")
        .arg("enroll")
        .arg("--operator-omni")
        .arg(&omni);
    cmd.assert()
        .success()
        .stderr(contains("WARN"))
        .stdout(contains("\"mode\": \"stage1-stub\""));
}

#[test]
fn k11_assert_rejects_invalid_omni() {
    let (mut cmd, _home) = isolated_cmd();
    cmd.env("AGENTKEYS_K11_STUB", "1")
        // Stub mode is dev-chain-only without explicit opt-in
        // (arch.md §22b.1 fail-loud on mainnet).
        .env("AGENTKEYS_CHAIN", "heima-paseo")
        .arg("--backend")
        .arg("http://localhost:0")
        .arg("k11")
        .arg("assert")
        .arg("--operator-omni")
        .arg("0xabc") // too short
        .arg("--message-hex")
        .arg("00");
    cmd.assert().failure().stderr(contains("64-hex"));
}
