//! Write the canonical broker/worker protocol fixtures to disk.
//!
//! ```text
//! cargo run -p agentkeys-backend-client --bin dump-protocol-fixtures
//! cargo run -p agentkeys-backend-client --bin dump-protocol-fixtures -- --check
//! ```
//!
//! Default: (re)writes `e2e/fixtures/backend-protocol/<name>.json` from the
//! serde types in `agentkeys_backend_client::protocol`. `--check` instead
//! verifies the on-disk files match what the types would emit and exits non-zero
//! on any drift (so CI fails if a struct changed without regenerating). The
//! output dir can be overridden with `--out <dir>` (default resolves to the
//! repo's `e2e/fixtures/backend-protocol`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agentkeys_backend_client::fixtures::canonical_fixtures;

fn default_out_dir() -> PathBuf {
    // This bin lives at crates/agentkeys-backend-client/src/bin/, so the repo
    // root is three parents up from CARGO_MANIFEST_DIR.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("e2e/fixtures/backend-protocol"))
        .unwrap_or_else(|| PathBuf::from("e2e/fixtures/backend-protocol"))
}

fn pretty(body: &serde_json::Value) -> String {
    let mut s = serde_json::to_string_pretty(body).expect("fixture serializes");
    s.push('\n');
    s
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check = args.iter().any(|a| a == "--check");
    let out_dir = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(default_out_dir);

    if !check {
        if let Err(e) = std::fs::create_dir_all(&out_dir) {
            eprintln!("fail: create {}: {e}", out_dir.display());
            return ExitCode::FAILURE;
        }
    }

    let mut drift = false;
    for f in canonical_fixtures() {
        let path = out_dir.join(format!("{}.json", f.name));
        let want = pretty(&f.body);
        if check {
            match std::fs::read_to_string(&path) {
                Ok(got) if got == want => println!("ok   {}", path.display()),
                Ok(_) => {
                    eprintln!("fail DRIFT {} — run `cargo run -p agentkeys-backend-client --bin dump-protocol-fixtures` and commit", path.display());
                    drift = true;
                }
                Err(e) => {
                    eprintln!("fail MISSING {} ({e})", path.display());
                    drift = true;
                }
            }
        } else {
            match std::fs::write(&path, &want) {
                Ok(()) => println!("wrote {}", path.display()),
                Err(e) => {
                    eprintln!("fail: write {}: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    if check && drift {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
