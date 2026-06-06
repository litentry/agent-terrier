//! Transport-conformance — boots the REAL `agentkeys-mcp-server` binary as a
//! subprocess and drives it as an MCP client over each transport, asserting
//! protocol conformance against the REAL http backend (broker URL from
//! `$CONFORMANCE_BROKER_URL`). This is the Rust replacement for the former
//! bash+python `scripts/mcp-demo-mode-{a,b,c,d,e}.sh` demos (curl / Anthropic
//! SDK / xiaozhi `ServerMCPClient` / WS relay / stdio) — **Rust, no python, real
//! backend, no in-memory fixture** (#207).
//!
//! What it proves (the demos' actual job — transport conformance, backend-
//! agnostic, over the REAL transport + REAL `BackendClient`):
//!   - `initialize` handshake + `serverInfo` + version negotiation
//!   - `tools/list` returns the real tool schemas (a spec-compliant client —
//!     the Anthropic SDK, xiaozhi's `ServerMCPClient`, Claude Desktop — can
//!     discover + drive us)
//!   - HTTP auth gating: wrong bearer → 401, missing actor header → 403
//!   - `permission.check` deterministic deny (local policy engine, no backend)
//!   - a `tools/call` round-trips a WELL-FORMED JSON-RPC frame through the real
//!     http backend (an auth / connection error is still a valid protocol
//!     round-trip — proves the transport carries tool calls + responses)
//!   - the **stdio** stream carries ONLY newline-framed JSON-RPC — no tracing-log
//!     corruption on stdout (the exact bug the stdio demo guarded; logs go to
//!     stderr per `main.rs`)
//!
//! Real-stack vs hermetic: CI (`mcp-server.yml`) sets `CONFORMANCE_BROKER_URL` to
//! a reachable broker, so the `tools/call` traverses the real cap-mint path. The
//! hermetic default points at an unreachable port, so the round-trip is a
//! well-formed connection error — the protocol assertions hold with ZERO external
//! deps (this file runs green under a plain `cargo test`).

use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{sleep, timeout};

const BIN: &str = env!("CARGO_BIN_EXE_agentkeys-mcp-server");
const ACTOR: &str = "0xa0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c701a0c7";
const VENDOR_TOKEN: &str = "conformance-tok";

/// Real-stack: CI sets this to a reachable broker. Hermetic default: an
/// unreachable port (discard) so a `tools/call` is a well-formed connection
/// error rather than a hang — the transport/protocol assertions still hold.
fn broker_url() -> String {
    std::env::var("CONFORMANCE_BROKER_URL").unwrap_or_else(|_| "http://127.0.0.1:9".to_string())
}

/// Bind :0, read the assigned port, release it. Small TOCTOU window, fine for a
/// test launcher (the server re-binds immediately after).
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

// ───────────────────────── HTTP transport ──────────────────────────────────

#[tokio::test]
async fn http_transport_conformance() {
    let port = free_port().await;
    let listen = format!("127.0.0.1:{port}");
    let base = format!("http://{listen}");

    let mut child = Command::new(BIN)
        .args([
            "--transport",
            "http",
            "--backend",
            "http",
            "--broker-url",
            &broker_url(),
            "--listen",
            &listen,
            "--vendor-tokens",
            &format!("conformance:{VENDOR_TOKEN}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn agentkeys-mcp-server (http)");

    let client = reqwest::Client::new();

    // Wait for /healthz (the server binds + is ready within ~1s, give it 10s).
    let mut healthy = false;
    for _ in 0..100 {
        if let Ok(r) = client.get(format!("{base}/healthz")).send().await {
            if r.status().is_success() {
                healthy = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(healthy, "mcp-server did not become healthy on {base}");

    let rpc = |body: Value| {
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .post(format!("{base}/mcp"))
                .header("authorization", format!("Bearer {VENDOR_TOKEN}"))
                .header("x-agentkeys-actor", ACTOR)
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .expect("POST /mcp")
        }
    };

    // 1. initialize — handshake + version negotiation (echoes the client's
    //    "2024-11-05" when sent) + serverInfo.
    let resp = rpc(json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05"}
    }))
    .await;
    assert!(resp.status().is_success(), "initialize HTTP status");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(
        v["result"]["protocolVersion"],
        json!("2024-11-05"),
        "version negotiated"
    );
    assert_eq!(
        v["result"]["serverInfo"]["name"],
        json!("agentkeys-mcp-server"),
        "serverInfo.name"
    );

    // 2. tools/list — the real tool schemas a spec client discovers.
    let resp = rpc(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await;
    let v: Value = resp.json().await.unwrap();
    let names: Vec<String> = v["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    for expected in [
        "agentkeys.identity.whoami",
        "agentkeys.memory.get",
        "agentkeys.memory.put",
        "agentkeys.cap.mint",
        "agentkeys.permission.check",
        "agentkeys.audit.append",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "tools/list missing {expected}: {names:?}"
        );
    }

    // 3. auth gating — wrong bearer → 401, missing actor header → 403. These are
    //    enforced at the MCP server's transport layer, before any backend call.
    let wrong_bearer = client
        .post(format!("{base}/mcp"))
        .header("authorization", "Bearer nope")
        .header("x-agentkeys-actor", ACTOR)
        .json(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_bearer.status().as_u16(), 401, "wrong bearer → 401");

    let no_actor = client
        .post(format!("{base}/mcp"))
        .header("authorization", format!("Bearer {VENDOR_TOKEN}"))
        .json(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        no_actor.status().as_u16(),
        403,
        "missing actor header → 403"
    );

    // 4. permission.check — deterministic deny (600 RMB over the 500 default
    //    cap). Pure local policy engine; proves a tools/call routes + computes
    //    with no backend dependency.
    let resp = rpc(json!({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "agentkeys.permission.check", "arguments":
            {"actor": ACTOR, "scope": "payment.spend", "params": {"amount_rmb": 600}}}
    }))
    .await;
    let v: Value = resp.json().await.unwrap();
    assert_eq!(
        v["result"]["structuredContent"]["verdict"],
        json!("deny"),
        "over-cap payment denied: {v}"
    );

    // 5. a backend-touching tools/call (memory.get) round-trips a WELL-FORMED
    //    JSON-RPC frame over the real http backend. Against an unreachable /
    //    unauth'd broker the app result is an error — that is STILL a valid
    //    protocol round-trip (the transport carried the call + a structured
    //    response). We assert well-formedness, not specific data.
    let resp = rpc(json!({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "agentkeys.memory.get", "arguments":
            {"actor": ACTOR, "namespace": "travel"}}
    }))
    .await;
    assert!(
        resp.status().is_success(),
        "tools/call HTTP status (JSON-RPC carries app errors in-band)"
    );
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["jsonrpc"], json!("2.0"), "well-formed JSON-RPC envelope");
    assert_eq!(v["id"], json!(6), "id echoed");
    assert!(
        v.get("result").is_some() || v.get("error").is_some(),
        "round-trip has a result OR a structured error: {v}"
    );

    let _ = child.kill().await;
}

// ───────────────────────── stdio transport ─────────────────────────────────

/// Read one newline-framed response line from the server's stdout and assert it
/// parses as PURE JSON-RPC. If a tracing log ever leaked onto stdout, `from_str`
/// fails here (Claude Desktop / Codex CLI would disconnect on a corrupt stream).
async fn read_json_line(
    lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) -> Value {
    let line = timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("stdio response within 10s")
        .expect("read stdout line")
        .expect("a response line (server did not hang up)");
    serde_json::from_str(&line).unwrap_or_else(|e| {
        panic!("stdout line MUST be pure JSON-RPC (no log corruption): {e}\nline: {line:?}")
    })
}

#[tokio::test]
async fn stdio_transport_is_clean_jsonrpc() {
    let mut child = Command::new(BIN)
        .args([
            "--transport",
            "stdio",
            "--backend",
            "http",
            "--broker-url",
            &broker_url(),
            "--vendor-tokens",
            &format!("conformance:{VENDOR_TOKEN}"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // tracing logs go HERE, never to stdout (the proof)
        .kill_on_drop(true)
        .spawn()
        .expect("spawn agentkeys-mcp-server (stdio)");

    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    // initialize
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}\n")
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let v = read_json_line(&mut lines).await;
    assert_eq!(v["id"], json!(1), "stdio initialize id echoed");
    assert_eq!(
        v["result"]["serverInfo"]["name"],
        json!("agentkeys-mcp-server"),
        "stdio serverInfo.name"
    );

    // tools/list
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n")
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let v = read_json_line(&mut lines).await;
    let names: Vec<String> = v["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    assert!(
        names.iter().any(|n| n == "agentkeys.memory.get"),
        "stdio tools/list missing agentkeys.memory.get: {names:?}"
    );

    let _ = child.kill().await;
}
