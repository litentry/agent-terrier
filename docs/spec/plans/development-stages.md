# AgentKeys v0 — Development Staging Plan

**Date:** 2026-04-09
**Source:** `ceo-plan.md`, `eng-review-test-plan.md`, `credential-backend-interface.md`, `architecture.md`
**Harness design:** Informed by [Anthropic's harness design for long-running apps](https://www.anthropic.com/engineering/harness-design-long-running-apps)

---

## Harness Principles Applied

From the Anthropic article, adapted for AgentKeys:

1. **Decomposition over single-pass.** Each stage is a self-contained sprint with its own deliverables, tests, and "what done means." A fresh agent can pick up any stage with just the stage contract and the prior stage's artifacts.
2. **Generator-Evaluator separation.** The developer (or agent) implements. The test suite evaluates. Unit tests validate internals. E2E tests validate behavior from the user's perspective. No self-grading.
3. **Sprint contracts.** Each stage starts with a contract: inputs (what exists), outputs (what ships), and acceptance criteria (hard pass/fail tests). A stage is not done until every criterion passes.
4. **File-based handoffs.** Stages communicate via compiled artifacts (crates, binaries, running services), not conversational context. Any agent can resume from a stage boundary.
5. **Hard thresholds, not vibes.** Every stage has `cargo test` unit tests + a reviewer E2E checklist with concrete commands to run. If any test fails, the stage is not done.
6. **Stress-test assumptions.** Each stage's tests verify the design assumptions from the plan docs (e.g., "memfd_secret works on this kernel" is a test, not an assumption).

### Concrete harness artifacts (required per stage)

Per [Anthropic's harness design for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents), abstract principles are not enough — the staged process needs **concrete, machine-readable artifact files** that make it actually resumable across agent contexts. Each stage MUST produce or update:

1. **`harness/init.sh`** — a single script that bootstraps the development environment for the current stage. A fresh agent runs `bash harness/init.sh <stage-number>` and gets: all prior-stage artifacts built, dependencies installed, mock backend running (if applicable), and the working directory set up. This is the entry point for any new context. Each stage extends `init.sh` with its own setup steps rather than overwriting it.

2. **`harness/progress.json`** — machine-readable progress log. Updated atomically at each stage boundary. Schema:
   ```json
   {
     "current_stage": 2,
     "stages": {
       "0": {"status": "complete", "completed_at": "2026-04-10T14:00:00Z", "tests_passed": 8, "tests_total": 8},
       "1": {"status": "complete", "completed_at": "2026-04-12T09:30:00Z", "tests_passed": 37, "tests_total": 37},
       "2": {"status": "in_progress", "started_at": "2026-04-12T10:00:00Z", "deliverables_done": ["cli_init", "cli_store"], "deliverables_remaining": ["cli_read", "cli_revoke", "cli_usage"]}
     }
   }
   ```
   A resuming agent reads this file first to know where to start. No free-form editing — use `jq` or equivalent for atomic updates.

3. **`harness/features.json`** — machine-readable feature list tracking what's been built. Agents update incrementally (append-only for new features, toggle `implemented: true` for completed ones) rather than regenerating from scratch. Schema:
   ```json
   {
     "features": [
       {"name": "create_session", "stage": 1, "implemented": true, "test": "session::create_valid"},
       {"name": "read_credential", "stage": 1, "implemented": true, "test": "credential::read_valid"},
       {"name": "cli_init", "stage": 2, "implemented": true, "test": "cli::init_creates_session"},
       {"name": "pair_flow", "stage": 4, "implemented": false, "test": "pair::full_e2e"}
     ]
   }
   ```
   This is the source of truth for "what can I call right now?" across agent handoffs.

4. **`harness/stage-N-done.sh`** — per-stage completion verifier. Runs all tests for stage N and outputs a pass/fail verdict. A stage is not "done" until `bash harness/stage-N-done.sh` exits 0. This is the harness's evaluator — the agent writes code, then runs this script to see if it passes. No self-grading.

5. **Git commit discipline** — per [Anthropic's harness design](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents), git history is a load-bearing resumability mechanism alongside the artifact files above. Concrete requirements:

   - **`harness/init.sh` creates an initial commit** when bootstrapping a fresh repo: `git add -A && git commit -m "harness: stage N init"`. This gives the next session a clean baseline to `git diff` against.
   - **Every coding session leaves atomic commits** per deliverable, not one giant commit at the end. Format: `agentkeys: stage N — <deliverable name>` (e.g., `agentkeys: stage 1 — rendezvous endpoints`). This lets a resuming agent run `git log --oneline -20` and see exactly what was built, what order, and where work stopped.
   - **Stage completion gets a tagged commit:** `git tag stage-N-done` after `harness/stage-N-done.sh` exits 0. A fresh session can `git log stage-N-done..HEAD` to see only the work since the last completed stage.
   - **`harness/progress.json` is committed atomically** with the stage-done tag — never out of sync with the code state.
   - **A resuming agent's first action** is `git log --oneline -10 && cat harness/progress.json && bash harness/init.sh <current-stage>`. Git history plus progress notes is what lets fresh sessions get oriented quickly — the article explicitly treats this pair as the handoff mechanism, not just the files alone.

**Why these artifacts + git discipline matter together:** without them, "file-based handoffs" is aspirational. A new agent context has no way to know what's already built, what's tested, what failed last time, or how to reproduce the environment. The five elements above (init.sh, progress.json, features.json, stage-N-done.sh, and git commit discipline) make the plan actually executable by long-running agents, not just readable by humans.

---

## Dependency Graph

```
Stage 0: Types + Core Trait
    │
    ├──► Stage 1: Mock Backend
    │        │
    │        ├──► Stage 2: CLI Core
    │        │        │
    │        │        ├──► Stage 4: Pair/Approve Flow
    │        │        │        │
    │        │        │        ├──► Stage 5: Provisioner
    │        │        │        │        │
    │        │        │        │        ├──► Stage 6: npm Package + DX Polish
    │        │        │        │        │
    │        │        │        │        └──► Stage 7: Full E2E
    │        │        │        │
    │        ├──► Stage 3: Daemon + MCP ──┘
    │
    └──► (all stages depend on Stage 0)
```

**Parallelizable:** Stages 2 and 3 can run in parallel after Stage 1. **Stage 6 requires Stage 5** (not Stage 3 — the npm package ships `--recover` which depends on Stage 4's pair/approve flow, and bundles the provisioner binary from Stage 5). The Stage 6 contract confirms this: "Inputs: Stages 0-5."

---

## Stage 0: Foundation — Types + Core Trait

**Goal:** Define the shared types and the `CredentialBackend` trait that every other crate depends on.

### Crates
- `agentkeys-types` — `Identity`, `Session`, `Scope`, `WalletAddress`, `AgentIdentity`, `ServiceName`, `PairCode`, `AuthRequestId`, `AuthRequestType`, `CanonicalBytes`
- `agentkeys-core` — `CredentialBackend` trait, `PaymentRail` trait, `PaymentLayer` enum, canonical CBOR serialization for `AuthRequestType`, HMAC-based OTP derivation, `MockHttpClient` (HTTP client that will talk to the mock backend)

### Deliverables
- [ ] `agentkeys-types/src/lib.rs` compiles with all types exported
- [ ] `agentkeys-core/src/backend.rs` — `CredentialBackend` trait with **all 15 methods** per `credential-backend-interface.md`: 8 base (`create_session`, `create_child_session`, `store_credential`, `read_credential`, `query_audit`, `revoke_session`, `teardown_agent`, `shielding_key`) + 3 rendezvous (`register_rendezvous`, `poll_rendezvous`, `deliver_rendezvous`) + 4 auth-request (`open_auth_request`, `fetch_auth_request`, `approve_auth_request`, `await_auth_decision`)
- [ ] `agentkeys-core/src/payment.rs` — `PaymentRail` trait with `PaymentLayer::SystemGas` / `ServicePayment`
- [ ] `agentkeys-core/src/auth_request.rs` — `AuthRequestType` enum (Pair, Recover, ScopeChange, HighValueRelease, KeyRotate), `AgentIdentity` enum, canonical CBOR serialization
- [ ] `agentkeys-core/src/otp.rs` — OTP derivation from nonce + canonical request details
- [ ] `agentkeys-core/src/mock_client.rs` — HTTP client struct (methods stubbed, not yet connected to a real server)
- [ ] `agentkeys-core/tests/auth_request_vectors.json` — canonical CBOR test vectors for every `AuthRequestType` variant

### Unit Tests
```
cargo test -p agentkeys-types    # all types serialize/deserialize
cargo test -p agentkeys-core     # trait compiles, CBOR round-trip, OTP determinism
```

| Test | What it validates |
|---|---|
| `types::session_serialize_roundtrip` | Session, Scope, WalletAddress survive serde round-trip |
| `types::agent_identity_variants` | AgentIdentity::Alias, Email, Ens, WalletAddress all construct and match |
| `auth_request::cbor_determinism` | Given fixed nonce + fixed request, canonical CBOR output is byte-identical across runs |
| `auth_request::cbor_vectors` | Every variant in `auth_request_vectors.json` produces the expected canonical bytes |
| `otp::determinism` | Given fixed nonce + canonical bytes, OTP is identical across runs |
| `otp::different_requests_different_otps` | Two requests with different details produce different OTPs (even if nonces collide, the HMAC input differs) |
| `trait::compiles` | A dummy struct implementing `CredentialBackend` compiles (compile-time contract check) |
| `payment::layer_enum` | `PaymentLayer::SystemGas` and `ServicePayment` are distinct |

### Reviewer E2E Checklist
```bash
cd agentkeys
cargo build -p agentkeys-types -p agentkeys-core    # compiles clean
cargo test -p agentkeys-types -p agentkeys-core      # all tests pass
cargo doc -p agentkeys-core --no-deps                 # trait docs render
```

### Stage Contract
- **Inputs:** None (first stage)
- **Outputs:** Two crates that compile and pass tests. The `CredentialBackend` trait is the primary artifact — it IS the API contract for all downstream work.
- **Done when:** `cargo test` passes, `cargo doc` renders, all `auth_request_vectors.json` test vectors pass.

---

## Stage 1: Mock Backend

**Goal:** A running HTTP server that implements the `CredentialBackend` trait over REST. This is the first thing that can actually store and retrieve data.

### Crate
- `agentkeys-mock-server` — Rust binary, `axum` + `rusqlite`

### Deliverables
- [ ] SQLite schema: `accounts`, `sessions`, `credentials`, `audit_log`, `rendezvous_registrations`, `auth_requests`, **`identity_links`** tables. The `identity_links` table backs `POST /identity/link` and `GET /identity/resolve` — stores `(wallet_address, identity_type, identity_value)` tuples for `AgentIdentity::Alias`, `Email`, `Ens` → `WalletAddress` resolution. Without this table, recovery-by-alias/email has no persistence model and test #25 (`identity::link_and_resolve`) + test #35 (`recover_flow_e2e`) cannot pass.
- [ ] REST endpoints implementing every `CredentialBackend` trait method:

| Endpoint | Trait Method | What it does |
|---|---|---|
| `POST /session/create` | `create_session` | Google OAuth token → account + session + mock wallet |
| `POST /session/child` | `create_child_session` | Mint scoped child session |
| `POST /credential/store` | `store_credential` | Store encrypted credential blob |
| `GET /credential/read` | `read_credential` | Fetch credential (scope-enforced) |
| `GET /audit/query` | `query_audit` | Query audit log |
| `POST /session/revoke` | `revoke_session` | Kill a session immediately |
| `DELETE /credential/teardown` | `teardown_agent` | Delete all credentials + revoke sessions |
| `GET /shielding-key` | `shielding_key` | Return mock shielding public key |
| `POST /rendezvous/register` | `register_rendezvous` | Daemon registers pair intent |
| `GET /rendezvous/poll` | `poll_rendezvous` | Daemon long-polls for pair payload |
| `POST /rendezvous/deliver` | `deliver_rendezvous` | CLI delivers encrypted pair payload |
| `POST /auth-request/open` | `open_auth_request` | Child opens an auth request, gets OTP + pair code |
| `GET /auth-request/fetch` | `fetch_auth_request` | Master fetches request by pair code |
| `POST /auth-request/approve` | `approve_auth_request` | Master approves, backend signs internally |
| `GET /auth-request/await` | `await_auth_decision` | Child long-polls for signed decision |

- [ ] Master key custody: server generates + stores Ed25519 keypair per user, signs auth requests internally
- [ ] TTL enforcement: rendezvous registrations expire after 5 min, auth requests after 60s (interactive) or 5 min (async)
- [ ] Single-use enforcement: consumed auth requests reject second approval
- [ ] Identity linking: `POST /identity/link` and `GET /identity/resolve` for AgentIdentity → WalletAddress resolution
- [ ] `agentkeys-core/src/mock_client.rs` — HTTP client methods connected to the running server

### Unit Tests
```
cargo test -p agentkeys-mock-server    # 37 tests (12 original + 25 rendezvous/auth-request per eng-review-test-plan.md)
```

| # | Test | What it validates |
|---|---|---|
| 1 | `session::create_valid` | Valid OAuth → new account + session + wallet |
| 2 | `session::create_invalid_token` | Invalid token → 401 |
| 3 | `session::create_existing` | Existing account → return existing session |
| 4 | `session::child_valid` | Valid parent → scoped child session |
| 5 | `session::child_invalid_parent` | Invalid/expired parent → 401 |
| 6 | `credential::store_valid` | Valid session + scope → stored |
| 7 | `credential::store_duplicate` | Duplicate agent+service → update |
| 8 | `credential::read_valid` | Valid scope → return credential |
| 9 | `credential::read_wrong_agent` | Wrong agent → DENIED + audit event |
| 10 | `credential::read_not_provisioned` | Service not stored → 404 |
| 11 | `session::revoke_valid` | Master revokes child → child reads fail |
| 12 | `credential::teardown` | Revoke sessions + delete credentials |
| 13 | `rendezvous::register_poll_deliver` | Full pair loop: register → deliver → poll returns payload |
| 14 | `rendezvous::poll_timeout` | No delivery → clean timeout |
| 15 | `rendezvous::deliver_unknown_code` | Unknown pair code → NO_MATCH |
| 16 | `rendezvous::deliver_twice` | Second delivery → ALREADY_DELIVERED |
| 17 | `rendezvous::ttl_expiry` | Register, wait 6 min (fake clock) → EXPIRED |
| 18 | `rendezvous::ciphertext_passthrough` | Payload bytes unchanged through relay |
| 19 | `auth_request::open_pair` | Open Pair request → returns OTP + pair code |
| 20 | `auth_request::approve_valid` | Valid session approves → consumed |
| 21 | `auth_request::approve_already_consumed` | Second approval → ALREADY_CONSUMED |
| 22 | `auth_request::approve_expired` | After TTL → EXPIRED |
| 23 | `auth_request::approve_wrong_session` | Different user → UNAUTHORIZED |
| 24 | `auth_request::await_decision` | Child polls → receives signed decision after approval |
| 25 | `identity::link_and_resolve` | Link alias → resolve returns correct wallet |
| 26 | `rendezvous::pair_code_collision_avoidance` | 100k concurrent registrations → zero duplicate codes (property test) |
| 27 | `rendezvous::ciphertext_tamper_detection` | Mutate one byte server-side → daemon decrypt fails (backend cannot silently tamper) |
| 28 | `auth_request::otp_determinism` | Fixed nonce + fixed canonical request → same OTP across runs |
| 29 | `auth_request::cbor_round_trip` | Every `AuthRequestType` variant in `auth_request_vectors.json` serializes identically across two independent impls |
| 30 | `auth_request::fetch_valid_invalid` | Valid master session → returns full request; invalid/expired session → 401 |
| 31 | `auth_request::tamper_detection` | Mutate `request_details` between `open` and `approve` → daemon-side verification rejects (canonical hash mismatch) |
| 32 | `auth_request::await_after_consumption` | Poll after request consumed → returns CONSUMED; child destroys local nonce |
| 33 | `auth_request::otp_cross_request_replay` | Two requests with colliding OTPs but different details → approve request A → decision cannot authorize request B (hash mismatch) |
| 34 | `auth_request::nonce_uniqueness` | 100k concurrent `open_auth_request` calls → zero duplicate nonces (property test) |
| 35 | `auth_request::recover_flow_e2e` | Full pair → store credential → kill daemon → fresh daemon `--recover agent-A` → same wallet + same credentials without re-provisioning |
| 36 | `auth_request::recover_wrong_session` | Attacker with different account session tries to approve a Recover targeting agent-A → UNAUTHORIZED |
| 37 | `auth_request::scope_change` | `ScopeChange` flows through auth-request primitive → scope updated in SQLite → subsequent reads respect new scope |

### Reviewer E2E Checklist
```bash
# Terminal 1: start the server
cargo run -p agentkeys-mock-server -- --port 8090

# Terminal 2: smoke test with curl
# Create session
curl -X POST http://localhost:8090/session/create \
  -H 'Content-Type: application/json' \
  -d '{"auth_token": "test-google-token"}'
# → returns {"session": "...", "wallet": "0x..."}

# Store a credential
curl -X POST http://localhost:8090/credential/store \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <session>' \
  -d '{"agent_id": "0xagent1", "service": "openrouter", "ciphertext": "base64..."}'
# → returns 200

# Read it back
curl http://localhost:8090/credential/read?agent_id=0xagent1&service=openrouter \
  -H 'Authorization: Bearer <session>'
# → returns the credential

# Revoke the session
curl -X POST http://localhost:8090/session/revoke \
  -H 'Authorization: Bearer <session>' \
  -d '{"target_session": "<child-session>"}'
# → returns 200

# Read again → DENIED
curl http://localhost:8090/credential/read?agent_id=0xagent1&service=openrouter \
  -H 'Authorization: Bearer <child-session>'
# → returns 403 DENIED
```

### Stage Contract
- **Inputs:** Stage 0 crates (agentkeys-types, agentkeys-core)
- **Outputs:** A running HTTP server + a working `MockHttpClient` in agentkeys-core
- **Done when:** All **37** unit tests pass (12 original + 25 rendezvous/auth-request per `eng-review-test-plan.md`). The curl smoke test above works end-to-end. Server starts in < 2 seconds.

---

## Stage 2: CLI Core

**Goal:** The `agentkeys` CLI binary with the core management commands. A human can store, read, revoke, and audit credentials from the terminal.

### Crate
- `agentkeys-cli` — Rust binary, `clap` + `keyring-rs` + `agentkeys-core`

### Deliverables
- [ ] `agentkeys init` — opens Google OAuth in browser (or mock token for testing), stores session in OS keychain via `keyring-rs`
- [ ] `agentkeys store <agent> <service> <key>` — encrypts to shielding key, calls `store_credential`
- [ ] `agentkeys read <agent> <service>` — calls `read_credential`, prints to stdout
- [ ] `agentkeys run <agent> -- <cmd>` — fetches credential, injects as env var (`<SERVICE>_API_KEY`), execs child process
- [ ] `agentkeys revoke <agent>` — calls `revoke_session`
- [ ] `agentkeys teardown <agent>` — calls `teardown_agent`
- [ ] `agentkeys usage [agent]` — calls `query_audit`, prints formatted table
- [ ] `agentkeys link <agent> --alias/--email` — calls identity linking endpoint
- [ ] `agentkeys feedback` — opens GitHub Discussion in browser
- [ ] All commands support `--help` (with examples), `--verbose`, `--json`, `--version`
- [ ] Error messages follow the spec: problem + cause + fix + docs link (5 error paths from DX review)

### Unit Tests
```
cargo test -p agentkeys-cli    # integration tests via assert_cmd
```

| Test | What it validates |
|---|---|
| `cli::init_creates_session` | `agentkeys init --mock-token test` stores session in keychain |
| `cli::store_and_read` | Store a credential, read it back, output matches |
| `cli::store_scope_denied` | Agent-A stores, Agent-B reads → DENIED error with correct message |
| `cli::run_injects_env` | `agentkeys run my-agent -- env` output contains `OPENROUTER_API_KEY=sk-xxx` |
| `cli::revoke_then_read` | Revoke, then read → DENIED with revocation timestamp |
| `cli::teardown_deletes_all` | Teardown, then read → 404 |
| `cli::usage_shows_audit` | After store + read, `usage` shows both events |
| `cli::link_alias` | Link an alias, verify `identity/resolve` returns correct wallet |
| `cli::help_has_examples` | `agentkeys store --help` output contains a copy-paste example |
| `cli::json_output` | `agentkeys read --json my-agent openrouter` outputs valid JSON |
| `cli::verbose_output` | `agentkeys read --verbose my-agent openrouter` shows backend request details |
| `cli::error_format_denied` | Revoke + read → error output matches the DENIED error spec (problem + cause + fix) |
| `cli::error_format_not_found` | Read non-existent → error output matches AGENT_NOT_FOUND spec |
| `cli::error_format_unreachable` | Backend down → error output matches BACKEND_UNREACHABLE spec |

### Reviewer E2E Checklist
```bash
# Prerequisite: Stage 1 mock backend running on port 8090
export AGENTKEYS_BACKEND=http://localhost:8090

# Full loop — the README quickstart
agentkeys init --mock-token test-user           # session saved to keychain
agentkeys store my-agent openrouter sk-test-123 # store a credential
agentkeys read my-agent openrouter              # → prints sk-test-123
agentkeys run my-agent -- printenv OPENROUTER_API_KEY  # → prints sk-test-123
agentkeys usage my-agent                        # → shows store + read events
agentkeys revoke my-agent                       # kill access
agentkeys read my-agent openrouter              # → DENIED error with revocation time
agentkeys teardown my-agent                     # cleanup

# Error quality check
agentkeys read nonexistent-agent openrouter     # → AGENT_NOT_FOUND with fix guidance
AGENTKEYS_BACKEND=http://localhost:9999 agentkeys read my-agent openrouter
                                                # → BACKEND_UNREACHABLE with retry info

# Flag check
agentkeys read --json my-agent openrouter       # → valid JSON
agentkeys store --help                          # → shows examples
agentkeys --version                             # → prints version + backend API version
```

### Stage Contract
- **Inputs:** Stage 0 crates + Stage 1 running mock backend
- **Outputs:** `agentkeys` CLI binary that passes all 14 tests and the E2E checklist
- **Done when:** All tests pass. The README quickstart sequence (7 commands) works exactly as documented. Every error message matches the DX spec.

---

## Stage 3: Daemon + MCP Server

**Goal:** The `agentkeys-daemon` binary that runs inside a sandbox, serves MCP tools, and applies kernel hardening.

### Crates
- `agentkeys-daemon` — Rust binary, `rmcp` (MCP protocol), `nix` (kernel syscalls)
- `agentkeys-mcp` — Rust library, MCP tool definitions

### Deliverables
- [ ] Daemon binary that starts, connects to mock backend, and serves MCP tools over stdio
- [ ] MCP tool: `agentkeys.get_credential(service)` — fetches from backend, returns to agent
- [ ] MCP tool: `agentkeys.list_credentials()` — lists available services for this agent
- [ ] Kernel hardening (in-process, verified at startup):
  - [ ] `memfd_secret()` for runtime session key copy (fallback to `mlock2` if ENOSYS)
  - [ ] `mlock2(MCL_CURRENT|MCL_FUTURE)` — prevent swap
  - [ ] `prctl(PR_SET_DUMPABLE, 0)` — block /proc/pid/mem reads
  - [ ] `prctl(PR_SET_NO_NEW_PRIVS, 1)` — block privilege escalation
  - [ ] Self-installed seccomp-bpf filter (deny ptrace, process_vm_readv, kcmp, keyctl, /dev/mem opens)
  - [ ] Capability drop to empty effective set after init
- [ ] Startup self-test: verify each hardening feature, log results, continue on degradation
- [ ] Session file at `$HOME/.agentkeys/session` (mode 0600)
- [ ] Version check: warn if sandbox image version differs from probed version (1.0.0.152)

### Unit Tests
```
cargo test -p agentkeys-daemon -p agentkeys-mcp
```

| Test | What it validates |
|---|---|
| `daemon::starts_and_connects` | Daemon starts, connects to mock backend, exits cleanly |
| `daemon::memfd_secret_or_fallback` | `memfd_secret()` returns valid fd OR fallback to mlock2 succeeds |
| `daemon::mlock_residency` | After init, `/proc/self/status` shows `VmLck > 0` |
| `daemon::dumpable_off` | After init, `Dumpable: 0` in `/proc/self/status` |
| `daemon::no_new_privs` | After init, `NoNewPrivs: 1` in `/proc/self/status` |
| `daemon::seccomp_installed` | After init, `Seccomp: 2` (filter mode) |
| `daemon::caps_dropped` | After init, `CapEff: 0000000000000000` |
| `daemon::landlock_enosys_ok` | Daemon starts cleanly when landlock returns ENOSYS |
| `daemon::session_file_permissions` | Session file created with mode 0600, owner matches current UID |
| `mcp::get_credential_valid` | MCP tool call returns stored credential |
| `mcp::get_credential_denied` | MCP tool call after revoke returns DENIED |
| `mcp::list_credentials` | MCP tool call returns list of available services |
| `mcp::tool_discovery` | MCP tool listing includes `agentkeys.get_credential` and `agentkeys.list_credentials` |

### Reviewer E2E Checklist

> **TEST SEAM — NOT THE PRODUCTION BOOTSTRAP.** The `AGENTKEYS_SESSION` env-var injection below is a **temporary test seam** that lets us validate the daemon in isolation before the full pair/approve flow exists. The production bootstrap (child-initiates pairing via `open_auth_request` + rendezvous, user approves via `agentkeys approve <code>`) ships in **Stage 4**. Reviewers should verify that the daemon works with this test seam, **NOT** that this test seam is the intended operational model. Any code that hard-depends on `AGENTKEYS_SESSION` being pre-set (rather than obtained via pairing) is a bug in Stage 4+.

```bash
# Prerequisite: Stage 1 mock backend running
# Prerequisite: A session exists (from Stage 2 CLI: agentkeys init + store)

# Start daemon (TEST SEAM — see note above)
AGENTKEYS_BACKEND=http://localhost:8090 \
AGENTKEYS_SESSION=<child-session-token> \
agentkeys-daemon --stdio

# In a separate terminal, use an MCP client (or Claude Code) to:
# 1. List tools → should show agentkeys.get_credential, agentkeys.list_credentials
# 2. Call agentkeys.get_credential(service: "openrouter") → returns the stored key
# 3. Revoke the session via CLI: agentkeys revoke my-agent
# 4. Call agentkeys.get_credential(service: "openrouter") → DENIED

# Hardening verification (run inside the daemon process or check /proc):
cat /proc/<daemon-pid>/status | grep -E 'Dumpable|NoNewPrivs|Seccomp|CapEff|VmLck'
# Expected: Dumpable: 0, NoNewPrivs: 1, Seccomp: 2, CapEff: 0, VmLck > 0
```

### Stage Contract
- **Inputs:** Stage 0 crates + Stage 1 running mock backend + a valid session token
- **Outputs:** `agentkeys-daemon` binary with MCP server and kernel hardening
- **Done when:** All 13 tests pass. MCP tools are discoverable and functional. Hardening checks pass on Linux (macOS: hardening tests skip gracefully with warnings).

---

## Stage 4: Pair/Approve Flow

**Goal:** The full child-initiates rendezvous pairing flow. A daemon can pair with a master session without any direct network connection.

### Crates Modified
- `agentkeys-daemon` — add pair-on-startup flow (open_auth_request, register_rendezvous, poll, display pair code)
- `agentkeys-cli` — add `agentkeys approve <pair-code>` command (fetch_auth_request by pair code, display details + OTP, confirm, approve_auth_request)

### Deliverables
- [ ] Daemon startup pair flow:
  1. Generate Ed25519 keypair
  2. Call `open_auth_request(Pair, {daemon_pubkey, scope})`
  3. Call `register_rendezvous(daemon_pubkey, pair_code)`
  4. Display: "Pair code: ABCD-EFGH. Approve on your Master device."
  5. Long-poll `poll_rendezvous` until payload arrives or timeout
  6. Decrypt child session from payload → store in memfd_secret + at-rest file
- [ ] `agentkeys approve <pair-code>`:
  1. Call `fetch_auth_request(session, pair_code)` → display request type, scope, OTP
  2. Prompt user: "OTP is XXXXXX. Does this match? [y/N]"
  3. On confirm: call `approve_auth_request(session, request_id)`
- [ ] Recovery flow: `agentkeys-daemon --recover <agent-identity>`
  1. Same as pair but with `AuthRequestType::Recover { agent_identity, new_daemon_pubkey }`
  2. Backend resolves AgentIdentity → WalletAddress via identity graph
  3. Backend re-encrypts existing credentials to new daemon pubkey
- [ ] Identity linking: `agentkeys link <agent> --alias/--email` already implemented in Stage 2

### Unit Tests
```
cargo test -p agentkeys-daemon -p agentkeys-cli -- pair
```

| Test | What it validates |
|---|---|
| `pair::full_loop` | Daemon opens request + registers → CLI approves → daemon receives session |
| `pair::otp_matches` | OTP displayed by daemon matches OTP shown by CLI `approve` |
| `pair::timeout_retry` | Daemon times out on poll → generates fresh pair code → second attempt succeeds |
| `pair::wrong_pair_code` | `agentkeys approve XXXX-YYYY` with unknown code → clear error |
| `pair::expired_code` | Approve after 5-min TTL → EXPIRED error |
| `pair::replay_resistance` | Approve same code twice → ALREADY_CONSUMED |
| `pair::wrong_user_approve` | Different user's session tries to approve → UNAUTHORIZED |
| `recover::full_loop` | Daemon `--recover agent-A` → CLI approves → daemon receives existing wallet + credentials |
| `recover::unknown_identity` | `--recover nonexistent` → AGENT_NOT_FOUND with guidance |
| `recover::old_pubkey_revoked` | After recovery, old daemon's pubkey is revoked |
| `recover::credentials_intact` | After recovery, `get_credential` returns the same key that was stored before the old daemon died |

### Reviewer E2E Checklist
```bash
# Prerequisite: Stage 1 mock backend running
# Prerequisite: Master session exists (agentkeys init)

# === PAIR FLOW ===

# Terminal 1: start daemon (it will display a pair code)
AGENTKEYS_BACKEND=http://localhost:8090 agentkeys-daemon
# Output: "Pair code: ABCD-EFGH. Approve on your Master device."

# Terminal 2: approve on Mac
agentkeys approve ABCD-EFGH
# Output: "Request: Pair new agent. OTP: 123456. Confirm? [y/N]"
# Type: y
# Output: "Approved. Agent paired successfully."

# Terminal 1 should now show: "Paired. Session received. Daemon ready."

# Test credential flow through the paired daemon:
agentkeys store <agent-wallet> openrouter sk-test   # store via CLI
# Then via MCP: agentkeys.get_credential("openrouter") → sk-test

# === RECOVER FLOW ===

# Link an identity first
agentkeys link <agent-wallet> --alias my-bot

# Kill daemon (Ctrl+C)
# Start new daemon in recover mode
AGENTKEYS_BACKEND=http://localhost:8090 agentkeys-daemon --recover my-bot
# Output: "Recovery code: WXYZ-1234. Approve on your Master device."

# Approve recovery
agentkeys approve WXYZ-1234
# Output: "Request: Recover agent 'my-bot'. OTP: 654321. Confirm? [y/N]"
# Type: y

# Verify same credentials survived:
# MCP: agentkeys.get_credential("openrouter") → sk-test (same key, no re-store needed)
```

### Stage Contract
- **Inputs:** Stages 0-3 (all crates + running backend + CLI + daemon with MCP)
- **Outputs:** Working pair + recover flows via rendezvous
- **Done when:** All 11 tests pass. The pair E2E flow works across two terminals. The recover flow preserves credentials.

---

## Stage 5: Provisioner — Agent-Driven Browser Automation

**Goal:** An agent with browser control can call `agentkeys.provision(service: "openrouter")` via MCP, and Playwright creates a real OpenRouter account automatically.

### Crates / Packages
- `agentkeys-provisioner` — Rust library, spawns Playwright subprocess, handles IPC
- `provisioner-scripts/` — TypeScript + Playwright:
  - `scrapers/openrouter.ts` — OpenRouter signup flow
  - **`lib/email.ts`** — ephemeral email integration (per `architecture.md` §6 workspace layout). Reads verification codes from the chosen burner email backend (Gmail plus-addressing for v0, SimpleLogin/AnonAddy as future options). This is a **required v0 component**, not an implied dependency — `openrouter.ts` calls `email.ts` to retrieve the verification code during signup.

### Deliverables
- [ ] MCP tool: `agentkeys.provision(service: "openrouter")` exposed on the daemon
- [ ] Rust orchestrator: receives MCP call → spawns `npx tsx provisioner-scripts/scrapers/openrouter.ts` → passes parameters via stdin/env → receives API key via stdout JSON → encrypts to shielding key → calls `store_credential`
- [ ] `openrouter.ts` Playwright script: navigates openrouter.ai → creates account (with burner email via `lib/email.ts`) → generates API key → returns `{"api_key": "sk-or-v1-..."}` on stdout
- [ ] **`lib/email.ts`** — email client module: connects to the burner email backend (IMAP for Gmail plus-addressing, or provider API for SimpleLogin), polls for a verification code matching a given subject/sender pattern, returns the code. Used by `openrouter.ts` and all future scraper scripts. Config: email backend type + credentials passed via env vars (`AGENTKEYS_EMAIL_BACKEND`, `AGENTKEYS_EMAIL_USER`, `AGENTKEYS_EMAIL_PASSWORD` or `AGENTKEYS_EMAIL_API_KEY`).
- [ ] Error handling: if Playwright fails (DOM changes, CAPTCHA, network) or email retrieval times out, return structured error to MCP caller with what step failed

### Unit Tests
```
cargo test -p agentkeys-provisioner     # orchestrator IPC tests with mock subprocess
npm test --prefix provisioner-scripts   # Playwright script unit tests
```

| Test | What it validates |
|---|---|
| `provisioner::spawn_and_receive` | Orchestrator spawns a mock TS subprocess, receives JSON on stdout |
| `provisioner::subprocess_timeout` | Subprocess hangs → orchestrator times out after 120s with clear error |
| `provisioner::subprocess_error` | Subprocess returns error JSON → orchestrator surfaces it to MCP caller |
| `provisioner::stores_credential` | After successful provision, `read_credential` returns the obtained key |
| `provisioner::duplicate_provision` | Provision when already provisioned → return existing credential |
| `email::fetch_code_gmail_plus` | `lib/email.ts` connects to Gmail IMAP with plus-addressed account, sends a test email with a known code, retrieves it within 30s |
| `email::fetch_code_timeout` | No matching email arrives → clean timeout with structured error (not a hang) |
| `email::fetch_code_wrong_pattern` | Email arrives but doesn't match expected sender/subject → returns NOT_FOUND, not the wrong code |
| `openrouter::smoke` | (CI weekly) Playwright script runs against live openrouter.ai, creates account (using `lib/email.ts` for verification), obtains key |

### Reviewer E2E Checklist
```bash
# Prerequisite: Stages 0-4 complete, daemon paired and running

# From an agent (or manually via MCP client):
# Call: agentkeys.provision(service: "openrouter")
# Expected: Playwright opens browser, creates OpenRouter account, returns success
# Verify: agentkeys.get_credential(service: "openrouter") → returns a real sk-or-v1-... key

# Error case: disconnect internet, call provision → clear error about network failure
```

### Stage Contract
- **Inputs:** Stages 0-4 + Node.js + Chrome/Chromium installed
- **Outputs:** Working `agentkeys.provision` MCP tool that creates real OpenRouter accounts
- **Done when:** Orchestrator IPC tests pass. At least one successful live provision of a real OpenRouter account (manual verification — this creates a real account).

---

## Stage 6: npm Package + DX Polish

**Goal:** Ship `@agentkeys/daemon` as an npm package for cloud LLM environments, plus all DX artifacts (README, install.sh, docs, error messages).

### Package
- `@agentkeys/daemon` npm package (TypeScript wrapper + prebuilt Rust binaries)

### Deliverables
- [ ] npm package with postinstall script that picks the right prebuilt binary (linux-x64, linux-arm64, darwin-x64, darwin-arm64)
- [ ] `npx @agentkeys/daemon` starts the daemon and displays pair code
- [ ] `npx @agentkeys/daemon --recover agent-A` starts in recovery mode
- [ ] `install.sh` script for Mac/Linux (prebuilt binary, PATH setup, prereq check)
- [ ] README.md following the DX spec (one-line pitch, quickstart with store/MCP/revoke loop, demo GIF placeholder)
- [ ] `agentkeys --help` with per-subcommand examples
- [ ] Error messages matching the 5 error path specs
- [ ] `docs/how-it-works.md`, `docs/security-model.md`
- [ ] CHANGELOG.md, LICENSE (MIT OR Apache-2.0)

### Tests

| Test | What it validates |
|---|---|
| `npm::install_linux_x64` | `npm install @agentkeys/daemon` on linux-x64 → binary present + executable |
| `npm::install_darwin_arm64` | Same on darwin-arm64 |
| `npm::npx_starts_daemon` | `npx @agentkeys/daemon` starts, prints pair code, exits on SIGTERM |
| `npm::npx_recover` | `npx @agentkeys/daemon --recover test-alias` starts in recovery mode |
| `install_sh::installs_binary` | `curl \| sh` installs binary, adds to PATH, prints next step |
| `install_sh::prereq_warning` | Without Node.js → prints warning but does not fail |
| `readme::quickstart_valid` | Every command in the README quickstart section is syntactically valid |

### Reviewer E2E Checklist
```bash
# Install via curl
curl -fsSL https://get.agentkeys.dev/install.sh | sh
agentkeys --version              # → prints version
agentkeys --help                 # → shows all subcommands with examples
agentkeys store --help           # → shows store-specific help with example

# Install via npm (simulating cloud LLM environment)
npx @agentkeys/daemon            # → starts daemon, shows pair code
# Ctrl+C to stop

# Walk through the full README quickstart and verify every command works
```

### Stage Contract
- **Inputs:** Stages 0-5 (all binaries built and tested)
- **Outputs:** Published npm package, install.sh, README, docs
- **Done when:** npm package installs and runs on both Linux and macOS. install.sh works. README quickstart sequence runs end-to-end without errors.

---

## Stage 7: Full E2E Integration + MCP Auth Demo

**Goal:** The complete system works end-to-end across all components. Includes the MCP auth demo (wrapping MCP servers with `agentkeys run`).

### No new crates. Cross-cutting integration.

### Deliverables
- [ ] Full E2E test suite that runs the complete user journey
- [ ] MCP auth demo: Claude Code settings.json with `agentkeys run` wrapping a real MCP server
- [ ] Multi-agent isolation E2E: two agents, each with different credentials, scope enforcement verified
- [ ] Recovery E2E: pair, store, kill daemon, recover, verify credentials survive
- [ ] Revocation latency test: revoke → next read denied within target latency

### E2E Test Flows

**E2E-1: Full lifecycle (the README demo)**
```bash
# Setup
cargo run -p agentkeys-mock-server -- --port 8090 &
agentkeys init --mock-token user1

# Store + Read + Revoke
agentkeys store agent-A openrouter sk-test-123
agentkeys read agent-A openrouter                    # → sk-test-123
agentkeys run agent-A -- printenv OPENROUTER_API_KEY  # → sk-test-123
agentkeys revoke agent-A
agentkeys read agent-A openrouter                    # → DENIED

# Verify: exactly 4 audit events (store, read, run-read, revoke)
agentkeys usage agent-A --json | jq '.events | length'  # → 4
```

**E2E-2: Multi-agent isolation**
```bash
agentkeys store agent-A openrouter sk-aaa
agentkeys store agent-B brave sk-bbb

# Agent-A can read its own
agentkeys read agent-A openrouter                    # → sk-aaa
# Agent-A cannot read Agent-B's
agentkeys read agent-A brave                         # → DENIED (scope: agent-A has no brave)
# Agent-B can read its own
agentkeys read agent-B brave                         # → sk-bbb
# Agent-B cannot read Agent-A's
agentkeys read agent-B openrouter                    # → DENIED
```

**E2E-3: Pair + MCP + Revoke (the full sandbox flow)**
```bash
# Terminal 1: daemon
AGENTKEYS_BACKEND=http://localhost:8090 agentkeys-daemon
# Shows: "Pair code: ABCD-EFGH"

# Terminal 2: approve + store
agentkeys approve ABCD-EFGH                          # confirm OTP
agentkeys store <agent-wallet> openrouter sk-test

# Terminal 1: MCP client calls get_credential → sk-test

# Terminal 2: revoke
agentkeys revoke <agent-wallet>

# Terminal 1: MCP client calls get_credential → DENIED
```

**E2E-4: Recovery (ephemeral daemon)**
```bash
# Setup: pair + store + link
agentkeys approve <code1>                            # first pair
agentkeys store <agent> openrouter sk-original
agentkeys link <agent> --alias my-bot

# Kill daemon (simulate ephemeral sandbox death)
# Start new daemon in recover mode
AGENTKEYS_BACKEND=http://localhost:8090 agentkeys-daemon --recover my-bot
# Shows: "Recovery code: WXYZ-1234"
agentkeys approve WXYZ-1234                          # approve recovery

# Verify credentials survived
# MCP: get_credential("openrouter") → sk-original (same key!)
```

**E2E-5: MCP auth demo (agentkeys run wrapping MCP servers)**
```bash
# Store credentials for two services
agentkeys store my-agent github ghp_test123
agentkeys store my-agent openrouter sk-test456

# Launch an MCP server wrapped with agentkeys run
agentkeys run my-agent -- npx @modelcontextprotocol/server-github
# The MCP server process should have GITHUB_TOKEN=ghp_test123 in its env

# Revoke → MCP server loses access on next restart
agentkeys revoke my-agent
agentkeys run my-agent -- npx @modelcontextprotocol/server-github
# → DENIED error, MCP server cannot start
```

**E2E-6: Revocation latency**
```bash
# Store + read (warm the path)
agentkeys store agent-X openrouter sk-timing
agentkeys read agent-X openrouter                    # → works

# Revoke and immediately read
agentkeys revoke agent-X
time agentkeys read agent-X openrouter               # → DENIED
# Verify: denied within < 1 second (mock backend, not Heima)
```

### Reviewer Master Checklist

Run all six E2E flows above in sequence. Every command must produce the expected output. Any failure = stage not done.

Additionally verify:
- [ ] `agentkeys --version` reports correct version
- [ ] `agentkeys --help` shows all subcommands
- [ ] Every error message follows the problem + cause + fix format
- [ ] `agentkeys usage` shows a complete audit trail of all operations
- [ ] The daemon's kernel hardening reports pass (on Linux)
- [ ] `npx @agentkeys/daemon` installs and starts successfully

### Stage Contract
- **Inputs:** All prior stages complete
- **Outputs:** A fully working AgentKeys v0 system
- **Done when:** All 6 E2E flows pass. The reviewer checklist is fully checked. The system is demo-ready for the meetup.

---

## Summary

| Stage | What ships | Depends on | Est. effort | Tests |
|---|---|---|---|---|
| 0 | Types + CredentialBackend trait | — | 2-3 days | 8 unit |
| 1 | Mock backend (25 endpoints + identity linking) | Stage 0 | 5-7 days | **37** unit + curl smoke |
| 2 | CLI (10 commands) | Stages 0, 1 | 4-5 days | 14 unit + E2E checklist |
| 3 | Daemon + MCP + hardening | Stages 0, 1 | 4-5 days | 13 unit + hardening checks |
| 4 | Pair/Approve + Recover | Stages 0-3 | 3-4 days | 11 unit + 2-terminal E2E |
| 5 | Provisioner (OpenRouter) + email integration | Stages 0-4 | 3-4 days | 9 unit + live provision |
| 6 | npm package + DX | Stages 0-5 | 2-3 days | 7 tests + install checks |
| 7 | Full E2E + MCP auth demo | All | 2-3 days | 6 E2E flows + master checklist |
| **Total** | | | **~25-34 days** | **105 tests + 6 E2E flows** |

**Parallelization opportunity:** Stages 2 and 3 can run in parallel (~4-5 days saved). Stage 6 can overlap with Stage 5. Realistic v0 timeline with one developer: **~4-5 weeks**.

**Critical path:** Stage 0 → Stage 1 → Stage 4 → Stage 7. Everything else is parallelizable around this spine.
