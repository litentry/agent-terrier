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
    │        │        │        ├──► Stage 5a: Provisioner (deterministic + patterns)
    │        │        │        │        │
    │        │        │        │        └──► Stage 7: Full E2E   [v0 ships here]
    │        │        │        │
    │        ├──► Stage 3: Daemon + MCP ──┘
    │
    └──► (all stages depend on Stage 0)

Post-v0 (v0.1 milestone, any order or parallel):
    Stage 7 ──► Stage 8: Production Hardening
             ├─► Stage 5b: Agentic fallback + audit + fallback→PR + script-gen
             └─► Stage 6:  npm Package + DX Polish
```

**Parallelizable:** Stages 2 and 3 can run in parallel after Stage 1. **v0 critical path terminates at Stage 7** (previously gated on Stage 6). Stages 5b, 6, and 8 all defer to the v0.1 milestone and can ship in any order or in parallel.

**Stage 5/6 restructuring (2026-04-16 CEO review, SELECTIVE EXPANSION mode):** The original Stage 5 bundled deterministic scraping with agentic ambitions; the original Stage 6 gated v0 on npm packaging. Both were relaxed:
- **Stage 5 splits into 5a and 5b.** 5a (deterministic + patterns library + mandatory post-provision verification) ships in v0. 5b (Claude-Chrome agentic fallback + audit trail + fallback→PR loop + LLM script-generator dev tool + 4 additional patterns) ships in v0.1. See the 4-tier runtime architecture in the Stage 5a section.
- **Stage 6 postpones to v0.1.** v0 distribution uses `cargo install` and GH-release prebuilt binaries. npm packaging, install.sh, README polish, and the remaining DX docs become part of the v0.1 milestone.
- **Rationale:** the `store`/`read`/`run`/`pair`/`recover`/`audit` loop is the actual product; provisioner is sugar and packaging is distribution. Shipping v0 on fewer dependencies (Rust only, no Node/Playwright in the critical path) reduces setup friction for the first demo while preserving the architectural substrate (Stage 5a patterns library, Stage 3 MCP infrastructure) that Stage 5b builds on.

CEO plan with full decision record: `~/.gstack/projects/litentry-agentKeys/ceo-plans/2026-04-16-stage-5-hybrid-agentic.md`.

---

## Stage 5–7 roadmap update (2026-04-19)

After the Stage 5a demo path landed and the email-system architecture + TEE-as-OIDC-provider design work matured, the post-Stage-5 roadmap is reordered. The new order is:

| Stage | Title | Status |
|---|---|---|
| **5** | Provisioner: deterministic + patterns + quick-email demo (dedicated personal Gmail) | **Current** — stays as-is, ships the live OpenRouter-provision demo on the simplest email path |
| **6** | **Federated own-email** — `xxxxx@agentkeys-email.io` hosted on our infrastructure (AWS SES + TEE-derived Ed25519 DKIM + ES256 OIDC issuer + PrincipalTag-based per-user isolation) | **Next** |
| **7** | **Generalized OIDC provider** — expose `https://oidc.agentkeys.dev` as a universal federation target; any cloud that accepts external OIDC (AWS, GCP, Azure, Snowflake, Ali Cloud, K8s) trusts us once; bring-your-own domain/Workspace/GitHub paths become available | **After 6** |
| 6 (old) — npm Package + DX Polish | | **Postponed** (preserved below for reference) |
| 7 (old) — Full E2E Integration + MCP Auth Demo | | **Postponed** (preserved below for reference) |
| 8 (old) — Production Hardening | | **Postponed** (preserved below for reference) |
| 9 (old) — v0.1 Heima Migration Holding Pen | | **Postponed** (preserved below for reference) |

### Why this reorder

The three architectural wiki pages on our email/OIDC design surfaced a coherent v0.1 milestone that does more for product-and-user value than packaging or late-stage hardening:

1. **Hosted-first default** — non-developer users get `xxxxx@agentkeys-email.io` with zero configuration, parallel to how AgentMail mints default-domain inboxes. See [`wiki/hosted-first.md`](../../../wiki/hosted-first.md).
2. **TEE holds all signing keys natively** — the Ed25519 DKIM key and ES256 OIDC-issuer key join the existing shielding/JWT/wallet derivation paths, all under `blockchain-tee-architecture.md` rule #2. See [`wiki/oidc-federation.md`](../../../wiki/oidc-federation.md).
3. **Per-user isolation without per-user IAM** — JWT claim `agentkeys_user_wallet` → AWS session tag → `aws:PrincipalTag` in bucket/role policy = one bucket, N users, cryptographic separation. See [`wiki/tag-based-access.md`](../../../wiki/tag-based-access.md).
4. **Knowledge-base decision deferred** — Stage 6/7 deliver the mechanism; which backend (GitHub / AWS S3 / Google Drive / Ali Cloud OSS) we ship as default is decided later per user segment. See [`wiki/knowledge-storage.md`](../../../wiki/knowledge-storage.md).

**Broker-not-proxy principle.** Stages 6 and 7 both adhere to the principle that AgentKeys infrastructure mints ephemeral credentials and the daemon talks to remote services directly via MCP. Our backend never proxies per-user reads/writes. This keeps compute cost flat with user count (scales with sign-up rate, not operation frequency) and aligns with `blockchain-tee-architecture.md` rules #2–#3.

Full stage contracts for 6 and 7 appear below in their own sections, right after Stage 5b and before the postponed ex-6/7/8/9 sections.

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

## Stage 5a: Provisioner — Deterministic + Patterns (v0 critical path)

**Goal:** An agent with browser control can call `agentkeys.provision(service: "openrouter")` via MCP, a deterministic Playwright script (composing a reusable pattern) creates a real OpenRouter account, and a mandatory verification step confirms the returned API key actually works against the target service before the credential is stored.

**Architectural context (2026-04-16 CEO review).** Stage 5 was restructured into a 4-tier runtime architecture. Stage 5a ships Tier 1 (patterns) and Tier 2 (scripts). Stage 5b ships Tier 0 (dev-time script generator) and Tier 3 (runtime agentic fallback).

```
  TIER 0 (dev tool, 5b)     LLM-generated script via agentkeys-scripts-gen
                            ↓ produces a draft .ts file for human review
  TIER 1 (5a)               Pattern library: signupEmailOtp (v0),
                            OAuth-Google / OAuth-GitHub / magic-link / password+verify (5b)
                            ↓ scripts compose patterns
  TIER 2 (5a)               Script registry: provisioner-scripts/scrapers/*.ts
                            ↓ runtime tries this first
  TIER 3 (5b)               Claude-Chrome agentic fallback via MCP browser primitives
                            ↓ engages on trip-wire (selector miss, CAPTCHA, no script)
```

### Crates / Packages
- `agentkeys-provisioner` — Rust library, spawns Playwright subprocess, handles IPC, runs verification
- `provisioner-scripts/` — TypeScript + Playwright:
  - `scrapers/openrouter.ts` — OpenRouter signup flow (composes `signup_email_otp` pattern)
  - **`patterns/signup_email_otp.ts`** — reusable pattern: email signup with OTP verification. Takes `{ url, emailBackend, submitButton, otpSelector, successKeySelector }` and drives the flow. Extracted from the OpenRouter script so v0.1 services can compose it without reimplementing the signup-with-OTP shape.
  - **`lib/email.ts`** — ephemeral email integration. Reads verification codes from the chosen burner email backend (Gmail plus-addressing for v0; SimpleLogin / mail.tm / AnonAddy in v0.1). Patterns call this; individual scrapers never call email directly.
  - **`lib/verify.ts`** — post-provision credential verification helper. Takes `{ key, service }` and makes one authenticated API call against the target. Returns `true` only if the call succeeds. This is the only defense against silent-corrupt-credential (a string that looks like an API key but isn't).

### Deliverables
- [ ] MCP tool: `agentkeys.provision(service: "openrouter")` exposed on the daemon
- [ ] Rust orchestrator: receives MCP call → spawns `npx tsx provisioner-scripts/scrapers/openrouter.ts` → passes parameters via stdin/env → receives API key via stdout JSON → **calls `lib/verify.ts` to confirm the key works against the live API** → encrypts to shielding key → calls `store_credential`. If verification fails, abort with a clear error; `store_credential` is NOT called.
- [ ] **Mandatory post-provision verification step.** Every tier's success output must be verified by one authenticated API call against the target service. This is non-negotiable: without it, script drift or LLM hallucination can return a page label or session ID that passes the "string was extracted" bar but is not a working credential. For OpenRouter: `GET https://openrouter.ai/api/v1/models` with `Authorization: Bearer <key>` → 200 is real, 401 is phantom.
- [ ] `patterns/signup_email_otp.ts` — reusable email-signup-with-OTP pattern extracted from the OpenRouter flow. Functions over a DSL. Composition is "scripts call pattern functions with service-specific selectors."
- [ ] `scrapers/openrouter.ts` — OpenRouter signup composes `signupEmailOtp` with OpenRouter-specific selectors + success-page key extraction.
- [ ] `lib/email.ts` — IMAP for Gmail plus-addressing in v0. Config via env: `AGENTKEYS_EMAIL_BACKEND`, `AGENTKEYS_EMAIL_USER`, `AGENTKEYS_EMAIL_PASSWORD` or `AGENTKEYS_EMAIL_API_KEY`.
- [ ] Structured error reporting per trip-wire type: selector timeout (15s default), unexpected navigation, HTTP 5xx from target, email timeout, verification failure. Each trip-wire reports `{ stage, trigger, service, elapsed_ms }` to the MCP caller. No generic "something failed."
- [ ] Observability (mandatory, per Section 8 of CEO review): emit `provision_tier_used{service,tier}`, `provision_duration_seconds{service}`, `provision_trip_wire_fired{service,trip_wire}`, `provision_verification_result{service,result}` metrics per run.

### Unit Tests
```
cargo test -p agentkeys-provisioner     # orchestrator IPC + trip-wire + verification gating
npm test --prefix provisioner-scripts   # patterns + scrapers + email + verify
```

| Test | What it validates |
|---|---|
| `provisioner::spawn_and_receive` | Orchestrator spawns a mock TS subprocess, receives JSON on stdout |
| `provisioner::subprocess_timeout` | Subprocess hangs → orchestrator times out after 120s with clear error |
| `provisioner::subprocess_error` | Subprocess returns error JSON → orchestrator surfaces it to MCP caller |
| `provisioner::verification_failure_aborts` | Script returns a key, `lib/verify` returns false → provision aborts, `store_credential` NOT called |
| `provisioner::stores_credential` | After successful provision + verification, `read_credential` returns the obtained key |
| `provisioner::duplicate_provision` | Provision when already provisioned → return existing credential (no new signup) |
| `provisioner::phantom_key_caught` | **Chaos test.** Decoy page returns a string shaped like `sk-or-v1-XXXXX` that isn't a real key → verification catches it → provision aborts with clear error |
| `patterns::signup_email_otp_happy` | Pattern runs against HAR fixture of OpenRouter signup, completes flow, returns extracted key |
| `patterns::signup_email_otp_selector_timeout` | Pattern hits missing selector → returns structured trip-wire error (not a hang) |
| `email::fetch_code_gmail_plus` | `lib/email.ts` connects to Gmail IMAP with plus-addressed account, retrieves test email within 30s |
| `email::fetch_code_timeout` | No matching email → clean timeout with structured error |
| `email::fetch_code_wrong_pattern` | Email arrives but doesn't match sender/subject → NOT_FOUND, not the wrong code |
| `verify::valid_key_returns_true` | Valid OpenRouter key → `GET /api/v1/models` 200 → returns true |
| `verify::invalid_key_returns_false` | Random string → 401 → returns false |
| `openrouter::smoke` | (CI weekly, non-blocking) Live openrouter.ai end-to-end provision with verification. Auto-files issue on failure; does not block merges. |

### Reviewer E2E Checklist
```bash
# Prerequisite: Stages 0-4 complete, daemon paired and running

# Happy path:
# Call via MCP: agentkeys.provision(service: "openrouter")
# Expected: Playwright opens browser, creates account via signup_email_otp pattern,
#           extracts key, verifies key against openrouter.ai/api/v1/models,
#           stores credential. Returns success.
# Verify: agentkeys.get_credential(service: "openrouter") → returns a real sk-or-v1-... key

# Phantom-key defense:
# Deploy a decoy HTTP server returning a page with a fake sk-or-v1-FAKE string
# Point the script at the decoy URL
# Expected: script "succeeds" extracting FAKE; verification calls openrouter.ai with FAKE;
#           gets 401; provision aborts; store_credential NOT called.

# Trip-wire: selector change
# Monkey-patch an OpenRouter selector in the script to a non-existent element
# Expected: clean structured error within 15s, not a hang. Error reports which selector failed.
```

### Stage Contract
- **Inputs:** Stages 0-4 + Node.js + Chrome/Chromium + Gmail IMAP creds (or equivalent burner-email backend)
- **Outputs:** Working `agentkeys.provision(openrouter)` MCP tool with pattern library (1 pattern) + mandatory verification + observability metrics
- **Done when:** All unit tests pass (including the phantom-key chaos test). At least one successful live provision of a real OpenRouter account, with verification confirming the key works against `GET /api/v1/models`. All observability metrics emitted.

### Stage 5a explicitly does NOT ship
- Claude-Chrome agentic fallback (→ Stage 5b)
- Fallback audit trail (→ Stage 5b)
- LLM script-generator dev tool (→ Stage 5b)
- Fallback→PR loop (→ Stage 5b)
- Additional patterns beyond `signupEmailOtp` (→ Stage 5b, extracted from the 2nd/3rd service as it's added)

### Open item to resolve before first live provision
- [ ] **OpenRouter ToS check:** confirm that scripted account creation does not violate the target service's ToS. Repeat this check for every new service added to Tier 2. Noted in TODOS.md per 2026-04-16 CEO review.

### CLI UX Specifications (2026-04-16 plan-design-review)

User-facing surfaces for Stage 5a — decisions locked to avoid "we'll figure out the output format later":

- **Success output masks the key.** Stdout on success prints exactly one line: `sk-or-v1-****...AB3F` (first 8 chars + `****...` + last 4 chars). Never the full key. Full key is retrieved via `agentkeys read <agent> openrouter` or injected into child processes via `agentkeys run`. Rationale: AgentKeys's whole pitch is "credentials don't leak" — printing a full key to stdout contradicts it (shell history, log aggregators, screen recordings all capture stdout).
- **Progress to stderr during long-running provision.** One plain-text line per phase: `Creating account...`, `Waiting for email verification...`, `Extracting API key...`, `Verifying key against openrouter.ai...`, `Stored.` To stderr, not stdout — so piping / MCP daemon callers can ignore cleanly. No spinners, no TUI animations. Renders correctly under `agentkeys run -- ...` wrappers.
- **Duplicate provision flow.** When a credential for the service already exists: verify the existing key with one `lib/verify.ts` call. If valid: stderr `openrouter already provisioned, key valid (provisioned <relative date>).` No re-signup, stdout prints the masked key. If invalid (revoked/expired): stderr `existing key invalid, re-provisioning...` and proceed with full flow. `--force` flag re-provisions regardless of existing.
- **Error message format.** All new error codes (`PROVISION_IN_PROGRESS`, `TRIPWIRE_SELECTOR_TIMEOUT`, `EMAIL_TIMEOUT`, `VERIFICATION_FAILED`, `PROVISION_STORE_FAILED`, `AUDIT_DEGRADED`) follow the Stage 2 DX spec: `problem + cause + fix + docs link`. Example for `VERIFICATION_FAILED`: `Problem: Provision succeeded but the returned key did not authenticate. Cause: The target service may have rate-limited signup, or the script extracted the wrong element. Fix: Retry in 5 minutes; if persistent, file an issue at <url> with provision audit log. Docs: https://agentkeys.dev/docs/errors#verification-failed`

### CLI UX Specifications for 5b (2026-04-16 plan-design-review)

- **TTY detection for fallback→PR prompt.** Use `atty::is(Stream::Stdin) && atty::is(Stream::Stdout)` in Rust. Prompt only shown when BOTH are TTYs. MCP daemon context (pipes), redirected output (`> log.txt`), and scripted execution all skip the prompt automatically. No environment variable needed. This is the Rust standard for "is this interactive?"
- **TUI prompt text (verbatim).** `Captured a new script from this fallback session. Submit as a draft PR to provisioner-scripts/? [y/N]` — default on Enter is No (capital-N convention). On `y`: write to `/tmp/agentkeys-proposed-<service>-<timestamp>.ts` and print `Draft written to <path>. Review, then run: gh pr create --title "add <service> script" --body-file <path>.md`.

### Eng Review Implementation Notes (2026-04-16 plan-eng-review)

Locked architectural decisions to prevent implementation drift:

- **IPC contract between Rust orchestrator and TS subprocess.** Line-delimited JSON, each line tagged with `type`. Schema defined in `agentkeys-types` as `ProvisionEvent` enum. Tags: `progress` `{step}`, `tripwire` `{kind, step, elapsed_ms}`, `success` `{api_key}`, `error` `{code, details}`. TS side imports the schema via hand-sync (per CLAUDE.md typed-parameters principle — no opaque JSON parsing).
- **Concurrency.** Daemon holds a single `Mutex<Option<ActiveProvision>>`. Second call while one in flight returns `PROVISION_IN_PROGRESS` immediately with the active service name. Mutex poisoning on panic is treated as a recoverable condition (mutex reset + log).
- **Observability transport.** Structured JSON log lines to stderr (e.g. `{"level":"info","event":"provision_metric","name":"tier_used","service":"openrouter","tier":2}`). Prometheus/OTel exporter deferred to v0.1 hardening alongside Stage 8.
- **HAR fixture layout.** `provisioner-scripts/tests/fixtures/<service>/<scenario>.har`. Regeneration script: `npm run record-fixtures -- --service openrouter --scenario signup_happy`. Weekly live smoke auto-regenerates on success. Each fixture directory includes a README with purpose + last-recorded date.
- **Phantom-key chaos test implementation.** Use Playwright `page.route()` + `route.fulfill()` to mock the success-page response with a fixture HTML containing `sk-or-v1-FAKE`. Hermetic, no decoy server needed.
- **Pattern-extraction regression seam.** Write the OpenRouter HAR-driven happy-path test BEFORE extracting `signupEmailOtp`. Commit. Extract pattern. Test must pass with identical output. Enforced at PR review; no direct commits extracting patterns without the prior test commit.
- **Typed error surface.** Shared `ProvisionEvent` enum in `agentkeys-types` consumed by both Rust and TS. Avoids string-code drift between languages.
- **DRY rule for patterns.** `patterns/signup_email_otp.ts` must contain zero references to "openrouter" or any service-specific string. All service-specific data flows as parameters. Trivial acceptance check: `grep -i openrouter patterns/` returns nothing.

### Additional test requirements (from 2026-04-16 eng review)

Added to the unit test table above:

| Test | What it validates |
|---|---|
| `provisioner::ipc_malformed_json` | Subprocess emits an unparseable stdout line → orchestrator aborts with clear error (not a silent skip) |
| `provisioner::concurrent_provision_rejected` | Second provision call while one in flight → returns `PROVISION_IN_PROGRESS` with active service name |
| `provisioner::mutex_recovery_after_panic` | First provision panics → mutex reset → third call proceeds normally |
| `provisioner::verification_endpoint_down` | Target API returns 503 → distinguish from 401 (retry with backoff vs. phantom) |
| `provisioner::store_fails_after_verify` | Verification passes but `store_credential` fails → error response includes the obtained key so the user can recover manually |
| `patterns::signup_email_otp_extraction_regression` | **Must-run before merge:** identical HAR fixture produces identical behavior pre- and post-pattern-extraction |

---

## Stage 5b: Provisioner — Agentic Fallback + Ecosystem Loop (post-v0, v0.1 milestone)

**Goal:** When Stage 5a's deterministic path misses (no script for service, site updated, CAPTCHA, selector drift), the user's own Claude drives Chrome via MCP browser primitives to complete the provision. Every fallback session is audited. Successful human-driven fallbacks optionally propose a PR to seed a new script. A dev-time tool uses the patterns library + LLM to draft candidate scripts for new services.

**Critical constraint — no second API key.** The agentic fallback uses the user's *native* LLM (whichever agent is already calling AgentKeys via MCP — typically Claude Code, Cursor, etc.) by exposing Playwright MCP browser primitives. AgentKeys does not embed its own LLM client or require a separate Anthropic/OpenAI API key for the fallback to function.

### Crates / Packages Modified
- `agentkeys-daemon` — add MCP browser-primitive tools (`browser_navigate`, `browser_click`, `browser_type`, `browser_screenshot`, `browser_read_dom`) exposed over the same MCP channel as credential tools
- `agentkeys-provisioner` — add tier dispatcher, trip-wire detection, fallback engagement, audit emission, fallback→PR draft emission
- `provisioner-scripts/patterns/` — add `oauth_google.ts`, `oauth_github.ts`, `magic_link.ts`, `password_email_verify.ts` (4 additional patterns)
- **New tool:** `agentkeys-scripts-gen` — dev-time script authoring aid, separate binary OR a gstack/Claude skill (decided at implementation time)

### Deliverables
- [ ] MCP browser primitives on daemon (Tier 3 exposed to user's agent via same MCP channel as existing credential tools)
- [ ] Tier dispatcher in `agentkeys-provisioner`: attempts Tier 2 script first; engages Tier 3 fallback on trip-wire. **Each tier attempt is independent — no resume.** When Tier 2 fails at step 7 of 12, Tier 3 starts fresh from the initial URL. Trades one extra browser startup for avoiding half-created-account bugs.
- [ ] Trip-wire detection expanded from Stage 5a: selector timeout (15s), unexpected navigation, HTTP 5xx, email timeout, missing script for service. Generic JS errors and unhandled promise rejections do NOT trigger fallback — those remain hard failures surfaced to the caller.
- [ ] Fallback audit trail: every action (navigate, click, type, screenshot, read_dom) logged with timestamp + target + value + elapsed_ms. Written to `~/.agentkeys/logs/provision-<timestamp>.jsonl` in v0.1. Migrates to on-chain via Pattern 4 (see Stage 9 notes) when the audit submission infrastructure ships.
- [ ] Post-fallback success handler:
  - **Human-driven path (TUI visible):** prompt "Captured a new script from this fallback session. Submit as a PR to provisioner-scripts/? [y/N]". On "y", draft candidate script and write to `/tmp/agentkeys-proposed-<service>-<timestamp>.ts` with a followup prompt to open a PR.
  - **Agent-driven path (no TUI, daemon-only):** never prompt, never auto-submit. Fallback session is audited and terminated cleanly. Guardrail against agents silently opening PRs on the user's behalf.
- [ ] Fallback-session → candidate script conversion: uses the patterns library + LLM-drafted glue to produce a Playwright script composing existing patterns. Always written to a temp path for human review. Never directly committed.
- [ ] **LLM script-generator is the `/agentkeys-record-scraper` Claude Code skill, NOT a separate binary.** Simplification from the original Stage 5b deliverable: we ship a skill, not a compiled tool. Skill location: `~/.claude/skills/agentkeys-record-scraper/SKILL.md`. The skill orchestrates Playwright codegen locally under human supervision, refactors raw codegen into pattern-composed scrapers, runs the full verification gauntlet (HAR tests, IPC contract, live key verification), fixes any code issues found during the session, and stages files for PR. See "Local harness workflow" subsection below.
- [ ] 4 additional patterns extracted as a natural consequence of adding 3-4 more services during Stage 5b: OAuth-Google, OAuth-GitHub, magic-link, password+email-verify. Each new pattern is extracted by the `/agentkeys-record-scraper` workflow when it encounters a signup shape not covered by existing patterns.

### Local harness workflow (added 2026-04-16 per `/agentkeys-record-scraper` skill)

After Stage 5a ships (patterns infrastructure + OpenRouter scraper + verification), adding a new service follows a fully local, LLM-orchestrated harness:

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  maintainer:  /agentkeys-record-scraper  in agentkeys repo      │
  └───────────────────────┬─────────────────────────────────────────┘
                          │
          ┌───────────────▼───────────────┐
          │  Phase 1: gather input         │
          │  (slug, URL, email backend,    │
          │   pattern match)               │
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │  Phase 2: drive session        │
          │  playwright codegen + Claude   │
          │  coaches the human through     │
          │  the signup                    │
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │  Phase 3: refactor raw.ts into │
          │  a pattern-composed scraper    │
          │  (extract new pattern if       │
          │   nothing fits)                │
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │  Phase 4: record HAR fixture   │
          │  + write scrapers/<slug>.test.ts│
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │  Phase 5: verification loop    │
          │  ts tests + cargo tests +      │
          │  live verify(); fix root       │
          │  causes                        │
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │  Phase 6: stage for PR        │
          │  jj describe + optional       │
          │  gh pr create --draft         │
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │  Phase 7: capture learnings    │
          │  (only if non-obvious pattern) │
          └───────────────────────────────┘
```

**Properties:**
- **Local only.** Spawns real browsers, creates real accounts. Never runs in CI.
- **Human in the loop.** Codegen records the human's actions; Claude coaches and refactors. No autonomous account creation.
- **No second API key.** Uses the user's Claude Code session — the LLM doing the refactoring + coaching is the one already driving the skill.
- **Bidirectional learning.** Sessions surface patterns library gaps (no existing pattern fits) or infrastructure bugs (`lib/email.ts` breaks on provider X). The skill fixes the root cause before staging the scraper.
- **Pattern library compounds.** Each session either uses an existing pattern unchanged (reuse win) or extracts a new one (ecosystem growth).

**Invocation:** `/agentkeys-record-scraper` in Claude Code while inside the repo. Full spec: `~/.claude/skills/agentkeys-record-scraper/SKILL.md`.

**Escalation thresholds (where the skill stops):**
- CAPTCHA on signup → skill stops, relies on Stage 5b Tier 3 runtime fallback
- Payment-gated service → out of scope
- No public verification API → flag TODO for manual verify flow
- ToS ambiguity → escalate to project lead

### Unit Tests
```
cargo test -p agentkeys-provisioner -- tier3      # dispatcher + trip-wire + fallback
cargo test -p agentkeys-daemon     -- browser_    # MCP browser primitives
npm test --prefix provisioner-scripts -- patterns/  # all 5 patterns against HAR fixtures
```

| Test | What it validates |
|---|---|
| `dispatcher::tier2_success_no_fallback` | Script succeeds → Tier 3 never engaged → audit log has no fallback section |
| `dispatcher::tier2_selector_timeout_engages_tier3` | Script times out → dispatcher engages fallback with fresh browser starting from URL |
| `dispatcher::tier2_unexpected_nav_engages_tier3` | Script navigates somewhere unexpected → dispatcher engages fallback |
| `dispatcher::no_script_engages_tier3` | Provision for unknown service → dispatcher skips Tier 2, goes straight to Tier 3 |
| `fallback::action_logged` | Every fallback action written to JSONL with timestamp + target + value |
| `fallback::verification_still_mandatory` | Fallback returns a key → Stage 5a's `lib/verify.ts` still runs → phantom keys still caught |
| `fallback::canned_llm_happy_path` | Fallback with pre-recorded LLM actions completes a provision end-to-end (tests dispatcher, not LLM intelligence) |
| `fallback::canned_llm_invalid_action_aborted` | Canned LLM returns an invalid action → dispatcher aborts with clear error (no retry loop beyond 1 attempt) |
| `fallback::pr_prompt_human_path` | Captured session + TUI attached → prompt shown → on "y", draft written to `/tmp/` |
| `fallback::pr_prompt_agent_path_silent` | Captured session + daemon-only (no TUI) → no prompt → no auto-submit → session audited |
| `patterns::oauth_google_happy` | Pattern runs against HAR fixture |
| `patterns::oauth_github_happy` | Pattern runs against HAR fixture |
| `patterns::magic_link_happy` | Pattern runs against HAR fixture |
| `patterns::password_email_verify_happy` | Pattern runs against HAR fixture |
| `scripts_gen::drafts_script` | `agentkeys-scripts-gen <url>` produces a syntactically valid `.ts` file composing patterns |

### Reviewer E2E Checklist
```bash
# Prerequisite: Stages 0-5a + 7 complete (v0 shipped)

# Fallback on selector drift:
# Edit openrouter.ts to use a non-existent selector
# Call agentkeys.provision(openrouter) via MCP
# Expected: Tier 2 times out within 15s → Tier 3 engages with fresh browser →
#           user's Claude drives signup → mandatory verification runs → credential stored.
#           Full audit JSONL in ~/.agentkeys/logs/
# Human TUI path: prompt "submit as script PR?" appears.
# Agent daemon path: completes silently, no prompt.

# Fallback on unknown service:
# Call agentkeys.provision("some_new_service_no_script")
# Expected: dispatcher skips Tier 2, engages Tier 3, user's Claude drives full flow

# Script-generator dev tool:
# Run: agentkeys-scripts-gen https://example.com/signup
# Expected: Chrome opens, maintainer performs signup, tool captures DOM/actions,
#           emits candidate script composing patterns, opens editor for review
```

### Stage Contract
- **Inputs:** Stages 0-5a + 7 complete (v0 shipped)
- **Outputs:** Tier 3 fallback + audit trail + fallback→PR loop (human-gated) + script-gen dev tool + 4 additional patterns
- **Done when:** All 5b unit tests pass. Manual fallback test succeeds for one site that Tier 2 does not cover. Script-gen tool produces a working candidate for a new service in one session. Fallback audit log is human-readable (JSONL with structured fields).

### Security watch-item
Tier 3 engagement exposes the user's agent to prompt injection from hostile pages (a malicious signup page could embed instructions attempting to exfiltrate the verification code or redirect credentials). Per the 2026-04-16 CEO review, v0.1 accepts this risk with **audit trail as after-the-fact detection** rather than a consent gate. Revisit the consent model in v0.2 if fallback usage scales beyond occasional recovery, or if an incident occurs.

### Eng Review Implementation Notes (2026-04-16 plan-eng-review)

Locked architectural decisions for 5b:

- **MCP browser primitives are provision-scoped.** `browser_navigate`, `browser_click`, `browser_type`, `browser_screenshot`, `browser_read_dom` are dynamically added to the MCP tool list only during an active `agentkeys.provision(service)` call that has trip-wired into fallback. Before provision starts: not discoverable. After fallback completes (success OR error): tools removed from discovery. This bounds the attack surface and preserves the "agentkeys is a credential tool, not a general browser automation tool" positioning.
- **Canned-LLM test harness for the dispatcher.** Tests replay pre-recorded `(tool_call, canned_response)` tuples. Harness feeds each canned response in order. Tests assert dispatcher behavior (correct trip-wire handling, verification still runs, audit written, PR-prompt gating). Harness does NOT test LLM intelligence.
- **Tier-attempt independence.** Each tier runs fresh. When Tier 2 script fails at step 7, Tier 3 starts from the initial URL with a fresh browser. Avoids half-created-account bugs at the cost of one extra browser startup. This matches the Stage 5a concurrency model (single mutex) so there's never more than one browser in flight per daemon.
- **Audit log durability.** On disk-full or write failure, fallback continues but flags the session as "AUDIT_DEGRADED" in the returned error/success payload. Don't silently drop audit events; don't block the provision on a log failure.
- **Interrupt safety in TUI PR prompt.** Ctrl-C during the "submit as PR?" prompt exits cleanly, no draft written, no orphaned `/tmp/` files.

### Additional test requirements for 5b (from 2026-04-16 eng review)

| Test | What it validates |
|---|---|
| `mcp::browser_primitives_hidden_before_provision` | Tool list does NOT include `browser_*` tools before provision is invoked |
| `mcp::browser_primitives_visible_during_fallback` | After a trip-wire engages Tier 3, tool list includes `browser_*` tools |
| `mcp::browser_primitives_hidden_after_fallback` | After fallback success OR error, tool list no longer includes `browser_*` tools |
| `dispatcher::tier3_also_fails` | Tier 2 trip-wires, Tier 3 also fails → both errors surfaced to MCP caller (no info loss) |
| `fallback::audit_log_write_fail_degraded` | Disk full during fallback → audit flagged AUDIT_DEGRADED, provision continues |
| `fallback::pr_prompt_ctrl_c_clean` | Ctrl-C during TUI prompt → clean exit, no `/tmp/` draft, no orphan state |

---

## Stage 6: Federated Own Email (`@agentkeys-email.io` hosted default)

**Status (2026-04-19):** next stage after 5a/5b.

**Goal:** Every AgentKeys user (non-developer default) gets a working agent email inbox at `xxxxx@agentkeys-email.io` with zero setup — no DNS, no admin console, no Workspace subscription, no custom domain. Hosted on our AWS SES infrastructure with TEE-held signing keys, per-user isolation enforced via PrincipalTag from JWT claims, chain-immutable audit.

**Why this is Stage 6:** it replaces the Stage 5 "dedicated personal Gmail" quick demo with production infrastructure that scales to every AgentKeys user without per-user setup friction. Moves AgentKeys from "demo email works" to "every agent has an email inbox the moment it exists."

### Architecture summary

See `docs/spec/ses-email-architecture.md` for the full spec. High-level:

1. **We operate `agentkeys-email.io`** — domain registered to AgentKeys, MX pointing at AWS SES `inbound-smtp.us-east-1.amazonaws.com`, DKIM records pointing at TEE-held keys.
2. **TEE-derived keys, both sealed:**
   - `derive("dkim/agentkeys-email.io/v1")` → **Ed25519** DKIM key (RFC 8463) — signs outbound DKIM header
   - `derive("oidc/issuer/v1")` → **ES256** OIDC-issuer key — signs JWTs for AWS STS federation
3. **Inbound path:** SES receives → writes raw MIME to S3 `agentkeys-mail/<user_wallet>/<inbox>/<msg_id>.eml` → no Lambda, no per-email compute on our side.
4. **Outbound path:** agent's daemon asks AgentKeys for temp SES send creds → TEE mints OIDC JWT → `sts:AssumeRoleWithWebIdentity` → daemon calls `SendRawEmail` directly. Our backend does zero work per-send.
5. **Read path:** daemon asks for temp S3 read creds → minted with `PrincipalTag/agentkeys_user_wallet=<wallet>` → daemon calls S3 directly → bucket policy conditions ensure daemon can only read its own user's prefix.
6. **Audit:** every credential mint emits an on-chain extrinsic attributed to the calling child wallet.

### Crates / Packages

- `agentkeys-email-auth` (new Rust crate) — handler for the TokenAuthority covering email-related operations: mint S3/SES temp creds, sign DKIM headers, emit audit extrinsics.
- `agentkeys-mail-receive-stack` (Terraform / CDK module) — one-shot deploy of the SES receipt rule, S3 bucket with PrincipalTag-conditioned policy, IAM role with OIDC trust. Not an AgentKeys crate — shipped as operator infrastructure.
- Daemon updates — new MCP tools: `email.list`, `email.get`, `email.send`. Each unwraps into `agentkeys mint <creds>` + direct SES/S3 call.
- `provisioner-scripts/src/lib/email.ts` — replace the `imapflow`-based fetcher with an S3-direct fetcher backed by minted creds.

### Deliverables

- [ ] `agentkeys-email.io` domain registered, SES domain verified
- [ ] MX + Ed25519 DKIM CNAME + SPF + DMARC published in our DNS
- [ ] S3 bucket `agentkeys-mail` + receipt rule configured
- [ ] IAM OIDC provider `oidc.agentkeys.dev` registered in our AWS account
- [ ] IAM role `agentkeys-agent` with trust policy conditioning on `mrenclave` + non-empty `agentkeys_user_wallet` tag
- [ ] Bucket policy with `${aws:PrincipalTag/agentkeys_user_wallet}` per-prefix isolation
- [ ] TEE-side JWT minter with ES256 derived key at `oidc/issuer/v1`
- [ ] TEE-side Ed25519 DKIM signing (`dkim/agentkeys-email.io/v1`) with locally-signed MIME before SES delivery
- [ ] Thin HTTPS proxy at `https://oidc.agentkeys.dev` serving `/.well-known/openid-configuration` + `/.well-known/jwks.json` (Let's Encrypt)
- [ ] Chain extrinsic pallet for `CredentialMinted` audit events
- [ ] Daemon MCP tools wired to real minted creds
- [ ] Stage 5's `provisioner-scripts` updated to read OTPs from the hosted inbox

### Tests

| Test | What it validates |
|---|---|
| `email::inbox_create_allocates_address` | New agent gets a unique `<id>@agentkeys-email.io` deterministically derived from its wallet |
| `email::inbound_lands_in_user_prefix` | SES receives to `agent-X@agentkeys-email.io` → raw MIME in `s3://agentkeys-mail/0xX/agent-X/...` |
| `email::daemon_reads_own_prefix` | Daemon with `agentkeys_user_wallet=0xA` tag → S3 list/get on `0xA/*` succeeds |
| `email::daemon_blocked_from_other_prefix` | Daemon with `0xA` tag → S3 get on `0xB/*` returns AccessDenied |
| `email::dkim_verifies_at_recipient` | Send test message to a Gmail inbox → receiver sees `DKIM-Signature ed25519` header, Gmail reports `dkim=pass` |
| `email::jwt_without_wallet_claim_denied` | JWT missing `agentkeys_user_wallet` → `sts:AssumeRoleWithWebIdentity` fails per role trust policy |
| `email::audit_emitted_on_mint` | Every SES/S3 credential mint emits a chain extrinsic with `(child, scope, operation, timestamp)` |
| `email::grant_revocation_propagates` | Revoke user's email grant → next mint attempt fails within ≤6s |

### Reviewer E2E Checklist

```bash
# Create an agent; it has an email address
agentkeys agent create my-agent
# → prints: "my-agent has inbox abc123@agentkeys-email.io"

# Send mail to it from outside
echo "test body" | mail -s "hello" abc123@agentkeys-email.io

# Agent reads its inbox
agentkeys run my-agent -- \
  claude-mcp-client email.list | jq
# → shows the hello message

# Agent sends mail
agentkeys run my-agent -- \
  claude-mcp-client email.send \
    --to me@example.com --subject "reply" --text "hi"

# Audit trail on chain
agentkeys usage my-agent --filter email
# → shows mint events for s3.read and ses.send
```

### Stage Contract

- **Inputs:** Stages 0-5a complete; TEE integration available (chain read/write + sealed key derivation); TokenAuthority trait stable.
- **Outputs:** Every AgentKeys user has a working email inbox on `agentkeys-email.io`. No user-side setup required. Per-user isolation enforced cryptographically.
- **Done when:** All 8 tests pass. An agent created via the CLI has a functioning inbox that can send/receive mail with real MTAs. Inbound deliverability verified against at least Gmail + Outlook.

### Deferred to Stage 7+ (not blocking Stage 6)

- Bring-your-own custom domain (`bots.theircompany.com`) — same architecture, different domain id in the DKIM derivation path
- Bring-your-own Workspace (DWD path) — existing `docs/stage5-workspace-email-setup.md` becomes the runbook; not the default
- Email drafts as HITL primitive (daemon-side, per our revised broker-not-proxy thesis)
- Advanced features: labels, threads, allow/block lists — implemented daemon-side in MCP; not server features

---

## Stage 7: Generalized OIDC Provider (universal federation)

**Status (2026-04-19):** follows Stage 6.

**Goal:** `https://oidc.agentkeys.dev` is publicly documented as a universal OIDC identity provider. Any cloud or service that accepts external OIDC federation (AWS IAM, GCP Workload Identity Federation, Azure AD, Snowflake External OAuth, Ali Cloud RAM, Kubernetes, etc.) trusts our TEE-signed JWTs. Advanced bring-your-own paths (custom AWS account, custom GCP project, custom GitHub org) become possible by registering our issuer once per user.

**Why this is Stage 7:** Stage 6 delivers the hosted-default path using OIDC federation inside our own AWS account. Stage 7 generalizes that capability as a public primitive — the same TEE-derived ES256 issuer key now federates into any user's or organization's cloud account without additional key material.

### Architecture summary

See [`wiki/oidc-federation.md`](../../../wiki/oidc-federation.md) for the full design. High-level:

1. **OIDC issuer endpoint** — stable HTTPS URL `https://oidc.agentkeys.dev` with Let's Encrypt cert, static `/.well-known/openid-configuration` and `/.well-known/jwks.json` served by a thin proxy.
2. **One signing key** — ES256 at `derive("oidc/issuer/v1")`, reused from Stage 6. No new key material.
3. **Per-consumer trust registration** — each user / org registers our OIDC issuer once in their cloud account (AWS `CreateOpenIDConnectProvider`, GCP `WorkloadIdentityPool`, Ali RAM `CreateOIDCProvider`, etc.) and sets up an IAM role trust policy.
4. **JWT format is consistent across consumers** — same `sub`, same `aud` varies per consumer, same `agentkeys_*` claim set for tag-based isolation.
5. **Consumer-side per-user isolation** — each consumer's trust policy conditions on `PrincipalTag` / attribute-mapping from the JWT's `agentkeys_user_wallet` claim.

### Cryptographic trust anchor in Stage 7: URL + TLS + JWKS signature

The trust that AWS / GCP / Ali Cloud place in our JWTs is rooted in:

- **The issuer URL** — `https://oidc.agentkeys.dev` is registered once per consumer as an OIDC provider. The consumer fetches our discovery doc and JWKS from this URL.
- **The TLS certificate** on that URL — protects the JWKS fetch against on-path attackers. Consumer libraries typically also validate that the cert chains to a trusted root CA.
- **The JWKS signature** — each JWT is signed with `derive("oidc/issuer/v1")` (ES256); consumers verify the signature using the current JWK served at the URL.

**Hardening we ship with Stage 7 (all standard belt-and-suspenders, zero blockchain dependency):**

- **AWS OIDC thumbprint pinning** — register the TLS cert's SHA-1 thumbprint on each consumer's AWS OIDC provider. Reduces the attack surface from "any CA" to "our specific cert." Documented in the AWS registration runbook and emitted by `agentkeys oidc register aws`.
- **CAA DNS records** on `agentkeys.dev` — only whitelisted CAs may issue for the domain.
- **DNSSEC** where the registrar supports it.
- **Short-lived JWTs (≤5 min `exp`)** — bounds a forged JWT's useful window to minutes even if the URL is compromised mid-flight.
- **Short `Cache-Control` on the JWKS URL** — our published cache directive is short; AWS's JWKS cache is several hours by default, which we accept in Stage 7 and tighten via Stage 7b.
- **Optional `sub`-pattern pinning** by relying parties is **informational-by-default** — the canonical trust-policy examples in [`wiki/tag-based-access.md`](../../../wiki/tag-based-access.md) pin on the issuer URL plus claim conditions (`agentkeys_user_wallet`, `agentkeys_operation`); `mrenclave`/`mrsigner` pinning is presented as an opt-in hardening with a documented rotation cost.

**What this explicitly does *not* defend against in Stage 7 alone:** compromise of the issuer URL itself — DNS hijack, CA misissuance, hosting takeover, or deploy-pipeline compromise. An attacker who controls the URL can replace the JWKS and mint arbitrary JWTs. Stage 7b below is the defense-in-depth layer that collapses the blast window for this class of attack from indefinite to seconds.

### Crates / Packages

- Primarily **operator/documentation work** — the TEE signing path already exists from Stage 6. Stage 7 adds:
- `agentkeys-oidc-registration-cli` (new) — CLI commands that emit ready-to-paste configuration snippets for each major cloud:
  - `agentkeys oidc register aws --account <id> --region <r>` → prints the AWS CLI commands + JSON trust policy
  - `agentkeys oidc register gcp --project <id>` → prints the gcloud commands for Workload Identity Pool
  - `agentkeys oidc register alicloud --account <id>` → prints ali CLI commands
  - `agentkeys oidc register github-app` → registers a new GitHub App installation path using derived ECDSA app key

### Deliverables

- [ ] `https://oidc.agentkeys.dev` publicly reachable, stable, documented
- [ ] Discovery doc + JWKS published and cacheable; rotation procedure documented
- [ ] AWS IAM OIDC registration runbook (for operators' own AWS accounts)
- [ ] GCP Workload Identity Federation registration runbook
- [ ] Ali Cloud RAM OIDC provider registration runbook
- [ ] Azure AD Federated Credential registration runbook
- [ ] `agentkeys-oidc-registration-cli` with four `register` subcommands
- [ ] Integration tests: end-to-end credential mint for each of the four clouds
- [ ] GitHub App (`AgentKeys Memory`) registered, ECDSA app key derived at `derive("github-app/v1")`, installation-token minting path
- [ ] Public documentation: "How to connect your AWS account to AgentKeys"

### Tests

| Test | What it validates |
|---|---|
| `oidc::discovery_doc_valid` | `curl https://oidc.agentkeys.dev/.well-known/openid-configuration` returns valid OIDC metadata |
| `oidc::jwks_served` | JWKS endpoint returns current ES256 public key with correct `kid` |
| `oidc::aws_federation_end_to_end` | TEE-minted JWT exchanged at AWS STS → usable temp creds → target S3 op succeeds |
| `oidc::gcp_federation_end_to_end` | Same flow via GCP Workload Identity Federation → GCS op succeeds |
| `oidc::alicloud_federation_end_to_end` | Same via Ali Cloud RAM → OSS op succeeds |
| `oidc::azure_federation_end_to_end` | Same via Azure AD Federated Credential |
| `oidc::key_rotation_dual_key_window` | Both v1 and v2 keys in JWKS during rotation window; JWTs signed by either accepted |
| `oidc::tag_claim_required_for_tagged_role` | JWT without `agentkeys_user_wallet` claim → role assumption denied where bucket policy requires tag |
| `github_app::installation_token_mint` | TEE signs app-level JWT with derived ECDSA → GitHub returns installation token |
| `registration_cli::aws_commands_executable` | `agentkeys oidc register aws ...` output runs on a fresh AWS account and registers successfully |

### Reviewer E2E Checklist

```bash
# Register our OIDC provider in a fresh test AWS account
agentkeys oidc register aws --account 999999999999 --region us-east-1
# → prints commands; run them; IAM provider `oidc.agentkeys.dev` shows up

# Create a role in that AWS account trusting our provider with PrincipalTag condition
# (commands included in the CLI output)

# Demonstrate federation from an agent
agentkeys run test-agent -- \
  aws s3 ls s3://their-bucket/
# → succeeds; CloudTrail shows the assumed role with the session tag

# Rotate the issuer key; verify zero-downtime
agentkeys oidc rotate --window 24h
# → JWKS now has both v1 and v2; new JWTs signed with v2

# Install the GitHub App on a test org
# (via GitHub UI)
agentkeys run test-agent -- \
  claude-mcp-client github.list_repos --owner testorg
# → succeeds; mint shows in our audit log
```

### Stage Contract

- **Inputs:** Stage 6 complete (OIDC issuer key and endpoint exist but are only used internally for our own AWS account).
- **Outputs:** Our OIDC provider is a publicly documented federation target. Users can plug their own AWS / GCP / Azure / Ali Cloud / GitHub accounts into AgentKeys without giving us static credentials.
- **Done when:** All 10 tests pass. End-to-end federation verified against at least AWS, GCP, and Ali Cloud. Registration CLI tested by a fresh external operator.

### Deferred past Stage 7

- Enterprise-specific advanced integrations (SAML federation, SCIM provisioning) — tracked in [`docs/spec/post-v0.1-future-work.md`](../post-v0.1-future-work.md) §7
- Per-tenant OIDC issuer URLs (`oidc.agentkeys.dev/tenant/<id>/`) with isolated issuer keys per tenant — §2.4 of future-work
- TEE-hosted OIDC endpoint (attestation-rooted TLS, not URL-rooted) — §2.1 of future-work
- Workload Identity Federation into consumer clouds like Cloudflare, Fly, etc.

---

## Stage 7b: URL-hijack defense (chain-anchored JWKS + watchdog)

**Status (2026-04-20):** one-sprint follow-on to Stage 7. Small, cheap, large security win.

**Goal:** close the gap between "Stage 7 cryptographic trust anchor is URL + TLS + signature" and "we want chain-anchored trust." Specifically: make URL compromise **detectable and revocable in seconds** rather than silently catastrophic. Foreign clouds (AWS / GCP / Ali) still can't speak Substrate, so Stage 7b targets detection + response, not prevention on foreign clouds. Prevention on foreign clouds is [`post-v0.1-future-work.md`](../post-v0.1-future-work.md) §2.1 / §2.3.

**Why this is Stage 7b and not Stage 8:** Stage 7's URL-only trust anchor is the single largest unmitigated class of risk left in the architecture. The fix (one pallet + one watchdog) is ~1 sprint. Deferring past v0.1 leaves a known, understood hole open for the entire v0.1 window. Shipping it inside the v0.1 milestone is cheap insurance.

### Architecture summary

Two new on-chain primitives plus one off-chain watchdog:

1. **`pallet-oidc-pubkeys`** — on-chain authoritative registry of currently valid OIDC-issuer public keys.
   - Extrinsic: `register_oidc_key(kid, pubkey, attestation_quote, active_from, active_until)` — callable only by the TEE via the existing TEE-submitter pattern.
   - Extrinsic: `revoke_oidc_key(kid, reason)` — callable by governance (fast-track for incident response).
   - Query: `active_oidc_keys() → Vec<(kid, pubkey)>`.
2. **`pallet-enclave-successors`** — on-chain list of authorized MRSIGNERs for MRSIGNER-rotation handoffs (see [`heima-gaps-vs-desired-architecture.md`](../heima-gaps-vs-desired-architecture.md) §9).
   - Extrinsic: `authorize_mrsigner(mrsigner, effective_from)` — governance-gated.
   - Query: `authorized_mrsigners() → Vec<MrSigner>`.
3. **OIDC watchdog** — a small off-chain process that every ~30 s fetches both:
   - Chain: `pallet-oidc-pubkeys::active_oidc_keys()`.
   - URL: `https://oidc.agentkeys.dev/.well-known/jwks.json`.

   On mismatch → (a) page on-call, (b) auto-call `aws iam remove-client-id-from-open-id-connect-provider` (or equivalent per cloud) on AgentKeys-owned federation trusts to cut their ability to accept our JWTs immediately, (c) file an on-chain `revoke_oidc_key` extrinsic with reason = `jwks_url_drift_detected`.

4. **Daemon-side dual verification for AgentKeys-owned relying parties.** Our own daemon, before exchanging a JWT at AWS STS against *our* accounts, queries `pallet-oidc-pubkeys` and rejects JWTs whose `kid` is not in `active_oidc_keys()`. Closes the URL-hijack hole entirely for our own infra. Customer BYO accounts still rely on the URL — they benefit from detection (watchdog) but not from dual verification unless they opt in.

### Crates / Packages

- `pallets/oidc-pubkeys/` (new, in the Heima fork) — small pallet; extrinsics + storage + events.
- `pallets/enclave-successors/` (new) — even smaller; stores the authorized-MRSIGNER list.
- `crates/agentkeys-oidc-watchdog/` (new) — standalone binary; Substrate RPC client + HTTPS fetcher + alerting + cloud-revocation adapter per cloud.
- `crates/agentkeys-daemon/` — extend OIDC-JWT-exchange code path with the on-chain kid check (behind feature flag `chain_verified_oidc`, on by default for AgentKeys-owned accounts, off by default for customer BYO accounts).
- **Mock-side mirrors:** `crates/agentkeys-mock-server/src/handlers/oidc_pubkeys.rs` and `enclave_successors.rs` replicate the two pallets' extrinsics + queries over HTTP so local dev + Stage 4/5 tests don't need a Heima node.

### Deliverables

- [ ] `pallet-oidc-pubkeys` in the Heima fork; extrinsics + storage + events; unit tests
- [ ] `pallet-enclave-successors`; same shape
- [ ] Mock-server HTTP endpoints mirroring both pallets, under `/mock/oidc-pubkeys/*` and `/mock/enclave-successors/*`
- [ ] `agentkeys-oidc-watchdog` binary: chain + URL fetch, mismatch detection, per-cloud revocation adapter (AWS first; GCP / Ali in follow-ups)
- [ ] Daemon dual-verification code path (`chain_verified_oidc` feature)
- [ ] Operator runbook: "OIDC URL drift incident response" (detection → revoke in AWS OIDC provider list → rotate cert → re-publish → re-register)
- [ ] Integration test: simulate URL drift by serving a rogue JWKS on a test endpoint; assert watchdog fires < 60 s; assert AWS revocation succeeds; assert daemon dual-verify rejects rogue JWTs

### Tests

| Test | What it validates |
|---|---|
| `pallet::oidc_pubkeys_register_by_tee_only` | Non-TEE submitter cannot call `register_oidc_key`; returns `NotAuthorizedSubmitter`. |
| `pallet::oidc_pubkeys_query_returns_active_only` | Keys past `active_until` are excluded from `active_oidc_keys()`. |
| `pallet::enclave_successors_governance_gated` | Non-governance call to `authorize_mrsigner` fails. |
| `watchdog::detects_jwks_drift_under_60s` | Rogue JWKS served on test URL; watchdog polls; mismatch detected; alert fired; AWS revocation invoked. |
| `daemon::dual_verify_rejects_unknown_kid` | JWT signed by an off-chain kid is rejected before reaching AWS STS; metric `oidc.dual_verify.rejected` increments. |
| `daemon::dual_verify_byo_opt_in` | Customer BYO mode (`chain_verified_oidc=false`) passes the JWT through to AWS without the chain check (preserves current Stage 7 behavior). |
| `mock::oidc_pubkeys_endpoint_parity` | Mock server `/mock/oidc-pubkeys/active` returns the same shape as the pallet query. |

### Reviewer E2E Checklist

```bash
# Spin up mock chain + mock OIDC URL + watchdog
cargo run --release -p agentkeys-mock-server &
cargo run --release -p agentkeys-oidc-watchdog --config harness/watchdog-test.toml &

# Register an OIDC kid on the mock chain
curl -X POST http://127.0.0.1:8090/mock/oidc-pubkeys/register \
  -d '{"kid":"v1","pubkey":"...","active_from":0,"active_until":999999999}'

# Serve a matching JWKS on the URL side — watchdog stays silent
# Flip the URL-side JWKS to a different key — watchdog should alert within 30 s
python harness/serve-rogue-jwks.py &
# Expected: within 30 s, watchdog logs "JWKS_URL_DRIFT_DETECTED" and fires the revocation adapter

# Verify daemon dual-verify path
agentkeys run test-agent -- \
  aws s3 ls s3://agentkeys-mail/
# On our own infra: succeeds with chain-verified kid.
# If rogue JWKS is active and daemon is in chain-verify mode: fails closed with DualVerifyRejected.
```

### Stage Contract

- **Inputs:** Stage 7 complete (`oidc.agentkeys.dev` live, public, working).
- **Outputs:** URL-hijack attacks on the JWKS endpoint are detected within 30–60 s and auto-revoked on AgentKeys-owned federation trusts. Our own daemon refuses to exchange JWTs whose kid is not on-chain. `pallet-enclave-successors` is available for the Stage 9 MRSIGNER-rotation procedure.
- **Done when:** All 7 tests pass. Drift-simulation integration test succeeds end-to-end. Runbook reviewed by security.

### Deferred past Stage 7b

- TEE-hosted OIDC endpoint (prevents compromise instead of just detecting it) — [`post-v0.1-future-work.md`](../post-v0.1-future-work.md) §2.1
- On-chain TLS cert fingerprints with dual-update requirement — §2.3
- Per-tenant OIDC issuer keys — §2.4
- GCP + Ali revocation adapters in the watchdog (AWS-first for v0.1; others follow)

---

## Stage 6 (POSTPONED; original scope: npm Package + DX Polish)

> **Status (2026-04-16 CEO review): POSTPONED past v0.** v0 ships at Stage 7 with `cargo install` and GH-release prebuilt binaries as the distribution path. npm packaging, `install.sh`, README polish, and the remaining DX artifacts move to the v0.1 milestone alongside Stage 5b and Stage 8. Stage 6 content below is preserved as-is for v0.1 execution — no scope change to Stage 6 itself, only a dependency relaxation.
>
> **Watch-item to prevent drift:** file a v0.1 milestone with Stage 6 as a named deliverable. "Post-MVP packaging" without a milestone rots.

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

## Stage 7 (POSTPONED; original scope: Full E2E Integration + MCP Auth Demo)

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

## Stage 8 (POSTPONED; original scope: Production Hardening, Post-MVP)

**Goal:** Close the daemon-side memory hygiene gaps not covered by Stage 3 kernel hardening, plus CLI defensive features and credential lifecycle controls. Stage 3 protects against external probes (ptrace, `/proc/pid/mem`, swap, core dumps); Stage 8 protects against internal bugs and reduces the in-memory exposure window for credential bytes that flow through the daemon between backend fetch and agent delivery.

### Why this is a separate stage from Stage 3

Stage 3 covers **kernel-enforced** hardening: process isolation against external probes via `memfd_secret`, `mlock2`, seccomp-bpf, capability drop. Those features close the threat model where a co-tenant or unprivileged attacker tries to read the daemon's memory through OS interfaces.

Stage 8 covers **process-internal** hardening: making sure credential bytes flowing through the daemon's own code do not linger in heap allocations after they should have been freed, do not appear in core files if the daemon crashes, and do not cache beyond the agent's actual need. This is defense against bugs in the daemon itself, against race conditions in the credential lifecycle, and against operator mistakes (running a daemon with permissive `ptrace_scope`, leaving cached credentials too long).

Both layers are necessary. Stage 3 alone leaks plaintext into freed-but-not-zeroed heap pages between requests; Stage 8 alone leaks plaintext to ptrace if seccomp is bypassed.

### Crates Modified
- `agentkeys-daemon` — credential lifecycle, memory zeroization, idle eviction
- `agentkeys-cli` — `whoami` subcommand, idempotent `init`, optional zeroize wrapping
- `agentkeys-types` — `SecretString` / `Zeroizing` wrappers on `Session.token` and credential payloads
- `agentkeys-mcp` — credential drop after delivery

### Real exposure window (read this before the priorities)

Where the credential actually spends its time:

```
backend         daemon                    agent
─────────────────────────────────────────────────────────────────
                  fetch ────►
       ◄──── plaintext (~50ms)
                  serialize MCP (~1ms)
                  send over socket ────►
                                    agent decodes
                                    agent uses credential for
                                    the entire task (minutes–hours)
                                    agent exits
─────────────────────────────────────────────────────────────────
       DAEMON WINDOW: ~50ms     AGENT WINDOW: minutes to hours
```

The credential's dominant residence is in **agent memory** after delivery, not in daemon memory before delivery. The daemon window is ~50ms; the agent window is 1000x to 100,000x longer, in the agent process's regular heap with no zeroize and no scrubbing. Daemon-side hardening is necessary but not sufficient — even with perfect daemon hygiene, the credential lives in the agent's address space for the entire duration of the task.

The Stage 8 priority ranking reflects this. **Priority A items shrink the agent window** (or are foundational types every other item depends on). **Priority B items shrink only the daemon window** — still worth doing as defense in depth, but they are not the dominant mitigation. The original ranking inverted this; it has been corrected based on the Stage 4 review.

### Daemon Deliverables — Priority A (shrink the dominant exposure window)

- [ ] **`zeroize` / `SecretString` wrappers** on every type that holds credential plaintext or session tokens. Touched types: `Session.token`, `CredentialBackend::read_credential` return type, MCP `get_credential` response builder, daemon-internal credential cache (if any). `Drop` impl actively zero-fills the underlying buffer. **Foundational** — every other item below assumes credentials flow through these types.
- [ ] **Daemon-mediated `cmd_run` for agentkeys-managed runtimes.** Move the `cmd_run` flow from CLI to daemon for runtimes we ship (`agentkeys run`, the MCP `agentkeys.run` tool). Daemon holds the credential in `memfd_secret`, forks the child, sets the env var in the child's address space, drops the parent's copy before `exec`. CLI never touches plaintext. **This shrinks the agent window** by keeping the credential out of the long-lived parent address space and limiting it to exactly the child process that needs it. We control both ends so no upstream cooperation is needed; this is achievable in v0.1.
- [ ] **`memfd_secret`-via-SCM_RIGHTS delivery for the `agentkeys.get_credential` MCP tool, agentkeys-managed runtime path.** When the requesting agent is running an agentkeys-managed runtime (one that knows how to read a credential from a passed fd), the daemon writes the credential into a `memfd_secret` and sends the fd via SCM_RIGHTS instead of inlining the bytes in the MCP response. The agent reads once, closes the fd, and the bytes never enter its regular heap. Falls back to inline bytes for runtimes that don't advertise fd support. **This shrinks the agent window** for the dominant path (MCP-delivered credentials).
- [ ] **Idle credential eviction.** Configurable TTL (default 60s) after which any cached credential is wiped from daemon memory even if the agent is still running. Closes the case where an agent fetches a credential, idles for a long time, then resumes — instead of holding the credential the whole time, the daemon re-fetches.
- [ ] **Daemon-internal audit trail.** Log every credential fetch / deliver / drop / evict event with timestamp, agent_id, service. Surfaces compromise attempts that the backend audit log alone cannot see (e.g., a suspicious read pattern from inside a single agent session). Foundational for detection regardless of which mitigations are in place.

### Daemon Deliverables — Priority B (shrink the daemon window; defensive depth)

These items shrink only the ~50ms daemon window. They are still worth doing because compromise of the long-lived daemon process is a real threat (the daemon holds the master session, scope information, and is the privileged process inside the sandbox), and dropping per-call removes the "retroactive enumeration" attack where a compromised daemon hands over every credential it has ever fetched. But the marginal security win is small relative to Priority A.

- [ ] **Drop credential from daemon memory immediately after MCP delivery.** When `agentkeys.get_credential` returns to the agent, the daemon's local copy is wiped before the function returns. No caching unless explicitly configured per-service. *Demoted from Priority A in the Stage 4 review:* this only defends against daemon compromise + retroactive enumeration, not against the dominant agent-side exposure window.
- [ ] **`setrlimit(RLIMIT_CORE, 0)`** at daemon startup. Belt-and-suspenders against `prctl(PR_SET_DUMPABLE, 0)` from Stage 3. Covers the path where dumpable is re-enabled by a buggy library or where a fork inherits permissive defaults.
- [ ] **`pkey_alloc` + `pkey_mprotect` per-credential page protection** (Linux 4.9+, x86 only). Marks credential pages `PROT_NONE` except during active read. Defense against in-process bugs that try to dereference the wrong pointer.
- [ ] **Secure-scrubbing global allocator.** Use `mimalloc` with secure mode, or `scudo`. Zeros heap allocations on free, adds guard pages, randomizes allocation order. Catches the gap where `Drop` impls don't run (panics, aborts, leaks).
- [ ] **`ptrace_scope` runtime check** at startup. Refuse to launch (or warn loudly and continue) if `kernel.yama.ptrace_scope < 1`. Stops daemons from running on hosts where any user process can ptrace siblings.
- [ ] **CI verification of binary hardening.** Run `checksec` or equivalent on `cargo build --release` artifacts to confirm PIE, RELRO (full), stack canaries, and NX bits. Add as a CI gate so a build with weakened flags fails the pipeline.
- [ ] **Anti-debugger check.** `prctl(PR_SET_DUMPABLE, 0)` + check `TracerPid` in `/proc/self/status` at startup. If a debugger is attached at launch (TracerPid != 0), refuse to start unless an explicit `--allow-debugger` flag is set.

### Daemon Deliverables — Priority C (broader runtime cooperation, v0.2+)

- [ ] **Extend `memfd_secret`-via-SCM_RIGHTS delivery to non-agentkeys-managed agent runtimes.** Most upstream LLM frameworks today expect a `String` env var, not an fd to read from. Getting them to support fd-based credential reads requires upstream changes. Until those land, the Priority A path covers only runtimes we ship; this Priority C item generalizes the same protection to arbitrary runtimes once cooperation is available.
- [ ] **Daemon-mediated `cmd_run` for arbitrary parent processes.** The Priority A version covers `agentkeys run` and `agentkeys.run` (paths we control). Generalizing the daemon-mediated fork-and-drop pattern to arbitrary parent processes that want to spawn a child with credentials is a v0.2+ item.

### CLI Deliverables

- [ ] **`agentkeys whoami`** subcommand. Print non-sensitive session metadata: wallet, scope, expiry, ttl remaining. Never prints `session.token`. Replaces the `ak-keychain-show | jq` pattern in `docs/manual-test-stage4.md` with a native, zero-prompt equivalent. ~15 LOC.
- [ ] **Idempotent `agentkeys init`.** If a valid (unexpired) session already exists in the keychain, print `"Already initialized as <wallet>"` and exit without minting a new one. `--force` overrides. Eliminates the find-then-update double-prompt path on macOS for repeated `init` calls. Matches `git init`, `gh auth login`, `gcloud auth login`, `kubectl config`.
- [ ] **`zeroize` wrapping for credential strings** in `cmd_read` and `cmd_run`. Optional given the CLI's short lifetime, but cheap and consistent with the daemon-side work. Covers the "core dump grabs plaintext credential" threat for the CLI.
- [ ] **`prctl(PR_SET_DUMPABLE, 0)` + `setrlimit(RLIMIT_CORE, 0)`** on CLI startup (Linux only — macOS already disables core dumps for unsigned binaries). One-liner each at the top of `main`.
- [ ] **Wire CLI `read` to honor `AuthRequestType::HighValueRelease`.** The mock backend already supports the enum variant; the CLI needs to detect a pending high-value-release response and route the user through `agentkeys approve`. Sensitive credentials (configured server-side) require human-in-the-loop release before the bytes ever leave the backend.

### Optional Storage Hardening

- [ ] **Touch-ID-gate the master session on macOS.** Use `kSecAttrAccessControl = kSecAccessControlUserPresence` when storing the master session via `keyring-rs` (or drop to `security-framework` directly for the access-control flag). Forces biometric on every CLI invocation that loads the session. Master session only — child sessions used by agents stay silent. Best-of-both-worlds UX. macOS only; Linux/Windows do not have a direct equivalent.
- [ ] **DEK + encrypted file pattern.** Cross-platform alternative to Touch ID. Store a 32-byte data encryption key (immutable after creation) in the OS keyring at `agentkeys/master-key`; store the session JSON encrypted at `~/.agentkeys/session.enc` (XChaCha20-Poly1305 or AES-GCM). Keyring item is never updated → no double-prompt update path. `security find-generic-password -w` returns useless random bytes, not a token. ~60 LOC + `chacha20poly1305`/`hex`/`rand` deps.

### Unit Tests

```
cargo test -p agentkeys-daemon -p agentkeys-cli -p agentkeys-types
```

| Test | What it validates |
|---|---|
| `daemon::credential_zeroize_on_drop` | After dropping a `SecretString` credential, the underlying buffer is zero-filled (probe via raw pointer in test-only inspector) |
| `daemon::credential_dropped_after_mcp_delivery` | After `agentkeys.get_credential` returns, the daemon-side copy is no longer in memory |
| `daemon::idle_eviction_fires` | A cached credential is wiped after the configured idle TTL |
| `daemon::rlimit_core_zero` | After init, `getrlimit(RLIMIT_CORE)` returns 0 |
| `daemon::ptrace_scope_check_warns` | Daemon logs a warning (or refuses to start, per config) if `ptrace_scope == 0` |
| `daemon::tracer_pid_check` | Daemon refuses to start if launched under a debugger and `--allow-debugger` is not set |
| `daemon::pkey_protected_pages` | (Linux x86) Credential pages report `PROT_NONE` between accesses |
| `daemon::audit_lifecycle_logged` | Every fetch / deliver / drop event appears in the daemon-internal audit log |
| `cli::whoami_no_token` | `agentkeys whoami` output never contains the session.token value (regex check) |
| `cli::whoami_prints_metadata` | `agentkeys whoami` prints wallet, scope, and expiry |
| `cli::init_idempotent` | Calling `init` twice with the same auth_token returns the existing session, no new keychain write |
| `cli::init_force_recreates` | `init --force` mints a new session even when one exists |
| `cli::high_value_release_pending` | `read` of a high-value credential returns a pending auth request, not the credential bytes |
| `cli::dumpable_off_linux` | (Linux only) After CLI startup, `Dumpable: 0` in `/proc/self/status` |
| `types::session_token_is_secret_string` | `Session.token` field is a `SecretString`, not a plain `String` |

### Reviewer E2E Checklist

```bash
# 1. Daemon credential lifecycle
agentkeys init --mock-token stage8-test
agentkeys store $WALLET openrouter sk-stage8-test
# Start daemon, attach to it from an MCP client, call get_credential, observe daemon logs:
#   expect: fetch → deliver → drop within milliseconds
#   verify: daemon RSS does not retain the credential bytes (use the test-only memory inspector)

# 2. Idle eviction
# Configure daemon with idle_ttl=10s, fetch a credential, wait 15s, fetch again
# Expect: second fetch hits backend (audit log shows two reads), not cache

# 3. whoami
agentkeys whoami
# Expected: wallet, scope, expiry, no token, zero keychain prompts on subsequent calls

# 4. Idempotent init
agentkeys init --mock-token stage8-test       # creates session
agentkeys init --mock-token stage8-test       # → "Already initialized as 0x..."
agentkeys init --mock-token stage8-test --force  # mints fresh session

# 5. High-value release gate
# Configure a service as high-value on the backend
agentkeys read $WALLET sensitive-service
# Expected: returns a pending auth request with an approval code, NOT the credential
agentkeys approve <code>
# After approval, repeat the read → returns the credential

# 6. Touch-ID gate (macOS only, optional)
# Reinstall master session with kSecAccessControlUserPresence flag
agentkeys read $WALLET openrouter
# Expected: Touch ID prompt before the read proceeds
```

### Stage Contract
- **Inputs:** Stages 0-7 complete
- **Outputs:** Hardened daemon and CLI; optional Touch-ID / DEK storage
- **Done when:** All Priority A daemon items implemented, all CLI items implemented, all 15 unit tests pass, manual review confirms credential bytes do not survive in daemon memory beyond the configured eviction window. Priority B items may slip to a follow-up issue if needed; Priority C is explicitly v0.2+.

---

## Stage 9 (POSTPONED; original scope: v0.1 Heima Migration Design Decisions Holding Pen)

**Purpose:** Capture v0.1-specific design decisions that were resolved during v0 planning so they don't have to be rediscovered when migration begins. This is **not a formal stage** in the sense of Stages 0-8 — no harness deliverables, no unit tests, no stage-done script. It is a design notes section for things that were decided now but will be executed later.

When the v0 → v0.1 migration actually begins, this section should be refactored into stages 9, 10, 11... with concrete deliverables, tests, and contracts, following the same harness pattern as Stages 0-8.

### Design decision: Audit submission uses Pattern 4 (TEE-as-paymaster per-read sponsored audit)

**Context.** Every credential read must emit an on-chain audit event to preserve the "tamper-evident public audit log" security property that is AgentKeys's core differentiator against 1Password (`docs/spec/heima-cli-exploration.md:85`). The naive implementation — "cold-first-read" — submits the audit extrinsic synchronously and waits for block inclusion before returning the credential. This adds ~6s (one Heima block time) to the first read of every session. For interactive flows this is annoying; for unattended agent flows it is a product killer.

**Decision.** Adopt **Pattern 4: TEE-as-paymaster per-read sponsored audit** as the default v0.1 design.

How it works:

1. CLI builds and signs a `read_credential` request with the session private key.
2. TEE receives the request, verifies the session signature and scope, decrypts the credential (all TEE-local operations, ~50ms).
3. **TEE returns the credential immediately** to the caller — no chain round-trip on the hot path.
4. In parallel and fully decoupled from the serve, the TEE builds an audit extrinsic, signs it with the **user's wallet key** (TEE-held per `pallet-bitacross` pattern — `docs/spec/1-step-analysis.md:88`), and submits it via a paymaster.
5. The audit extrinsic arrives on-chain in the next block (~6s later). The event attributes the read to the user's wallet address as the semantically correct subject.
6. The user does not wait for the audit extrinsic to confirm. Serve and audit are fully decoupled in the critical path.

**Key property:** this works because the TEE already holds the user's wallet private key (Heima design, `pallet-bitacross` pattern). The TEE can sign extrinsics *as* the user without the user's explicit per-call involvement. This is the meta-transaction / gasless-transaction pattern (EIP-2771 on Ethereum, custom signed extension on Substrate), applied specifically to audit submission.

### Design decision: Fee funding uses Option A (AgentKeys operators subsidize)

The paymaster in Pattern 4 has to be funded somehow. Three options were considered:

- **Option A (chosen for v0.1):** AgentKeys operators fund a treasury account that covers all audit extrinsics. Cost grows linearly with usage × reads/user. Sustainable via a per-user fee structure at deployment time. Requires no Heima runtime changes — works today on any Substrate chain with a standard fee system. This is the hosted-AgentKeys model.
- **Option B (filed for future reconsideration):** Heima protocol subsidizes TEE-originated audit extrinsics as "free calls" at the runtime level. Most elegant architecturally — zero per-read cost to anyone, cost borne by validators as part of base chain operation. Blocked on Heima runtime changes; requires a new pallet primitive for free TEE-originated calls. Revisit once Kai confirms whether this is in scope for the AgentKeys pallet integration (see `docs/spec/heima-open-questions.md`).
- **Option C (filed for future reconsideration):** User's own wallet pays fees from its existing USDC balance (the same balance that holds x402 funds). No treasury, no paymaster infrastructure. Rejected for v0.1 because it mixes "wallet pays gas" with "wallet is user's identity" roles and creates confusing error UX when the balance runs low. Could be offered as an opt-in mode for self-hosted deployments where users prefer to pay their own audit fees directly.

**Why Option A over Option B/C:** Option A works with the existing Substrate runtime with no pallet changes, matches the hosted-service model that AgentKeys plans to offer, and lets us ship v0.1 on Kai's existing TEE worker without blocking on runtime modifications. Options B and C remain open for future reconsideration.

### Design decision: TEE-side per-session read rate limit (abuse defense)

Independent of the audit submission pattern, the TEE enforces a per-session read rate cap — default **100 reads per minute per session**, configurable at session creation. Excess reads return a rate-limit error to the agent.

**Why this is needed regardless of audit pattern.** Without a rate limit, an abusive or buggy agent could trigger thousands of credential reads per second, which (a) drains the paymaster treasury in Option A, (b) overwhelms any fast-path TEE worker, and (c) creates audit log spam that makes real compromise hard to detect. Putting the rate limit at the **credential-read layer** (not at the audit-submission layer) defends everything downstream simultaneously: if you can't do 10,000 reads/second, you can't cause 10,000 audit submissions/second, and you can't exfiltrate credentials 10,000 times/second either.

The rate limit is also a Stage 8 item in its own right — it is a general abuse defense, not specific to Pattern 4 — but it becomes load-bearing for Pattern 4's paymaster-funded model and must ship before Pattern 4 can safely deploy. Full design in [issue #4](https://github.com/litentry/agentKeys/issues/4).

### Deferred decisions (not yet resolved)

- **Cross-pattern mixing:** whether to offer Pattern 4 (default) with an opt-out to synchronous-on-chain audit for users who want hard guarantees over latency. Probably yes, as a `--sync-audit` CLI flag, but not blocking v0.1.
- **Paymaster DoS protection beyond rate limiting:** whether to add a per-user audit-fee budget cap that reports an error when exceeded, in addition to the rate limit. Probably yes for hosted AgentKeys, probably no for self-hosted.
- **Audit submission failure handling:** what happens when the paymaster fails to submit an audit extrinsic (chain halted, paymaster out of funds, network issue)? Options: TEE holds a pending-audit queue with retry + backoff; TEE circuit-breaks further reads from the affected session until the queue drains; TEE logs the failure locally and flushes later. Each has different durability tradeoffs. Needs explicit design before v0.1.

### Tracked separately

The full design and implementation plan for Pattern 4 is tracked in [issue #5](https://github.com/litentry/agentKeys/issues/5), labeled `enhancement` and tagged for v0.1. The Stage 9 section above is the design notes; the issue is the execution plan. Companion wiki: [`wiki/serve-and-audit.md`](../../../wiki/serve-and-audit.md) — visual pattern comparison, latency budget table, scoring matrix.

Related issues:
- [issue #3](https://github.com/litentry/agentKeys/issues/3) — Stage 8 production hardening (daemon memory hygiene + CLI defensive features)
- [issue #4](https://github.com/litentry/agentKeys/issues/4) — TEE-side per-session read rate limit (Pattern 4 prerequisite)
- [issue #5](https://github.com/litentry/agentKeys/issues/5) — Pattern 4 implementation for v0.1 audit submission

---

## Summary

| Stage | What ships | Milestone | Depends on | Est. effort | Tests |
|---|---|---|---|---|---|
| 0 | Types + CredentialBackend trait | v0 | — | 2-3 days | 8 unit |
| 1 | Mock backend (25 endpoints + identity linking) | v0 | Stage 0 | 5-7 days | **37** unit + curl smoke |
| 2 | CLI (10 commands) | v0 | Stages 0, 1 | 4-5 days | 14 unit + E2E checklist |
| 3 | Daemon + MCP + hardening | v0 | Stages 0, 1 | 4-5 days | 13 unit + hardening checks |
| 4 | Pair/Approve + Recover | v0 | Stages 0-3 | 3-4 days | 11 unit + 2-terminal E2E |
| 5a | Provisioner Tier 1+2 (OpenRouter + `signupEmailOtp` pattern + **mandatory verification**) | v0 | Stages 0-4 | 3-4 days | 15 unit + phantom-key chaos + live provision |
| 5b | Provisioner Tier 0+3 (agentic fallback + audit trail + fallback→PR + script-gen + 4 patterns) | v0.1 | Stages 0-5a + 7 | 4-5 days | 15 unit + canned-LLM harness + manual fallback |
| 6 | npm package + DX polish | v0.1 | Stages 0-5a + 7 | 2-3 days | 7 tests + install checks |
| 7 | Full E2E + MCP auth demo | v0 | Stages 0-5a | 2-3 days | 6 E2E flows + master checklist |
| 8 | Production hardening (daemon memory hygiene + CLI defensive features) | v0.1 | Stages 0-7 | 4-6 days | 15 unit + 6 E2E hardening checks |
| 9 | v0.1 Heima migration design decisions (holding pen — not a formal stage) | v0.1 design notes | — | — | — |
| **Total (v0 MVP: stages 0-5a, 7)** | | | | **~23-31 days** | **111 tests + 6 E2E flows** |
| **Total (v0.1: + stages 5b, 6, 8)** | | | | **+10-14 days** | **+37 tests + 6 E2E flows** |

**Parallelization opportunity:**
- Within v0: Stages 2 and 3 can run in parallel after Stage 1 (~4-5 days saved).
- Within v0.1: Stages 5b, 6, and 8 are independent and can run in any order or in parallel. No dependency among them beyond Stage 7.

Realistic v0 timeline with one developer: **~4 weeks** (stages 0-5a + 7). v0.1 adds **~2-3 weeks** for 5b + 6 + 8.

**Critical path for v0:** Stage 0 → Stage 1 → Stage 4 → Stage 5a → Stage 7. Stage 5b, Stage 6, and Stage 8 all defer to v0.1 per the 2026-04-16 CEO review. Stage 9 is a design holding pen, not executable work. Everything else is parallelizable around this spine.

---

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | CLEAR | Mode: SELECTIVE EXPANSION. 7 proposals, 5 accepted, 1 deferred, 1 rejected. 1 critical gap caught + fixed (silent-corrupt-credential → mandatory verification). |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | — |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR | 3 architectural decisions locked (IPC schema, concurrency, MCP scope), 5 implementation notes baked in, 11 additional tests added to 5a/5b tables, 0 unresolved. |
| Design Review | `/plan-design-review` | UI/UX gaps | 1 | CLEAR | CLI-scoped review (no visual UI). 4 UX decisions locked: masked-key output, stderr progress, atty TTY detection, duplicate-provision verify-and-report. Score 5/10 → 9/10. |

**ENG-REVIEW DECISIONS LOCKED:**
- IPC contract: line-delimited JSON `ProvisionEvent` enum (Rust ↔ TS), shared via `agentkeys-types`
- Concurrency: `Mutex<Option<ActiveProvision>>` with `PROVISION_IN_PROGRESS` sentinel
- MCP browser primitives: provision-scoped dynamic visibility (5b)

**DESIGN-REVIEW DECISIONS LOCKED:**
- Success output: masked key `sk-or-v1-****...AB3F` (never full key to stdout)
- Progress: stderr step lines during provision, no spinners
- TTY detection: `atty::is` on both stdin and stdout for fallback→PR prompt
- Duplicate provision: verify-and-report, `--force` flag to re-provision

**VERDICT:** CEO + ENG + DESIGN CLEARED — ready to implement Stage 5a. Optional next step: `/codex review` for independent 2nd opinion on architecture before coding starts.

**UNRESOLVED:** 0 decisions (all cherry-picks resolved, all gaps addressed in scope).

**CHERRY-PICKS ACCEPTED (in scope):**
- (5a) Patterns library — `signupEmailOtp` extracted as reusable function
- (5a) Post-provision credential verification — mandatory, non-negotiable
- (5b) Claude-Chrome agentic fallback via MCP browser primitives — uses user's native LLM
- (5b) Fallback audit trail — local JSONL v0.1, on-chain later
- (5b) Fallback→PR loop — human-gated TUI prompt; agent path never auto-submits
- (5b) LLM script-generator dev tool — maintainer-facing, not runtime

**CHERRY-PICKS REJECTED:**
- Scrapers as separate OSS repo — keep in main repo for simpler v0 release engineering
- Agentic mode consent gate — audit trail as detection instead (security watch-item)

**DEFERRED TO TODOS.md:**
- OpenRouter ToS compliance check — required before first live Stage 5a provision

**CEO PLAN DOCUMENT:** `~/.gstack/projects/litentry-agentKeys/ceo-plans/2026-04-16-stage-5-hybrid-agentic.md`
