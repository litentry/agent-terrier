# Phase 0 Checkpoint — Demo & Verification Guide

**Status:** Phase 0 SHIPPED (16/16 stories, 116 tests, codex stop rule fired).
**Branch:** `claude/dazzling-mirzakhani-2a06bc`
**Last commit:** `772ef7e` (US-016 codex rounds 1+2).
**Plan home:** [`PLAN.md`](PLAN.md) (or `~/.claude/plans/now-i-just-merged-idempotent-plum.md`).

This document is the human-checkable checkpoint for Phase 0. Read it
end-to-end to verify what shipped; use the demo recipes to exercise
the broker locally before approving phase progression.

---

## What shipped in Phase 0

### Three-layer pluggable broker — foundation

| Layer | Trait | Plugin shipping in Phase 0 | File |
|---|---|---|---|
| Auth | `UserAuthMethod` | `SiweWalletAuth` (SIWE EIP-4361 wrapping EIP-191) | `src/plugins/auth/wallet_sig.rs` |
| Wallet | `WalletProvisioner` | `ClientSideKeystoreProvisioner` (MetaMask model) | `src/plugins/wallet/keystore.rs` |
| Audit | `AuditAnchor` | `SqliteAnchor` (WAL+FULL, plugin_mint_log table) | `src/plugins/audit/sqlite.rs` |

### HTTP surface

| Method | Path | Purpose | Handler |
|---|---|---|---|
| GET  | `/healthz` | Liveness (always 200) | `handlers::broker_status::healthz` |
| GET  | `/readyz`  | Plugin + Tier-2 aggregated readiness | `handlers::broker_status::readyz` |
| POST | `/v1/auth/wallet/start`  | Issue SIWE challenge | `handlers::auth::wallet_start` |
| POST | `/v1/auth/wallet/verify` | Verify SIWE → session JWT | `handlers::auth::wallet_verify` |
| POST | `/v1/auth/exchange`      | Legacy bearer → session JWT shim | `handlers::auth::exchange` |
| POST | `/v1/mint-aws-creds`     | Session JWT + per-call sig → STS creds (v2 path); legacy bearer also accepted | `handlers::mint::mint_aws_creds` |
| GET  | `/.well-known/openid-configuration` | OIDC discovery | `handlers::oidc::discovery` |
| GET  | `/.well-known/jwks.json` | OIDC JWKS for AWS STS | `handlers::oidc::jwks` |
| POST | `/v1/mint-oidc-jwt`      | OIDC JWT for STS AssumeRoleWithWebIdentity | `handlers::oidc::mint_oidc_jwt` |

### Process-rule enforcement

All 11 plan-rules (§1) verified in `codex-round1.md` "Process-rules verification" section. Highlights:
- **Day-1 invariant test:** `tests/invariant_load_bearing.rs` (US-013) — all 6 cases a-f green.
- **Refuse-to-boot:** `BOOT_FAIL: <var>=<value>: <reason>; see runbook §<anchor>` on every Tier-1 config error.
- **Centralized env vars:** zero raw `BROKER_*`/`DAEMON_*`/`ACCOUNT_ID`/`REGION` literals outside `src/env.rs` (smoke-script-enforced).
- **Smoke-per-phase:** `harness/stage-7-issue-64-phase0-smoke.sh` exits 0 with 9 invariants checked.

### Test totals

```
85  lib unit tests          (env, identity, jwt::*, plugins::*, storage::*, boot, handlers::*)
 4  auth_wallet_flow        (SIWE → session JWT round-trip + replay/garbage rejection)
 7  invariant_load_bearing  (all 6 cases a-f from plan §2 + 1 helper)
 9  mint_flow               (legacy bearer path preserved; readyz under tier-2 toggle)
 5  mint_v2_flow            (new v2 path: happy + 4 rejection cases)
 6  oidc_flow               (untouched legacy OIDC issuer suite)
---
116 total
```

---

## Demo: build + boot + exercise

### 0. Prerequisites

- Rust 1.75+ (stable). Repo CI matrix tracks the toolchain.
- `jq` (for parsing curl JSON in this guide).
- macOS or Linux. `set_owner_only_inner` 0600 chmod is Unix-only.

### 1. Build (default features)

```bash
cd /path/to/agentKeys/.claude/worktrees/dazzling-mirzakhani-2a06bc
cargo build -p agentkeys-broker-server --release
# Binary at: target/release/agentkeys-broker-server
```

For the v0-testnet feature combo (Phase A.1+A.2+C ready):

```bash
cargo build -p agentkeys-broker-server --release \
  --features auth-email-link,auth-oauth2-google,audit-evm
```

### 2. Generate the two ES256 keypairs (purpose-tagged)

Phase 0 disables silent generation (plan §6). The runbook's
`§oidc-keypair` and `§session-keypair` anchors document the
operator-side commands. For demo purposes the unit-test fixtures
generate their own keypairs in temp dirs; operator demo:

```bash
mkdir -p ~/.agentkeys/broker
# OIDC keypair (signs tokens AWS STS verifies):
cargo run -p agentkeys-broker-server --release -- \
  keygen --purpose oidc \
         --out ~/.agentkeys/broker/oidc-keypair.json
# Session keypair (signs broker-internal session JWTs):
cargo run -p agentkeys-broker-server --release -- \
  keygen --purpose session \
         --out ~/.agentkeys/broker/session-keypair.json
chmod 600 ~/.agentkeys/broker/{oidc,session}-keypair.json
```

> NOTE: the `keygen` subcommand is a Phase E US-039 deliverable and
> not yet wired in Phase 0. For now, the keypairs auto-generate at
> first boot only when their paths point at non-existent files AND
> `BROKER_DEV_MODE=true` is set. Production deployments should gate
> on the explicit `keygen` subcommand once US-039 ships.

### 3. Set env vars (minimal default v0 config)

```bash
export BROKER_BACKEND_URL=http://localhost:18000  # or the real backend
export BROKER_DATA_ROLE_ARN=arn:aws:iam::000000000000:role/agentkeys-data-role
export BROKER_OIDC_ISSUER=http://localhost:8091   # use http for local
export BROKER_OIDC_KEYPAIR_PATH=~/.agentkeys/broker/oidc-keypair.json
export BROKER_SESSION_KEYPAIR_PATH=~/.agentkeys/broker/session-keypair.json
export BROKER_AUTH_METHODS=wallet_sig
export BROKER_WALLET_PROVISIONER=client_keystore
export BROKER_AUDIT_ANCHORS=sqlite
export BROKER_AUDIT_DB_PATH=~/.agentkeys/broker/audit.sqlite
export BROKER_DEV_MODE=true                       # required for http:// issuer
```

Full env-var inventory (51 constants) lives in `docs/operator-runbook-stage7.md`.

### 4. Boot the broker

```bash
target/release/agentkeys-broker-server --bind 127.0.0.1 --port 8091 \
                                       --skip-startup-check
```

Tier-1 refuse-to-boot runs synchronously. If anything's misconfigured,
expect a single-line `BOOT_FAIL: …` on stderr that ends with
`see runbook §<anchor>` — paste the anchor into the runbook to find
the fix.

Tier-2 reachability checks run async; `/readyz` returns 503 until the
backend `/healthz` probe succeeds (or `BROKER_REFUSE_TO_BOOT_STRICT=true`
collapses Tier-2 to refuse-to-boot).

### 5. Exercise `/healthz` and `/readyz`

```bash
curl -i http://localhost:8091/healthz
# HTTP/1.1 200 OK
# ok

curl -s http://localhost:8091/readyz | jq
# Expected (during Tier-2 backend-down): {"status":"unready", ...}
# After backend probe succeeds: {} (empty body, plan §7)
```

Each "checks" entry carries a `docs` URL anchor pointing into the
operator runbook. Paste it to debug.

### 6. Exercise the SIWE auth flow (US-006 + US-009)

> The walkthrough below uses a real EIP-191 wallet; for unit-level
> verification see `tests/auth_wallet_flow.rs` which uses a fresh
> k256 SigningKey.

```bash
# 1) Get a SIWE challenge
curl -s -X POST http://localhost:8091/v1/auth/wallet/start \
     -H 'content-type: application/json' \
     -d '{"address":"0xYourAddr…","chain_id":84532}' | jq
# {
#   "request_id": "siwe-…",
#   "expires_in_seconds": 2700,
#   "siwe_message": "broker.example.com wants you to sign in with…",
#   "nonce": "…",
#   "expires_at_iso": "2026-05-05T15:22:11Z"
# }

# 2) Sign the SIWE message with your wallet (MetaMask, cast, etc.)
#    using personal_sign — this is EIP-191 with the prefix the broker
#    re-derives. For cast:
#    cast wallet sign --private-key $PK --no-hash "$SIWE_MESSAGE"

# 3) Verify
curl -s -X POST http://localhost:8091/v1/auth/wallet/verify \
     -H 'content-type: application/json' \
     -d '{"request_id":"siwe-…","signature":"0x…<130 hex>"}' | jq
# {
#   "session_jwt": "eyJ…",
#   "session_jwt_kid": "ak-session-…",
#   "expires_at": 1762345678,
#   "omni_account": "<64 hex>",
#   "wallet_address": "0xYourAddr…",
#   "identity_type": "evm",
#   "identity_value": "0xYourAddr…"
# }
```

The `omni_account` is `SHA256("agentkeys" || "evm" || wallet)` — distinct
from any other operator's namespace by construction.

### 7. Exercise the v2 mint flow (US-011)

The mint endpoint detects whether the bearer is a session JWT (v2 path)
or a legacy backend-validated bearer (legacy path) by token shape.

#### v2 path (session JWT + per-call sig)

```bash
SESSION_JWT="eyJ…"                  # from step 6
WALLET="0xYourAddr…"                # same as JWT-bound wallet

# Build the body (auth.signature is over canonical-JSON-bytes-minus-itself).
# Helper script for canonicalization is in tests/mint_v2_flow.rs::canonical_input.
# In practice your daemon SDK does this for you.

BODY=$(jq -n --arg w "$WALLET" '{
  request_id: "mnt_demo_1",
  issued_at: "2026-05-05T14:00:00Z",
  intent: { agent_id: $w, service: "s3", scope_path: "bots/" },
  auth: { address: $w, signature: "" }
}')

# Compute canonical bytes + EIP-191 sign with your wallet → SIG
# (omitted; see tests/mint_v2_flow.rs::eip191_sign for the algorithm)

BODY_SIGNED=$(printf '%s' "$BODY" | jq --arg s "$SIG" '.auth.signature = $s')

curl -s -X POST http://localhost:8091/v1/mint-aws-creds \
     -H "authorization: Bearer $SESSION_JWT" \
     -H 'content-type: application/json' \
     -d "$BODY_SIGNED" | jq
# {
#   "access_key_id": "ASIA…",
#   "secret_access_key": "…",
#   "session_token": "…",
#   "expiration": 1762357678,
#   "wallet": "0xYourAddr…",
#   "audit_record_id": "aud_…",
#   "anchored": ["sqlite"]
# }
```

#### Legacy path (existing daemon/CLI binaries unchanged)

If you're a pre-Stage-7 daemon, `Authorization: Bearer <opaque-token>`
where the token is NOT JWT-shaped routes through the legacy
`/session/validate` path. Response shape unchanged from PR #61.

### 8. Verify audit row

```bash
sqlite3 ~/.agentkeys/broker/audit.sqlite \
  'SELECT id, omni_account, wallet, agent_id, service, status, outcome
     FROM plugin_mint_log ORDER BY minted_at DESC LIMIT 1;' \
  | column -ts'|'
```

Phase 0 writes `status='confirmed'` directly. Phase C introduces the
`pending → confirmed | quarantined` lifecycle for dual-anchor.

### 9. Re-run the load-bearing invariant suite

```bash
cargo test -p agentkeys-broker-server --test invariant_load_bearing
# 7 passed; 0 failed
```

These 7 tests are the day-1 contract per plan §2 + rule 7. They MUST
stay green for any subsequent phase to advance.

### 10. Run the harness smoke + done scripts

```bash
bash harness/stage-7-issue-64-phase0-smoke.sh
# OK — Phase 0 smoke green   (9 invariants checked)

bash harness/stage-7-issue-64-done.sh
# Phase 0 deliverables verified.
# Phases A.1+ assertions land as those phases ship.
```

---

## What you can verify by reading

If you want to spot-check rather than run:

- **Plan adherence** — read `codex-round1.md` "Process-rules verification" and `codex-round2.md` "Process-rules cross-check" sections.
- **Invariant test contract** — read `tests/invariant_load_bearing.rs` top-of-file doc comment.
- **Mint endpoint dispatch + audit gate** — read `src/handlers/mint.rs::mint_aws_creds` (40 LOC dispatch) and `mint_v2` (130 LOC). The audit-gate semantic lives at lines 232-249.
- **Refuse-to-boot UX** — read `src/boot.rs::run_tier1` (each `boot_fail(…)` call has a stable runbook anchor).
- **Plugin trait contract** — read `src/plugins/{auth,wallet,audit}/mod.rs` trait blocks (none of the trait methods default to `Ready`).
- **Open follow-ups** — read `V0.1-FOLLOWUPS.md` (20 P2/P3 items rolled forward; first-priority backlog for Phase A.1).

---

## What's NOT done (intentional Phase 0 scope)

- EmailLink auth method (Phase A.1 — US-017/018/019).
- OAuth2/Google auth method (Phase A.2 — US-020/021/022).
- Graceful shutdown SIGTERM drain + 0001_v2_schema.sql migrations (Phase C.0 — US-023/024).
- Capability grants + master-gated recovery (Phase B — US-025-029).
- EVM Base Sepolia audit anchor + circuit breaker + reconciler + gas-drain mitigations (Phase C — US-030-035).
- Prometheus metrics + Idempotency-Key dedup + body-size limit (Phase D-rest — US-036/037/038).
- Operator runbook final form + auto-generated env-var table + restore drill (Phase E — US-039-041).

The next ralph iteration picks up at Phase A.1 US-017 (EmailLink plugin
+ storage). The V0.1-FOLLOWUPS list is the priority-zero backlog
before any new Phase A.1 deliverables — see [`V0.1-FOLLOWUPS.md`](V0.1-FOLLOWUPS.md).

---

## Branch + PR readiness

The branch is ready for PR review whenever you decide to slice it.
Recommended PR slicing:

- **PR #1 (this checkpoint, 21 commits):** Phase 0 foundation. Reviewable as a single trunk-friendly PR; all tests green.
- **PR #2:** Phase A.1 (EmailLink) when complete.
- **PR #3:** Phase A.2 (OAuth2/Google) when complete.
- ... etc.

Or land all phases incrementally on `claude/dazzling-mirzakhani-2a06bc`
and PR the whole branch at the end. The plan is agnostic to PR
slicing.
