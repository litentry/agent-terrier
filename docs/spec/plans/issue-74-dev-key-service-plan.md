# Plan — Issue #74: dev_key_service + TEE-shaped daemon migration

## Status (post-PR #75) — successor steps

This plan covers **issue #74 step 1**: HKDF-backed `dev_key_service`
in `agentkeys-mock-server`, the `/dev/*` wire contract per
[`signer-protocol.md`](../signer-protocol.md), and the daemon/CLI
migration that consumes it. **Shipped in PR #75.**

Two successor steps follow this plan and supersede portions of
its design as they land:

- **Step 1b — public signer listener + bearer-JWT auth.** Deploys
  `signer.<zone>` as a separate listener on `:8092`; adds JWT
  bearer verification in `/dev/*` handlers (signer reads broker's
  session pubkey at boot from a pinned file). No SIGNER_ACCESS_TOKEN.
  Lands as part of the same PR #75 architectural follow-up commits;
  drops the SSH-tunnel scaffolding from the demo doc. The "private
  network assumption" in this plan's §"Risks" is replaced by
  "JWT-bearer-on-public-listener" assumption.
- **Step 1c — device-key per-request authentication.** Replaces
  bearer-JWT-only auth on `/dev/*` with a device-key signature
  scheme: daemon generates a device keypair locally at init,
  identity ceremony (email/OAuth2/EVM/passkey) binds the device
  pubkey atomically with proof-of-possession, every per-request
  signature is verified against the bound pubkey. Removes the
  broker-as-SPOF risk. Tracked in
  [`issue-74-step-1c-device-key-auth.md`](issue-74-step-1c-device-key-auth.md)
  and gh issue [#76](https://github.com/litentry/agentKeys/issues/76).
  - **v1c-interim** ships bespoke per-identity PoP shapes (`pop_sig`
    field for email/oauth2; SIWE-payload `Device Pubkey` commit for
    evm).
  - **v0.2 target** collapses these into a uniform WebAuthn binding
    ceremony for **master machines** (workstation with platform
    authenticator: Touch ID / Hello / Android biometric) and a
    uniform link-code binding ceremony for **agent machines** (VM /
    Linux / CI / `agent-infra/sandbox` containers). Single source
    of truth: [`architecture.md` §5a.1](../architecture.md).
    Hardware-attested user presence at re-bind closes the
    email-account-compromise → device-takeover gap (Q7). YubiKey-on-
    Linux as a master tier is deferred to
    [issue #79](https://github.com/litentry/agentKeys/issues/79).

The architecture.md doc ([`../architecture.md`](../architecture.md))
is the canonical source of truth post-PR-#75; this plan documents
the original step-1 intent and is preserved for historical context.

## Goal

Move the daemon off the legacy `agentkeys init --mock-token` → backend `/session/create` → opaque-bearer flow, onto an omni_account-anchored, server-derived-EVM-keypair flow, with the same wire shape a future TEE worker will use. Operator manages no local EVM keys.

## Non-goals
- Production hardening of the dev signer (master secret rotation, multi-region, threshold sigs) — deferred to the TEE swap (issue #74 step 2)
- Removing `/v1/auth/exchange` and backend `/session/validate` in this PR — separate cleanup once daemon migrates and no callers remain
- Changing the operator-workstation SIWE flow (the demo uses `cast wallet sign` directly; that stays as the "power-user / hardware-key" path)

## Invariants the migration must preserve
- Broker holds zero AWS principals at runtime (Stage 7 trust boundary)
- Broker session-JWT verification stays cryptographic (no new "trust the backend" surface)
- AWS PrincipalTag-enforced S3 isolation (`agentkeys_user_wallet`) — every minted OIDC JWT carries an EVM address that maps 1:1 to a single user
- Same code path for power-user (local-key SIWE) and managed-user (server-derived SIWE) — broker can't tell them apart, both go through `/v1/auth/wallet/{start,verify}`

## Architecture target

```
                Operator workstation                                   Backend (mock-server)
                ┌──────────────────────────────┐                       ┌────────────────────┐
                │  agentkeys-daemon            │                       │  dev_key_service   │
                │                              │   POST /dev/derive    │                    │
                │  ① auth as user              │ ────────────────────▶ │  HKDF + secp256k1  │
                │     (email / OAuth2)         │   {omni_account}      │  master_secret     │
                │  ② derive managed wallet     │ ◀──── {address} ───── │   (env-gated)      │
                │  ③ link to broker            │                       │                    │
                │  ④ per-mint: SIWE round-trip │   POST /dev/sign      │                    │
                │     with backend signing     │ ────────────────────▶ │                    │
                │                              │  {omni, message}      │                    │
                │                              │ ◀──── {signature} ─── │                    │
                └────┬───────────────────┬─────┘                       └────────────────────┘
                     │ ① email/OAuth2    │ ③ /v1/wallet/link
                     │   auth flows      │ ④ /v1/auth/wallet/{start,verify}
                     │ ④ /v1/mint-oidc-jwt   ④ /v1/mint-aws-creds
                     ▼                   ▼
                  Broker (stateless minter, no key material from this flow)
```

The backend → broker path doesn't change. The dev_key_service is a **new** edge: daemon → backend (signer), parallel to the existing daemon → backend (credential vault). When TEE lands, this edge re-routes to the TEE worker; daemon code doesn't change.

## User stories

### US-1 — Operator runs `agentkeys init` with no local keypair
**Acceptance:**
- `agentkeys init` prompts for email or OAuth2 (no `--mock-token` path)
- After auth, daemon stashes `(email_session_jwt, derived_evm_address)` in keychain
- `agentkeys provision openrouter` succeeds end-to-end without ever holding a private key locally

### US-2 — Daemon derives a stable EVM wallet from omni_account
**Acceptance:**
- Same email → same derived wallet, every time, across daemon reinstalls (deterministic HKDF)
- Different emails → different wallets (no cross-user collision)
- Backend exposes `POST /dev/derive-address` returning `{address}`
- Backend refuses to start if `DEV_KEY_SERVICE_MASTER_SECRET` is unset

### US-3 — Daemon obtains a session JWT for the derived wallet
**Acceptance:**
- Daemon calls broker `/v1/auth/wallet/start(derived_addr)` → SIWE message
- Daemon calls backend `/dev/sign-message(omni, siwe_message)` → ECDSA signature
- Daemon calls broker `/v1/auth/wallet/verify(req_id, sig)` → session JWT for `omni_evm`
- The session JWT verifies against broker's session keypair (existing path, unchanged)

### US-4 — Recovery via re-auth of any linked identity
**Acceptance:**
- Operator with linked email + linked OAuth2 can sign in with either; daemon derives the same wallet, same omni_evm
- Loss of one identity doesn't lock the operator out as long as another linked identity is reachable
- (No new code; existing IdentityLinkStore + recovery_lookup handles this once US-1+US-2+US-3 land)

### US-5 — Production builds reject dev_key_service
**Acceptance:**
- Mock-server boots, but `/dev/*` endpoints return 503 with body `{"error":"dev_key_service disabled — set DEV_KEY_SERVICE_MASTER_SECRET to enable"}` if env unset
- Demo deployment sets the env via `scripts/broker.env` (or backend's equivalent)
- README + module-level doc comment in `dev_key_service.rs` make the dev-only intent unmissable

### US-6 — Wire shape matches future TEE worker
**Acceptance:**
- HTTP wire surface (`POST /dev/derive-address`, `POST /dev/sign-message`) is independent of HKDF-vs-TEE implementation
- Daemon code makes no assumptions about how the signer derives keys (treats it as opaque RPC)
- Issue #74 step 2 can land a TEE-backed signer purely by swapping the implementation behind the same routes

## Implementation order

| # | Step | LOC est. | Test gate |
|---|---|---|---|
| 0 | **`docs/spec/signer-protocol.md`** (v0 wire contract) — request/response shapes, error envelope, signature encoding, future attestation handshake. Both dev_key_service and TEE worker conform to this. **Written before any code.** | ~150 lines doc | n/a (review-only) |
| 1 | `crates/agentkeys-mock-server/src/dev_key_service.rs` (HKDF + secp256k1 + EIP-191). HKDF info string is **versioned** as `[0x01] || "agentkeys-evm-wallet" || omni_account`, so future master-secret rotation can change derivation domain without re-deriving every linked wallet. | ~220 | Unit tests: determinism, version-byte respected, signature recoverability, address derivation matches `cast wallet derive` |
| 2 | `crates/agentkeys-mock-server/src/handlers/dev_keys.rs` (env-gated routes per `DEV_KEY_SERVICE_MASTER_SECRET`; 503 if unset) | ~80 | Integration test: 503 without env, derived address stable across calls, conforms to signer-protocol.md |
| 3 | Wire routes in `mock-server/src/lib.rs` + `state.rs` | ~20 | Existing test suite green |
| 4 | Add `DEV_KEY_SERVICE_MASTER_SECRET` to `scripts/broker.env` (commented placeholder) + `setup-broker-host.sh` env detection | ~10 | `bash scripts/setup-broker-host.sh --upgrade` round-trip |
| 5 | `crates/agentkeys-daemon/src/main.rs` — email/OAuth2 + dev-signer flow + emit one **audit-log row** at successful init via existing audit infrastructure | ~170 | Daemon-startup test against in-memory mock-server with dev signer enabled; audit row asserted |
| 6 | `agentkeys-cli/src/lib.rs::cmd_init` rewritten for new flow. **`--mock-token` flag deleted in this PR (hard cut).** | ~80 | CLI integration test |
| 7 | **`agentkeys whoami` CLI command** — read-only, shows omni_account + linked identities + derived wallet + session JWT TTL remaining | ~80 | CLI integration test |
| 8 | **TEE-stub integration test** — fixture implementing the same wire contract as `dev_key_service`, run all daemon integration tests against it. Proves the wire shape is the actual swap point. | ~150 | Daemon tests pass against the stub identical to passing against dev_key_service |
| 9 | Update `docs/stage7-demo-and-verification.md` with the new "headless / no-local-key" path under §2 | ~50 | `bash harness/stage-7-issue-64-done.sh` exits 0 |
| 10 | Live broker host redeploy + smoke walkthrough using the new flow | n/a | Wallet A / Wallet B isolation proof still passes; legacy `--mock-token` no longer accepted |

**Rough total: ~830 LOC + protocol doc + tests**, contained to mock-server (new module + handler), daemon, CLI, one doc section, one design doc. Broker code untouched.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| dev_key_service master secret leaks (env-var compromise) | Strong DEV-ONLY warnings; production deployment uses TEE worker (issue #74 step 2); the TEE swap is one-component change |
| HKDF-derived secp256k1 key has insufficient entropy | Use `secp256k1::SecretKey::from_slice` validation; if rejected, retry with counter-extended HKDF (vanishingly rare with proper master secret) |
| Daemon migration breaks existing agentkeys-mcp / provisioner CI | All existing tests must pass; CI gate before merge; `--mock-token` stays as a transitional flag for one release with a deprecation warning |
| Operator workflow regression — losing the simple `--mock-token` test path | Keep `--mock-token` accepting a key-bypass mode for tests; document the email/OAuth2 path as the production default |
| Daemon's email/OAuth2 auth requires interactive input (no headless mode for headless servers) | OAuth2 device-code flow for headless servers; document `agentkeys init --headless` if needed |
| Wire-shape lock-in — once the TEE worker is built, daemon can't easily migrate if the dev_key_service interface diverges from the TEE's | Define the contract in a `signer-protocol.md` design doc; both implementations conform to it |

## What lands at v1.0 (post-#74)

- `dev_key_service` deleted; TEE worker takes over via env-var routing
- `/v1/auth/exchange` deleted (no daemon caller)
- Broker `validate_bearer_token` + `auth.rs` deleted (no caller)
- Backend's `/session/validate` deleted (no caller)
- Daemon's only auth surface: email/OAuth2 → omni → derived wallet → SIWE → session JWT — all cryptographic, all minimal-trust
- The architecture diagram in #73's PR description simplifies to the v1.0 target shape ("three independent edges, three independent products")

## Order of operations across issues

1. **#73 lands** (this branch's PR) — broker live deploy + OIDC-only auto-provision is the foundation
2. **#74 step 1** (this plan) — dev_key_service module + daemon migration. Closes legacy auth bearer.
3. **#74 step 2** (separate issue, to be filed) — TEE worker replaces dev_key_service. Wire shape unchanged.
4. **Cleanup PR** — delete `/v1/auth/exchange`, backend `/session/validate`, broker `auth.rs`, etc., once no callers remain.

## Open questions for review

- Should `dev_key_service` live in mock-server, or as a separate `agentkeys-dev-signer` crate? Pro-separate: cleaner removal at TEE swap; pro-mock-server: one less crate, one less binary to deploy.
- Should the daemon's email/OAuth2 session JWT and the derived-EVM session JWT be stored separately in keychain, or always re-derived per call? Pro-cached: faster mints; pro-fresh: smaller blast radius if keychain leaks.
- For the operator-workstation demo, should the `cast wallet sign` flow stay as the documented power-user path, or should both flows be presented as equivalent? My read: keep both, document both.

---

## CEO review — scope decisions (SELECTIVE EXPANSION mode)

Reviewed `2026-05-08`. Mode: SELECTIVE EXPANSION. Decisions captured below.

### Accepted (added to scope above)
| # | Expansion | Why | Effort |
|---|---|---|---|
| 1 | `docs/spec/signer-protocol.md` v0 wire contract | TEE drop-in swap is mechanical not hand-wavy; both dev_key_service and TEE worker conform to it | S |
| 3 | Versioned HKDF derivation (`[0x01] || …`) | Future master-secret rotation doesn't require re-deriving every linked wallet | S (1 byte) |
| 5 | Audit-log row on `agentkeys init` | Day-1 observability for the new auth surface; "did the daemon ever auth?" answerable from a query | S |
| 6 | `agentkeys whoami` CLI | Operator UX; user has multiple linked identities + derived wallet, needs a "where am I" view | S (~80 LOC) |
| 7 | TEE-stub integration test | Wire-shape-as-swap-point becomes a tested invariant, not an assertion | M (~150 LOC) |
| 8 | **Hard cut** of `agentkeys init --mock-token` flag | User chose stronger-than-recommended option: no deprecation runway, clean slate this PR | trivial |

### Skipped (explicitly NOT in scope)
| # | Expansion | Reason |
|---|---|---|
| 2 | Feature-flag gating (`#[cfg(feature = "dev-key-service")]`) | Plan keeps env-var gating; user accepted the lighter-weight approach |
| 4 | Short-lived session JWT + refresh flow | Long TTL acceptable for current demo deployment; revisit when team expands beyond single-operator |

### NOT in scope (deferred to future issues, unchanged from original plan)
- Master-secret rotation policy (deferred to TEE-swap follow-up)
- Threshold signing for high-value omni_accounts
- Multi-region TEE replication
- Production gating beyond env-var (compile-time `cfg(not(production))` could come later)
- The TEE worker itself — separate issue once dev_key_service ships

### Revised effort estimate

| | Original plan | After CEO review |
|---|---|---|
| LOC | ~600 | ~830 |
| New design docs | 0 | 1 (`signer-protocol.md`) |
| New CLI commands | 0 | 1 (`whoami`) |
| New test infrastructure | unit + happy-path integration | + TEE-stub conformance test |
| Human-team estimate | ~3 days | ~5 days |
| CC+gstack estimate | ~3 hours | ~5 hours |

The expansions are net-additive on observability + reusability. None changes the architectural target.
