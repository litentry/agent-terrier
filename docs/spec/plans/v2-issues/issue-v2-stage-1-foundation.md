# GH issue body — v2 stage 1: Foundation (sovereign sidecar + on-chain identity + credentials-service worker)

**Title**: v2 stage 1 — Foundation: sovereign sidecar + on-chain identity + credentials-service worker

**File via**:
```bash
gh issue create \
  --title "v2 stage 1 — Foundation: sovereign sidecar + on-chain identity + credentials-service worker" \
  --label "documentation,enhancement" \
  --body-file docs/spec/plans/v2-issues/issue-v2-stage-1-foundation.md
```

---

Stage 1 of the v2 architecture. Replaces #87 (client-side scope enforcement in S3CredentialBackend) with a sovereign sidecar + cap-token + worker architecture. After stage 1, credentials are stored at `s3://$BUCKET/bots/<actor_omni_hex>/credentials/<service>.enc` (actor_omni-keyed paths, stable across K3 rotation), and the broker has zero credential-decrypt authority.

## Default mode: sovereign

Stage 1 ships **sovereign mode as default**:
- Operator's wallet signs chain submissions directly (msg.sender = master_wallet)
- master_wallet appears in chain history (audit events, scope mutations)
- Block-explorer + ENS lookups work on the operator's wallet
- Zero third-party trust required (no relay service)

Hosted-relay mode kept as **opt-in for gas subsidy + tx batching** only (not for privacy — actor_omni hash exposure does NOT weaken K3 due to 2^160 address-space rainbow infeasibility).

## Codex-review-driven amendments (2026-05-17)

Three high-severity findings amended into this plan before implementation begins:

1. **Cloud-enforced vs host-local distinction made explicit.** Per-service "what's allowed" lives on chain (ScopeContract: `scope[operator_omni][agent_omni] → services` + `actor_binding` on SidecarRegistry). Per-call constraints (method/path allowlist, spend quotas, request-rate limits) are **host-local operator policy** enforced by the sidecar — they bound normal-operation misuse but are NOT cloud-enforced cap-token claims. A compromised sidecar can bypass host-local policy, but blast radius is bounded by cloud-enforced cap-binding (it cannot escape the registered actor's scoped services).
2. **K11 WebAuthn moves from stage 2 to stage 1.** Stage 1 ships the full master-mutation authorization model (K10 + K11 for scope grant, scope revoke, device bind, device revoke, K10 rotation). Stage 1 must NOT deploy on-chain ScopeContract with K10-only mutations — that would create a known escalation window before stage 2.
3. **S3 path / PrincipalTag migration is dual-read by spec.** The migration sequence is rigid: (a) OIDC JWT emits BOTH `agentkeys_user_wallet` AND `agentkeys_actor_omni` tags during the transition; (b) bucket policy adds BOTH `_v1_wallet_keyed` AND `_v2_omni_keyed` rules; (c) credentials-service worker can decrypt BOTH v1 envelopes (wallet-keyed AAD) AND v2 envelopes (actor_omni-keyed AAD); (d) lazy on-access copy moves blobs from v1 to v2 path. Default flip and old-rule retirement happen ONLY after explicit operator opt-in per deployment.

## What ships in stage 1

### Daemon as sovereign sidecar
- Localhost HTTP proxy at `$XDG_RUNTIME_DIR/agentkeys-proxy.sock` (Unix socket; SO_PEERCRED for caller-auth)
- Optional TCP `localhost:9090` for container deployments
- Lazy-fetch + short TTL (5 min) credential cache
- Required controls before any proxy operation:
  - Caller auth via SO_PEERCRED (E1) / pod namespace (E2) / TEE caller pin (E3)
  - Per-caller scope binding: `(uid, binary_path) → allowed_services`
  - Service/method/path allowlist (e.g., POST /v1/chat/completions only)
  - Spend quotas: req/min, req/hour, daily $ budget per (caller, service)
  - Per-call audit row → local log + ship to chain audit-relay batch
  - Fail-closed on stale broker (60s threshold)
- Writes `~/.config/agentkeys/env` with proxy URLs + placeholder auth tokens
- Operator adds single `source ~/.config/agentkeys/env` to shell rc (one-time)

### Broker becomes cap-mint authority
- New endpoints: `/v1/cap/cred-fetch`, `/v1/cap/cred-store`
- Reads scope from on-chain ScopeContract (NOT local DB)
- Verifies cap-mint requests against on-chain SidecarRegistry — including the actor-binding check per Codex finding #1
- Verifies K3 epoch against on-chain K3EpochCounter
- Co-signs caps with K1; relays results to workers
- **Removes**: `/credential/*` endpoints (moved to creds-service worker)
- **Removes**: scope DB (moved to ScopeContract on chain)

### On-chain identity layer (3 contracts on Litentry chain; reserve EVM L2 as fallback)

- **ScopeContract**: `scope[operator_omni][agent_omni] → {services, read_only}`
  - **Mutations require K10 + K11 WebAuthn assertion** (per Codex review amendment — was deferred to stage 2, moved into stage 1 to avoid the K10-only escalation window). Endpoint signature: `set_scope_with_webauthn(operator_omni, agent_omni, services, read_only, k10_sig, k11_assertion)`.
  - Service list is the ONLY cloud-enforced scope claim. Per-method/path/spend lives in host-local sidecar config per Codex amendment #1.
- **SidecarRegistry**: `device_pubkey_hash → {operator_omni, actor_omni, role, attestation, k11_cred_id}`
  - Per-actor binding per Codex finding #1
  - K11 enrollment happens at first device-bind (stage 1 ships full master-binding ceremony per arch.md §5 stages 2)
- **K3EpochCounter**: global counter, bumped by signer-governance multisig per K3 rotation event
  - One contract, one tx per rotation (O(1) regardless of operator count)
- All chain submissions:
  - **Sovereign default**: operator's wallet signs (msg.sender = master_wallet)
  - **Hosted-relay opt-in**: relay-wallet pays gas + batches tx; only justified by gas subsidy

### credentials-service worker
- AWS Lambda + API Gateway (default for AWS deployments) OR self-hosted Rust microservice
- Replaces broker's `/credential/*` endpoints
- **Reads BOTH legacy v1 paths AND new v2 paths during migration window (Codex amendment #3)**:
  - v1: `s3://$BUCKET/bots/<lowercase_wallet>/credentials/<service>.enc` (today's #87 path)
  - v2: `s3://$BUCKET/bots/<actor_omni_hex>/credentials/<service>.enc` (stage 1 target)
- **Supports BOTH legacy v1 envelope AND v2 envelope formats**:
  - v1 envelope: AAD = `wallet||service`, deterministic KEK via `signer.sign_eip191(omni, msg)` per `s3_backend.rs`
  - v2 envelope: AAD = `actor_omni||service`, KEK = `HKDF(K3_v[epoch], "agentkeys.user.v1"||actor_omni)`
  - Worker tries v2 path first; on miss, falls back to v1 path; on v1 read, OPTIONALLY copies blob to v2 path under v2 envelope (lazy migration)
- AWS PrincipalTag DURING MIGRATION: **BOTH** `agentkeys_user_wallet` (v1) AND `agentkeys_actor_omni` (v2)
- Bucket policy DURING MIGRATION: BOTH `_v1_wallet_keyed` AND `_v2_omni_keyed` allow-rules (see migration steps below)
- Calls signer mTLS for KEK derivation (signer supports BOTH v1 and v2 derivations during the window)
- Verifies cap-token (broker_sig + K10 device-key sig + per-actor binding) + scope + K3 epoch before AES-GCM operations
- Per-invocation CloudTrail audit; on-chain audit anchor via audit-relay batch (stage 2)

### Migration from #87
- S3CredentialBackend (today) remains for backwards compat during transition
- Add new `SidecarCredentialBackend` that uses localhost proxy URL
- Operators opt-in via `--credential-backend=sidecar`
- Stage 1 completion: sidecar is the default; S3CredentialBackend deprecated

## Migration steps for existing #87 deployments (Codex-amendment-driven, dual-read sequence)

**Hard rule**: the bucket policy and OIDC JWT must support BOTH v1 and v2 simultaneously throughout the migration window. No flag-flips break existing flows.

1. Deploy contracts (ScopeContract, SidecarRegistry, K3EpochCounter) on Litentry chain. **Empty state initially.**
2. Update broker to read scope from chain. Broker is dual-mode: chain scope if entry exists; legacy in-memory scope otherwise.
3. Update OIDC JWT to emit BOTH `agentkeys_user_wallet` AND `agentkeys_actor_omni` claims.
4. Update bucket policy to ADD `_v2_omni_keyed` rules ALONGSIDE existing `_v1_wallet_keyed`. Do NOT remove v1 rules.
5. Update credentials-service worker (Lambda) with dual-envelope decrypt + dual-path read support.
6. Update signer to support BOTH v1 KEK derivation (`signer.sign_eip191(omni, msg)`) AND v2 KEK derivation (`HKDF(K3_v[epoch], info||actor_omni)`).
7. Ship daemon's sidecar proxy (the new `SidecarCredentialBackend`).
8. Ship CLI `--credential-backend=sidecar` flag. Default stays `s3` (today's #87).
9. **Operator opt-in**: per-operator-deployment, run `agentkeys device register --upgrade-from-v1` to:
   - Enroll K11 (WebAuthn) on each master device
   - Submit `SidecarRegistry.register_master_device(...)` tx
   - Operator can now use `--credential-backend=sidecar` (writes go to v2 path)
10. **Lazy migration**: as operator reads existing v1 blobs, worker auto-copies to v2 path under v2 envelope; v1 blob stays at v1 path until next eager-migration pass.
11. **Eager migration**: operator runs `agentkeys-migrate-s3-prefix --operator-omni <X>` to walk all v1 blobs, decrypt under v1 KEK, re-encrypt under v2 KEK, write to v2 path. Optionally deletes v1 blob after verify.
12. After **at least one release** of `--credential-backend=sidecar` opt-in stability: flip the CLI default to `sidecar`. Old `=s3` keeps working with deprecation warning.
13. After at least one release of `=sidecar`-as-default: remove `S3CredentialBackend` from the codebase. v1 PrincipalTag (`agentkeys_user_wallet`) and v1 bucket-policy rules retire in the same release.

**Each step is independently revertable until step 12.** Steps 1–11 add new code paths alongside existing #87 paths; steps 12–13 are the only flag-flip retirements, and each follows a release of operator soak time.

## Tasks

### Daemon
- [ ] Localhost HTTP proxy + lazy-fetch cache + **host-local** controls (caller auth via SO_PEERCRED, allowlist, quotas, audit, fail-closed)
- [ ] `~/.config/agentkeys/env` writer with proxy URLs + placeholders
- [ ] K10 generation as Stage 0 of bootstrap (per arch.md §5)

### Broker
- [ ] New cap-mint endpoints (`/v1/cap/cred-fetch`, `/v1/cap/cred-store`) — K10 sig + per-actor binding verification
- [ ] Scope chain-read + SidecarRegistry chain-read + K3EpochCounter chain-read
- [ ] **K11 WebAuthn verification on master-mutation endpoints** (was stage 2 → moved to stage 1 per Codex amendment #2)
- [ ] Dual-mode scope reads: chain-stored if exists, fallback to legacy in-memory during transition

### On-chain contracts
- [ ] `ScopeContract.sol` with `set_scope_with_webauthn(...)` REQUIRING K10 + K11 sigs + deployment to Litentry chain
- [ ] `SidecarRegistry.sol` with per-actor binding + roles bitfield + k11_cred_id + deployment
- [ ] `K3EpochCounter.sol` + governance multisig setup

### credentials-service worker (Codex amendment #3)
- [ ] Lambda variant: **dual-envelope decrypt** (v1 wallet-keyed AAD + v2 actor_omni-keyed AAD) — already landed in `S3CredentialBackend` client-side (see `s3_backend::open` dispatching on `ENVELOPE_VERSION_{V1,V2}` byte); Lambda reuse of this path is the remaining work
- [ ] Lambda variant: **dual-path read** (v1 `bots/<wallet>/` + v2 `bots/<actor_omni>/`); try v2 first, fall back to v1 — already landed in `S3CredentialBackend::read_credential`; Lambda reuse is the remaining work
- [ ] Lambda variant: lazy on-access copy v1 → v2 path (with new v2 envelope)
- [ ] Microservice variant (Rust, axum) — parallel deliverable, same dual-read support
- [ ] Eager-migration tool: `agentkeys-migrate-s3-prefix --operator-omni <X>`

### Signer
- [ ] New typed endpoints (`/derive-cred-kek`, `/sts-credentials`) + K3 epoch verification + K10 verification helper
- [ ] K11 WebAuthn verification helper (`/verify/k11-assertion`)
- [ ] **Dual KEK derivation support**: v1 (`signer.sign_eip191(omni, msg)`) AND v2 (`HKDF(K3_v[epoch], info||actor_omni)`) during transition

### CLI
- [ ] Restructure bootstrap to arch.md §5 stages 0-3 (K10 gen at startup → email-link → WebAuthn enrollment → SIWE)
- [ ] `agentkeys device register --upgrade-from-v1` — one-shot upgrade for existing operators (K11 enrollment + SidecarRegistry write)
- [x] `--credential-backend=sidecar` flag (parallel to existing `=s3` default) — accepted by CLI surface; today returns "not yet implemented" error pointing at `--envelope-version=v2` as the closest currently-working substitute (daemon proxy lands separately)
- [x] `--envelope-version={v1,v2}` flag wiring the new `WriteEnvelope` in `S3CredentialBackend` — v1 default keeps PR #87 working, v2 opt-in writes the actor_omni-keyed envelope per arch.md §14.4
- [x] `agentkeys whoami` prints `agentkeys_actor_omni` alongside `session_wallet` (per arch.md §14.1 stable per-operator anchor)
- [ ] Deprecation warning for `--credential-backend=s3` (today's #87)
- [ ] `agentkeys agent create` with K11 prompt (master-only mutation)
- [ ] `agentkeys scope add/remove` with K11 prompt (master-only mutation)

### Bucket policy / OIDC
- [ ] OIDC JWT emits BOTH `agentkeys_user_wallet` AND `agentkeys_actor_omni` tag claims
- [ ] Bucket policy: ADD `_v2_omni_keyed` rules ALONGSIDE existing `_v1_wallet_keyed` (do NOT remove v1)
- [ ] Migration runbook section in [cloud-bootstrap.md](../../cloud-bootstrap.md) §4.4 covering dual-tag transition

### Testing
- [ ] End-to-end sidecar + broker + worker + signer flow against staging deployment
- [ ] **Migration test**: existing #87 S3CredentialBackend credentials successfully readable through dual-read worker after policy + tag transition (Codex amendment #3 test gate)
- [ ] K11 enforcement test: scope mutation with K10-only sig must be rejected; K10+K11 must succeed

### Operator runbook
- [ ] [v2-stage1-migration-and-demo.md](../../v2-stage1-migration-and-demo.md) Part A (migration) — written
- [ ] [v2-stage1-migration-and-demo.md](../../v2-stage1-migration-and-demo.md) Part B (new-feature demo) — written
- [ ] Stage 7 demo doc cross-references updated

## Dependencies

- Depends on: nothing (foundational; everything else builds on this)
- Parallel track: arch.md v2 doc (filed alongside this issue)
- Future track: issue #74 step 2 (signer in TEE) — stage 1 works with signer in mock-server too; TEE migration improves K3 confidentiality

## Cross-reference

Design context: see consolidated arch.md v2.
Predecessor: today's S3CredentialBackend implemented in PR #87.
