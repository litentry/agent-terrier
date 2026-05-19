# GH issue body — v2 stage 2: Hardening (K11 WebAuthn + multi-device recovery + audit/memory/email workers)

**Title**: v2 stage 2 — Hardening: K11 WebAuthn + multi-device recovery + audit/memory/email workers

**File via**:
```bash
gh issue create \
  --title "v2 stage 2 — Hardening: K11 WebAuthn + multi-device recovery + audit/memory/email workers" \
  --label "documentation,enhancement" \
  --body-file docs/spec/plans/v2-issues/issue-v2-stage-2-hardening.md
```

---

Stage 2 of the v2 architecture. Adds multi-master-device M-of-N recovery quorum (no anchor wallet, no seed phrase) and the remaining per-service workers (audit, memory, email).

**Note (Codex amendment 2026-05-17)**: K11 WebAuthn binding for master mutations originally planned for stage 2 is **moved to stage 1**. Stage 1 must ship K11 enforcement to avoid an interim window where on-chain ScopeContract accepts K10-only mutations. See updated [issue-v2-stage-1-foundation.md](issue-v2-stage-1-foundation.md).

Stage 2 builds on stage 1's already-shipped K11 binding to add the multi-device + recovery + workers layer.

## What ships in stage 2

### Multi-master-device registration + role bitfield (builds on stage 1's K11)
- Stage 1 already ships K11 enrollment + `SidecarRegistry.register_master_device(...)` for single-device case
- Stage 2 extends with multi-master-device pairing flow (arch.md §5a.3.1):
  - Existing master's K10 + K11 authorizes new device's K10 + K11 binding
  - New device registers in SidecarRegistry with default roles `CAP_MINT | RECOVERY` (SCOPE_MGMT opt-in)
- Per-operator `recovery_threshold` (default 1; prompt to bump to 2 on 3rd-device add)

### Multi-master-device registration + role bitfield
- Role bitfield per SidecarRegistry entry: `CAP_MINT (0x01) | RECOVERY (0x02) | SCOPE_MGMT (0x04)`
- Default role assignments:
  - First master device of a new operator: all roles (`CAP_MINT | RECOVERY | SCOPE_MGMT`)
  - Subsequent master devices: `CAP_MINT | RECOVERY` (SCOPE_MGMT opt-in to prevent mobile-mgmt sprawl)
  - Agent devices: `CAP_MINT` only (no RECOVERY because no K11; no SCOPE_MGMT because agents can't grant scope)
- Per-operator `recovery_threshold` (default 1; prompt to bump to 2 on 3rd-device add)

### Recovery flow (no anchor wallet, no seed phrase)
- Operator detects lost/compromised master device
- On surviving master device: opens agentkeys app → "Lost device — revoke & rotate"
- App constructs revoke + rotate payload; signs with K10 + K11 (Face ID / Touch ID)
- M-of-N device sigs (≥ recovery_threshold) authorize the rotation
- Relay submits SidecarRegistry.revoke_device + WalletRotated audit event
- Signer subscribes to chain event; drops revoked device from authorized set
- Brokers push SSE drop event to all daemons under operator_omni
- Within ~60s: attacker's cap-mints rejected; attacker's cached creds expire on TTL
- New-device registration post-recovery per arch.md §5a.3.1 conventions

### audit-service worker
- **Sovereign default (tier C)**: per-event chain tx, operator's wallet signs (master_wallet visible per event)
- **Hosted-relay opt-in (tier A)**: Merkle-batched audit-roots on chain; reduces gas + enables tx batching
- audit-service-relay holds zero credential decrypt authority; cannot forge audit events (chain-anchored Merkle roots)
- Operator chooses tier via deployment config; both tiers preserve auditability
- Hosted relay does NOT contradict self-sovereignty because tier B (operator runs own relay) is always available as fallback

### memory-service worker
- Per-actor memory at `s3://$BUCKET/bots/<actor_omni_hex>/memory/...`
- High-frequency reads/writes (agent state, chat history, scratch space)
- STS session policies enable direct S3 access from agent — broker NOT in LLM-call hot path
- TTL-bounded cap-tokens minted at session start; agent uses STS creds for many ops within TTL

### email-service worker
- Sends via SES from operator's domain (e.g., `agent-a@bots.litentry.org`)
- Receives via SES routing Lambda (extension of #83's existing infrastructure)
- Per-actor inbox at `s3://$BUCKET/bots/<actor_omni_hex>/inbound/...`
- Inbox migration from `<wallet>` to `<actor_omni_hex>` per stage 1 path migration

### K3 rotation flow
- Signer-governance multisig calls `K3EpochCounter.bump_epoch()` on chain (1 tx, global)
- Signer (in TEE per issue #74 step 2) retains K3_v[N] for decrypt of pre-rotation blobs
- Signer generates K3_v[N+1] inside TEE
- Workers read new epoch from chain; new writes use new K3 epoch
- Lazy on-read re-encryption (optional): blob read → decrypt under old K3 → re-encrypt under new K3 → upload to same S3 path
- Operator-driven eager re-encryption tool available
- **ZERO S3 path migration** (actor_omni-keyed paths)
- **ZERO PrincipalTag changes** (actor_omni stable)
- **ZERO IAM changes** (bucket policy stays put)

## Tasks

- [ ] Signer: K11 WebAuthn verification helpers + cap-mint endpoint with K11 requirement
- [ ] Broker: K11 requirement on master-only endpoints (scope mutation, device bind, K10 rotation)
- [ ] SidecarRegistry contract update: role bitfield + k11_cred_id storage + per-operator recovery_threshold
- [ ] ScopeContract update: `set_scope_with_webauthn` requires both K10 + K11 sigs
- [ ] CLI: bootstrap flow restructured to arch.md v2 §5 stages 0-3 (K10 gen → identity → K11 enrollment → SIWE)
- [ ] CLI: `agentkeys agent create` with K11 prompt (Touch ID)
- [ ] CLI: `agentkeys scope add/remove` with K11 prompt
- [ ] CLI: `agentkeys device add` (new-master-device pairing flow per §5a.3.1)
- [ ] CLI: `agentkeys recovery` (M-of-N flow via web UI / mobile app)
- [ ] Mobile app (iOS + Android): agentkeys companion app with Face ID/Touch ID for K11
  - Bootstrap pairing via QR scan from laptop
  - Recovery flow (revoke device, authorize new device)
  - Scope grant approvals from mobile
- [ ] audit-service worker (Lambda variant) — supports both tier C direct-write + tier A relay batches
- [ ] memory-service worker (Lambda + microservice variants)
- [ ] email-service worker (integrate with existing SES routing Lambda from #83)
- [ ] K3 rotation operational runbook (signer-governance multisig procedure, migration timing)
- [ ] Eager re-encryption tool: per-operator scan + re-encrypt all blobs from old K3 epoch
- [ ] Test plan: K11 binding + multi-device flows + recovery + K3 rotation end-to-end against staging

## Dependencies

- Depends on: stage 1 (foundation must ship first)
- Depends on: arch.md v2 (the consolidated reference)
- Parallel track: issue #74 step 2 (signer in TEE) — stage 2 works with signer in mock-server too; TEE migration strengthens K3 confidentiality but is independent

## Out of scope (separate issues)

- payment-service worker (deferred — separate issue)
- ZK-proven cap minting (v3+; tracked separately)
- One-shot CAS-burn caps for state-mutating ops (tracked as v3 hardening)
- Per-operator K3 (tracked as v3+ multi-tenancy hardening)

## Cross-reference

Design context: see consolidated arch.md v2.
Predecessor stage: v2 stage 1.
