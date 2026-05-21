# Issue #82 — ERC-7730 clear-signing, v2-aligned plan

**Status:** plan in progress (this PR ships phases 1-3 + phase-4 schema).
**Supersedes:** the original #82 body, which targeted v1 architecture (mock-server-as-signer, daemon-side metadata, broker SQLite audit).
**Owner:** AgentKeys signer + worker stack.

---

## Why this rewrite

The original #82 was filed before v2 architecture landed (PR #87 / #92). Three premises in the original issue are now out of date:

1. **"Signer is `dev_key_service`, replaced post-#74-step-2 by TEE worker."** Reality: the signer is now a first-class component (arch.md §14, `signer.litentry.org`) with a typed RPC surface (`/derive-address`, `/derive-cred-kek`, `/sts-credentials`, `/sign/siwe`, `/sign/audit-row`, `/verify/k10-sig`, `/verify/k11-assertion`). `/dev/sign-message` is the legacy SIWE-only path; new sign primitives must land on the §14.2 surface.
2. **"Daemon-side metadata binding."** Reality: daemons never call the signer directly (arch.md §14.2 line 1). Binding belongs at the broker's cap-mint (so the cap-token's `op_type` carries the intent commitment) and at the signer (so it refuses to sign domains outside its bound 7730 set). The daemon's job is preview rendering.
3. **"Broker SQLite audit row schema extension."** Reality: audit is now a worker (`agentkeys-worker-audit`) with three tiers (§15.3). Intent fields belong on the worker's row schema and in `CredentialAudit.append` on chain.

This plan re-targets all four phases against v2 surfaces. **It also adds K11-binding-on-high-value-signs**, a defense the original missed.

---

## Phase 1 — EIP-712 typed-data signing

**Wire shape** (extends [`signer-protocol.md`](../signer-protocol.md)):

```
POST /dev/sign-typed-data
{
  "omni_account": "<64 hex>",
  "typed_data":   { EIP-712 v4 JSON: domain, types, primaryType, message }
}
→ 200
{
  "signature":          "0x<130 hex>",
  "address":            "0x<40 hex>",
  "primary_type_hash":  "0x<64 hex>",   // audit cross-ref
  "domain_separator":   "0x<64 hex>",   // audit cross-ref
  "digest":             "0x<64 hex>",   // final EIP-712 digest signed
  "key_version":        1
}
```

**Key property:** the signer parses the typed-data JSON itself and computes
`keccak256("\x19\x01" || domainSeparator || hashStruct(primaryType, message))`
internally — it never trusts a caller-supplied prehash. This is what makes the
signer's signature a meaningful claim about *what was signed*.

**Crates touched:**

| File | Change |
|---|---|
| [`crates/agentkeys-mock-server/src/dev_key_service.rs`](../../crates/agentkeys-mock-server/src/dev_key_service.rs) | Add `sign_eip712(omni, typed_data) → (sig, addr, type_hash, domain_sep, digest)` + EIP-712 v4 hashing |
| [`crates/agentkeys-mock-server/src/handlers/dev_keys.rs`](../../crates/agentkeys-mock-server/src/handlers/dev_keys.rs) | Add `sign_typed_data` handler with JWT auth path identical to `sign_message` |
| [`crates/agentkeys-mock-server/src/lib.rs`](../../crates/agentkeys-mock-server/src/lib.rs) | Wire route in both `create_signer_router()` and `create_router()` |
| [`crates/agentkeys-core/src/signer_client.rs`](../../crates/agentkeys-core/src/signer_client.rs) | Add `sign_eip712()` to `SignerClient` trait + `HttpSignerClient` |

**Tests:**

- Unit tests in `dev_key_service.rs`: domain-separator computation against known
  fixtures (USDC permit, Permit2 single-permit, EIP-2612 generic).
- Route tests in `dev_key_service_routes.rs`: 200 / 400 / 401 / 503 paths.
- Conformance tests in `signer_conformance.rs`: TEE-stub vs HKDF-backed parity.

## Phase 2 — ERC-7730 metadata parser + binding

**New module:** `crates/agentkeys-core/src/clear_signing/`:

```
clear_signing/
├── mod.rs         # public API: ClearSigningCatalog, BoundSignRequest
├── parser.rs      # ERC-7730 JSON parser (subset for v0)
├── format.rs      # token-amount / address-name / enum / date formatters
├── binding.rs     # domain.{name,version,chainId,verifyingContract} → 7730 file lookup
├── eip712.rs      # EIP-712 typed-data encoding (shared with mock-server signer)
└── fixtures/
    └── erc20-permit.json     # bundled USDC permit ERC-7730 file
```

**Binding strategy (per arch.md §22 pluggable surfaces):**

| v | Source | When |
|---|---|---|
| v0 | Bundled set under `fixtures/` (USDC permit, Permit2, OpenSea Seaport) | This PR |
| v1 | Fetch from `github.com/ethereum/clear-signing-erc7730-registry` at daemon startup, cached locally | Follow-up issue |
| v2 | On-chain registry / IPFS-pinned + signature-verified | v3+ |

**Public API:**

```rust
pub struct ClearSigningCatalog { /* loaded ERC-7730 files keyed by domain */ }

impl ClearSigningCatalog {
    pub fn bundled() -> Self;
    pub fn from_dir(path: &Path) -> Result<Self, ClearSigningError>;
    pub fn lookup_for_eip712(&self, domain: &Eip712Domain) -> Option<&Erc7730File>;
}

pub struct BoundSignRequest {
    pub typed_data: serde_json::Value,
    pub rendered_intent: String,       // e.g. "Approve USDC 1000.00 to Uniswap router"
    pub intent_commitment: [u8; 32],   // keccak256(intent_text || "|" || digest)
}

impl BoundSignRequest {
    pub fn build(
        catalog: &ClearSigningCatalog,
        typed_data: serde_json::Value,
        digest: [u8; 32],
    ) -> Result<Self, ClearSigningError>;
}
```

## Phase 3 — Display rendering at operator review surface

**CLI subcommand additions:**

```
# Preview without signing — show what the wallet would authorize
agentkeys signer preview-7730 \
  --typed-data-file ./permit.json \
  [--7730-file ./erc20-permit.json | --catalog bundled]

# Sign with preview + confirmation prompt (interactive)
agentkeys signer sign-typed-data \
  --signer-url <url> \
  --omni-account <64hex> \
  --typed-data-file ./permit.json \
  [--no-preview]
```

**Surface affected:** [`crates/agentkeys-cli/`](../../crates/agentkeys-cli/) — new
subcommands routed through `signer` group.

**MCP tool (later — separate issue):** `agentkeys.preview_sign` returns the
rendered display for LLM agents to surface inline before requesting the
operator's K11 assertion.

## Phase 4 — Intent-aware audit (schema this PR; wiring follow-up)

**Arch.md §15.3 addition (this PR):** extend audit-row schema with:

- `signed_intent_text` — the rendered `interpolatedIntent` string (e.g.,
  `"Approve USDC 1000.00 to Uniswap v4 router"`).
- `signed_intent_hash` — `keccak256(intent_text || "|" || digest)`. The
  audit row cryptographically commits to the rendered intent the operator
  saw.

**Wiring (follow-up issue):**

- `agentkeys-worker-audit::handlers::append` accepts the two fields in the
  request body and stores them.
- `CredentialAudit.append(...)` on chain extends its event log to include
  the commitment hash (text stays off-chain; chain holds only the
  commitment).
- Broker cap-mint propagates the commitment through the cap-token's
  `intent_commitment` field so workers can verify it before any sign call.

**Why split:** the schema is backwards-compatible (workers ignore unknown
fields today); the chain-side audit event extension requires a contract
revision + redeploy, which is a separate change ladder. Schema-first
unblocks Phase 3 to start writing intent fields immediately; the chain
extension lands when the next contract revision ships.

## Phase 5 — K11 binding on high-value signs (NEW vs original #82)

Original #82 missed this entirely. Per arch.md §10.1 + §5a, K11 WebAuthn is
required for master mutations. Typed-data signs that meet operator-policy
thresholds (e.g., `tokenAmount > $POLICY_THRESHOLD` per `7730 display`
formatter output) should require a fresh K11 assertion in addition to K10.

**Wiring (separate issue):**

- Broker `handlers/cap.rs` adds an `intent_requires_k11` policy hook.
- ScopeContract on chain stores per-(operator, agent) signing policy
  (max tokenAmount per service, allow-listed verifyingContract set).
- Daemon's localhost proxy triggers the K11 ceremony when the policy hook
  fires.

Tracked separately as a follow-up to this PR because the ScopeContract
extension is non-trivial.

---

## What ships in THIS PR (scope lock)

| Phase | Status | Notes |
|---|---|---|
| Plan refresh (this doc) | ✅ | Replaces stale #82 body |
| signer-protocol.md update | ✅ | `/dev/sign-typed-data` documented |
| arch.md §14.2 + §15.3 + §22 update | ✅ | New endpoint + intent commitment + clear-signing pluggable surface |
| Phase 1 — EIP-712 signing | ✅ | `dev_key_service.sign_eip712` + handler + signer_client method + tests |
| Phase 2 — clear_signing module | ✅ | Parser + formatter + binding + 1 bundled fixture (USDC permit) |
| Phase 3 — CLI preview + sign-typed | ✅ | Two new `agentkeys signer ...` subcommands |
| Phase 4 — audit intent schema | ✅ (docs only) | Schema in arch.md §15.3; broker/worker wiring deferred |
| Phase 5 — K11-on-high-value | ❌ (separate issue) | Needs ScopeContract extension |

## What does NOT ship in this PR

- **K11 binding on high-value signs (Phase 5).** Needs ScopeContract revision; tracked as follow-up.
- **Broker cap-mint policy gate.** Tracked as follow-up; the cap-mint endpoint will eventually gate sign requests against `intent_commitment` but the broker side stays unchanged in this PR (daemon → signer goes direct via `signer_client`).
- **Worker audit-row wiring.** Schema is documented; worker reads of new fields will land when the follow-up Phase 4 wiring PR ships. Today's worker silently ignores them (forward-compatible).
- **On-chain CredentialAudit event extension.** Needs contract revision + redeploy; tracked separately.
- **Registry fetch (v1).** Follow-up issue; v0 catalog is bundled-only.
- **EIP-4337 UserOp clear signing.** Out of scope per original #82.
- **FHE / encrypted-field support.** Out of scope per original #82.
