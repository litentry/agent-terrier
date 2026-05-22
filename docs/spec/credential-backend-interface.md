# AgentKeys — Credential Backend Interface Specification

**Date:** 2026-04-08
**Source:** CEO review + eng review decisions
**Purpose:** Define the abstract interfaces that allow AgentKeys to run on multiple backends (Heima TEE, centralized server, mock) and multiple payment rails (crypto-native, fiat via paymaster, hybrid).

---

## 1. Why This Abstraction Exists

AgentKeys must operate across jurisdictions with different regulatory regimes:

- **Crypto-friendly jurisdictions:** Users pay directly with USDC via x402. Credentials stored on Heima TEE with on-chain audit. Full decentralization.
- **Crypto-restricted jurisdictions (China, some SEA countries):** Cryptocurrency payments are banned or restricted. Users pay via fiat (Alipay, GrabPay, WeChat Pay, bank transfer). Credentials may need to be stored on a government-compliant centralized server rather than a public blockchain.
- **Enterprise/government environments:** Data residency requirements. Credentials must stay on-premises or in a specific cloud region. Payment is via enterprise billing (invoicing, purchase orders).

The same `agentkeys` CLI and daemon must work in all three scenarios. The only thing that changes is the **backend** (where credentials are stored and how sessions are managed) and the **payment rail** (how usage is billed).

## 2. Credential Backend Trait

The core abstraction. CLI and daemon depend on this trait, never on Heima-specific types.

```rust
#[async_trait]
pub trait CredentialBackend: Send + Sync {
    /// Authenticate user and create a master session.
    /// auth_token: Google OAuth token, passkey assertion, or other identity proof.
    /// Returns: session handle + canonical wallet address (mock or real EVM).
    async fn create_session(&self, auth_token: AuthToken)
        -> Result<(Session, WalletAddress)>;

    /// Mint a scoped child session for an agent.
    /// The child session can only access credentials within `scope`.
    async fn create_child_session(&self, parent: &Session, scope: Scope)
        -> Result<(Session, WalletAddress)>;

    /// Store an encrypted credential blob.
    /// Ciphertext is encrypted to the backend's shielding key by the caller.
    async fn store_credential(&self, session: &Session,
        agent_id: &WalletAddress, service: &ServiceName,
        ciphertext: &[u8]) -> Result<()>;

    /// Read a credential. Backend enforces scope: agent can only read its own.
    /// Returns decrypted credential bytes.
    async fn read_credential(&self, session: &Session,
        agent_id: &WalletAddress, service: &ServiceName)
        -> Result<Vec<u8>>;

    /// Query the audit log. Filterable by owner, agent, service, time range.
    async fn query_audit(&self, session: &Session, filter: AuditFilter)
        -> Result<Vec<AuditEvent>>;

    /// Revoke a session immediately. All subsequent reads with this session fail.
    async fn revoke_session(&self, session: &Session,
        target: &Session) -> Result<()>;

    /// Tear down an agent: revoke all sessions, delete all credentials.
    async fn teardown_agent(&self, session: &Session,
        agent_id: &WalletAddress) -> Result<()>;

    /// Get the backend's public shielding key for client-side encryption.
    async fn shielding_key(&self) -> Result<PublicKey>;

    // ========================================================================
    // Rendezvous (added 2026-04-09 after Round 13 cloud-LLM-assistant case)
    //
    // Rendezvous exists because a daemon inside a hosted cloud LLM sandbox
    // has no inbound-reachable URL — the Mac CLI cannot connect to it
    // directly. Both sides CAN reach the CredentialBackend, so we use the
    // backend as the rendezvous relay. The pair flow becomes:
    //   daemon.register_rendezvous(pubkey, pair_code) → long-poll wait
    //   cli.deliver_rendezvous(pair_code, encrypted_child_session)
    //   daemon receives payload → decrypts into memfd_secret
    // Also becomes the UNIVERSAL pair path for every backend — local Docker,
    // hardened fork, Fly.io VM, cloud LLM — so the CLI no longer needs
    // backend-specific URL knowledge.
    // ========================================================================

    /// Daemon side: register a pairing intent. Returns a registration token
    /// the daemon can use to poll / long-poll. TTL is backend-enforced (v0:
    /// 5 minutes). pair_code is a 6-char human-readable code derived from
    /// the TEE-generated nonce for this request.
    async fn register_rendezvous(&self,
        daemon_pubkey: &PublicKey,
        pair_code: &PairCode,
    ) -> Result<RegistrationToken>;

    /// Daemon side: wait for the pairing payload. Long-poll with a backend-
    /// enforced timeout. Returns the encrypted payload delivered by the CLI
    /// OR a clean timeout the daemon can retry on.
    async fn poll_rendezvous(&self,
        token: &RegistrationToken,
    ) -> Result<Option<PairPayload>>;

    /// CLI side: deliver an encrypted pair payload to a waiting daemon.
    /// The CLI has authenticated with its master session; the backend
    /// verifies the pair_code matches an outstanding registration and
    /// relays the ciphertext. The backend SEES ONLY CIPHERTEXT — the
    /// payload is encrypted to daemon_pubkey before transit.
    async fn deliver_rendezvous(&self,
        session: &Session,
        pair_code: &PairCode,
        payload: &EncryptedPairPayload,
    ) -> Result<()>;

    // ========================================================================
    // Authorization request primitive (added 2026-04-09)
    //
    // Generalized "Master approves a Child operation" channel. Every flow
    // that needs explicit Master consent routes through this:
    //   - Pair a new daemon
    //   - Recover an existing agent's wallet + credentials to a new daemon
    //   - Expand or reduce an agent's scope
    //   - Release a credential for a high-value call (spend threshold)
    //   - Rotate a session key
    //
    // One primitive, many uses. Replay-resistant by construction: every
    // request has a TEE-generated nonce, is single-use, has a TTL, and the
    // Master's signature is over a hash that includes canonical request
    // details + child pubkey + nonce.
    //
    // The OTP shown to the user is a HUMAN CONFIRMATION CHANNEL, not a
    // secret. Its job is to let the user visually verify that the request
    // shown on the Master device matches the request the Child is waiting
    // on. Crypto does the enforcement; the OTP does the human UX.
    // Same pattern as WebAuthn cross-device, Signal Safety Numbers, BLE
    // numeric comparison.
    // ========================================================================

    /// Child side: open an authorization request. Backend assigns an ID and
    /// a TEE-generated nonce, derives the human-visible OTP, stores the
    /// request with a TTL, and returns the OTP so the child can show it to
    /// the user (e.g., print it in the LLM chat).
    ///
    /// `request_details` must be canonically serialized (CBOR with sorted
    /// keys) so the hash that the backend signs (on the Master's behalf)
    /// is deterministic across implementations.
    async fn open_auth_request(&self,
        child_pubkey: &PublicKey,
        request_type: AuthRequestType,
        request_details: &CanonicalBytes,
    ) -> Result<OpenedAuthRequest>; // contains: id, otp, ttl, nonce_hash

    /// Master side: fetch an open request for the user to inspect. The
    /// user typed the pair code they saw on the daemon's screen; the
    /// Master CLI uses it to look up the pending request. Displays the
    /// full request details + the OTP and asks the user to confirm it
    /// matches what the Child showed.
    ///
    /// Accepts a `PairCode` (not a `request_id`) because in the child-
    /// initiates model, the Master CLI only knows the pair code the user
    /// typed — it never sees the request_id directly. The backend
    /// resolves pair_code → request_id internally.
    async fn fetch_auth_request(&self,
        session: &Session,
        pair_code: &PairCode,
    ) -> Result<AuthRequest>;

    /// Master side: approve an authorization request after the user
    /// confirmed the OTP match. The CLI sends only its session (proof of
    /// who the user is) — **no client-side signature**. The backend holds
    /// the master private key (server-side in MockBackend v0, inside the
    /// TEE in HeimaBackend v0.1) and signs internally:
    ///   SHA256("AgentKeys-v1-AuthRequest" || id || request_type
    ///          || canonical(request_details) || child_pubkey
    ///          || parent_session || created_at || nonce)
    /// Then marks the request as consumed. Single-use — a second call
    /// returns ALREADY_CONSUMED.
    ///
    /// Future extension (v0.2+): an optional `client_signature` parameter
    /// allows users who have exported their master key locally (or to a
    /// phone app) to sign client-side. When present, the backend verifies
    /// the client signature against the stored public key instead of
    /// signing itself. This gives full self-custody without changing the
    /// trait contract.
    async fn approve_auth_request(&self,
        session: &Session,
        request_id: &AuthRequestId,
    ) -> Result<()>;

    /// Child side: long-poll for the signed decision. Returns the signed
    /// authorization OR a clean timeout the child can retry on. Once
    /// consumed, further polls return CONSUMED and the child destroys its
    /// local copy of the nonce.
    async fn await_auth_decision(&self,
        request_id: &AuthRequestId,
    ) -> Result<SignedAuthDecision>;
}
```

### AuthRequestType enum

```rust
pub enum AuthRequestType {
    /// Pair a new daemon — mint a fresh agent wallet + scoped session.
    Pair { requested_scope: Scope },

    /// Recover an existing agent to a new daemon. The backend resolves
    /// the human-readable identity (alias, email, ENS name) via the
    /// identity graph (`pallet-omni-account` in Heima, SQLite lookup
    /// table in mock backend) to find the agent's wallet address, then
    /// re-encrypts the agent's wallet + credential ciphertexts to the
    /// new daemon's pubkey. Solves the ephemeral-cloud-LLM case:
    /// daemons die, agents don't. Falls back to raw `WalletAddress`
    /// if no human-readable identity is linked.
    Recover { agent_identity: AgentIdentity, new_daemon_pubkey: PublicKey },

    /// Expand or reduce an existing agent's scope.
    ScopeChange { agent_id: WalletAddress, new_scope: Scope },

    /// Release a credential for a call whose estimated cost exceeds a
    /// user-configured threshold. Used for "phone-approve large spends".
    HighValueRelease { agent_id: WalletAddress, service: ServiceName, estimated_cost_usd: Decimal },

    /// Rotate an agent's session key or daemon pubkey without minting a
    /// new agent identity.
    KeyRotate { agent_id: WalletAddress, new_pubkey: PublicKey },
}
```

### AgentIdentity — human-readable or raw wallet

```rust
pub enum AgentIdentity {
    /// Human-readable alias set via `agentkeys link agent-A --alias "my-bot"`.
    Alias(String),

    /// Email linked via `agentkeys link agent-A --email bot@example.com`.
    /// Resolved via the identity graph (pallet-omni-account in Heima,
    /// SQLite lookup in mock backend).
    Email(String),

    /// ENS name or other on-chain identity (future).
    Ens(String),

    /// Raw wallet address — always works, but less ergonomic for cloud
    /// LLM chat where the user has to remember or paste an address.
    WalletAddress(WalletAddress),
}
```

The backend resolves `AgentIdentity` → `WalletAddress` via the identity graph before processing the auth request. If the identity is not found, returns `AGENT_NOT_FOUND` with guidance to link an identity or use the raw wallet address.

### Canonical serialization

All `request_details` values MUST be serialized with **deterministic CBOR** (RFC 8949 §4.2.1 Core Deterministic Encoding Requirements) before hashing: sorted map keys, shortest-form integer encoding, no indefinite-length items. This is non-negotiable — any deviation across implementations produces hash mismatches that break verification on the daemon side. Test vectors for each `AuthRequestType` variant live in `agentkeys-core/tests/auth_request_vectors.json` and all backend implementations must pass them.

### Signing model

**v0 (MockBackend) and v0.1 (HeimaBackend):** the master private key lives in the backend (server-side in v0, inside the TEE in v0.1). The Mac CLI does NOT hold the master key — it holds only a session key that proves "I'm the user who authenticated via Google/passkey." When the CLI calls `approve_auth_request`, the backend verifies the session, looks up the user's master key, and signs the canonical request hash internally. The daemon receives the signed decision and verifies it against the user's master public key (which it obtained during the pair flow).

**v0.2+ (optional local key export):** users who want full self-custody can export their master private key from the backend/TEE to their local machine (or phone app). With a local key, `approve_auth_request` can accept an optional client-generated signature. When present, the backend verifies the client signature against the stored public key instead of signing itself. This is a future extension — the trait method acquires an `Option<Signature>` parameter without changing its semantics for callers who don't supply one.

**v0.2+ (phone app with QR code):** the phone app holds the master key (exported from TEE) and replaces the CLI's text-based OTP confirmation with a QR code challenge-response. The CLI (or daemon, or web UI) displays a QR code encoding the auth request; the phone scans, shows request details for review, signs locally, and sends the signature to the backend. Eliminates manual OTP typing entirely.

### Replay resistance invariants (enforced backend-side)

1. `request_id` is single-use. One successful `approve_auth_request` consumes it; a second attempt returns `ALREADY_CONSUMED`.
2. `nonce` is TEE-generated per request (mock backend: CSPRNG), 256 bits, never reused, destroyed on consumption or expiry.
3. TTL: 60 seconds for interactive flows (Pair, Recover), 5 minutes for async flows (ScopeChange, HighValueRelease). After TTL, request moves to EXPIRED and cannot be approved.
4. The backend's internal signature covers the full canonical request: `SHA256("AgentKeys-v1-AuthRequest" || request_id || request_type || canonical(request_details) || child_pubkey || parent_session || created_at || nonce)`. The daemon verifies this signature against the user's master public key, ensuring the backend signed over the actual request, not a substituted one. Any tampering between `open` and `approve` is caught daemon-side.
5. Pair codes and OTPs are derived from the nonce, not chosen independently — so OTP collisions on the wire cannot authorize a different request, because the daemon's signature verification catches the hash mismatch even if the displayed digits happen to match.

### Implementations

| Backend | Storage | Session Keys | Audit | Trust Model |
|---------|---------|-------------|-------|-------------|
| **MockBackend (v0)** | SQLite on VPS | Server-generated tokens | SQLite table | Trust the VPS operator |
| **HeimaBackend (v0.1)** | TEE-encrypted blobs on Heima chain | TEE-attested ephemeral keys | On-chain extrinsics | Trust Intel SGX + Heima validators |
| **CentralizedBackend (future)** | Encrypted DB (Postgres + KMS) | Server-generated tokens + HMAC | DB audit table + SIEM export | Trust the server operator (enterprise/gov) |

**Scope note on the rendezvous and authorization-request methods (added 2026-04-09):** these methods are implemented by **MockBackend in v0 only**. No blockchain work is in v0 scope. The HeimaBackend implementation of `register_rendezvous` / `poll_rendezvous` / `deliver_rendezvous` / `open_auth_request` / `fetch_auth_request` / `approve_auth_request` / `await_auth_decision` lives in the v0.1 Heima integration TODO list (see `plans/ceo-plan.md` §"Deferred to v0.1"). The trait contract and canonical CBOR test vectors are shared across backends so the Heima implementation can drop in without any CLI, daemon, or provisioner changes — but writing the pallet is not in v0 scope.

### Mapping to Heima Primitives

> **Superseded 2026-04-26 — vault rows.** The `store_credential` / `read_credential` rows below originally pointed at `pallet-secrets-vault` (on-chain encrypted blob store). Per [`./threat-model-key-custody.md`](./threat-model-key-custody.md) and [`../stage8-wip.md`](../stage8-wip.md), the canonical v0.1 design moves ciphertext **off-chain** into S3 under per-epoch DEKs. The chain holds only `(blob_pointer, ciphertext_hash, epoch)` via `pallet-vault-pointers`. Mapping rows updated below; the on-chain encrypted vault is no longer a target.

For the Heima backend implementation:

| Trait Method | Heima Primitive | Notes |
|-------------|----------------|-------|
| `create_session` | Google OAuth → `pallet-identity-management` → `RegisterUserByOmniAccount` | Existing flow, reuse |
| `create_child_session` | New: scoped session key minting in TEE worker (Kai Q1) | Needs to be built |
| `store_credential` | S3 PUT under `s3://agentkeys-vault/<wallet>/<service>/<epoch>/<blob_id>.enc` + new `pallet-vault-pointers::register_blob` extrinsic | Stage 8; replaces former `pallet-secrets-vault::write_secret` |
| `read_credential` | `pallet-vault-pointers::lookup` → S3 GET → TEE unwraps DEK + decrypts; scope check on chain | Stage 8; replaces former `pallet-secrets-vault::read_secret_intent` |
| `query_audit` | Chain events + Subsquid/Subquery indexer | Standard Substrate dev |
| `revoke_session` | Policy table update in TEE worker, propagates in ~1 block (~6s) (Kai Q9) | Verify with Kai |
| `teardown_agent` | Batch: revoke sessions + S3 lifecycle-delete blobs + epoch-rotate user DEK | Composition of above |
| `shielding_key` | `pallet-teebag` shielding key (already public on chain) | Reuse — used to wrap epoch DEKs, not to encrypt bulk data |

## 3. Payment Rail Abstraction

Separate from the credential backend. AgentKeys has **two distinct payment layers** that should not be conflated:

1. **System gas (Heima chain):** Paid in **HEI** (Heima's native gas token). Covers on-chain extrinsics: credential store, session mint, session revoke, audit log writes. These are Heima parachain transactions that consume gas like any Substrate extrinsic.

2. **Service payment (Base Chain):** Paid in **USDC via x402 protocol on Base Chain**. Covers actual API service costs: OpenRouter inference, Brave Search queries, Notion API calls, etc. This is what the agent spends when it uses the provisioned credentials.

The `PaymentRail` trait abstracts over both layers:

```rust
#[async_trait]
pub trait PaymentRail: Send + Sync {
    /// Check if the user/agent has sufficient balance for an operation.
    /// For system gas: checks HEI balance on Heima.
    /// For service payment: checks USDC balance on Base Chain.
    async fn check_balance(&self, wallet: &WalletAddress, amount: Amount,
        layer: PaymentLayer) -> Result<bool>;

    /// Debit an amount for a provisioning or usage operation.
    async fn debit(&self, wallet: &WalletAddress, amount: Amount,
        layer: PaymentLayer, reason: &str) -> Result<TransactionReceipt>;

    /// Fund a child wallet from the master wallet.
    async fn fund_child(&self, master: &WalletAddress,
        child: &WalletAddress, amount: Amount,
        layer: PaymentLayer) -> Result<TransactionReceipt>;

    /// Query spending history (both layers combined or filtered).
    async fn spending_history(&self, wallet: &WalletAddress, filter: SpendFilter)
        -> Result<Vec<SpendEvent>>;

    /// Get the payment method display name for CLI output.
    fn display_name(&self) -> &str;
}

pub enum PaymentLayer {
    /// Heima chain gas fees (HEI token). For credential store/read/revoke
    /// extrinsics, session minting, audit log writes.
    SystemGas,

    /// API service usage fees (USDC on Base Chain via x402). For actual
    /// consumption of provisioned services (OpenRouter, Brave, etc.).
    ServicePayment,
}
```

### Payment Implementations

| Payment Rail | System Gas (Heima) | Service Payment | User Pays With | Jurisdictions |
|---|---|---|---|---|
| **Crypto Direct (target)** | HEI (native token) | USDC on Base Chain (x402) | Crypto wallet holding both HEI + USDC | Crypto-friendly (US, EU, Singapore, etc.) |
| **Paymaster + Fiat (Option 1)** | HEI, sponsored by paymaster | USDC on Base, sponsored by paymaster | Alipay / GrabPay / WeChat Pay / bank transfer | Crypto-restricted (China, some SEA) |
| **Centralized Billing (Option 2)** | N/A (no chain) | Fiat (CNY, USD, SGD) | Alipay / credit card / invoice | Enterprise, government, crypto-banned |
| **Mock (v0)** | Fake HEI (numbers in DB) | Fake USDC (numbers in DB) | Nothing (free for testing) | Development/testing |

### The Paymaster Pattern (Option 1)

For jurisdictions where users cannot hold or transact cryptocurrency directly, but the system still runs on a blockchain. The paymaster handles BOTH payment layers:

```
User                    AgentKeys              Paymaster Service        Chains
 │                         │                        │                      │
 │ Pay 29.9 CNY/month ────►│                        │                      │
 │ via Alipay              │ Record fiat payment ──►│                      │
 │                         │                        │ Allocate from pool:  │
 │                         │                        │  - HEI for Heima gas │
 │                         │                        │  - USDC for services │
 │                         │                        │                      │
 │ agentkeys store ────────►│                        │                      │
 │                         │ Request gas sponsor ───►│                      │
 │                         │                        │ Submit Heima tx with │
 │                         │                        │ HEI from pool ──────►│ Heima: credential stored
 │                         │                        │                      │
 │ agent uses OpenRouter ──►│                        │                      │
 │                         │ Request USDC sponsor ──►│                      │
 │                         │                        │ x402 payment with    │
 │                         │                        │ USDC on Base ───────►│ Base: service paid
 │                         │ ◄── success             │                      │
```

The user never touches crypto. The paymaster converts fiat to HEI (for Heima gas) and USDC (for service payments on Base Chain) and sponsors both transaction types. The blockchain still provides TEE-attested credential storage and on-chain audit. The user's experience is identical to a subscription service.

**Advantages:**
- Full Heima security model preserved (TEE, on-chain audit, instant revocation)
- User pays in local currency via familiar payment methods
- Regulatory compliant: the user never holds cryptocurrency
- The paymaster is a business entity that can be licensed/regulated

**Disadvantages:**
- Requires a paymaster service (operational overhead, needs to hold both HEI and USDC)
- Fiat-to-crypto conversion adds cost (~2-3% payment processing fees)
- The paymaster is a centralized intermediary (partial centralization)
- Needs different paymaster per jurisdiction (Alipay for China, GrabPay for SEA)

### Centralized Billing (Option 2)

For environments where no blockchain is used at all:

- The `CentralizedBackend` stores credentials in an encrypted database
- Payment is via standard SaaS billing (Stripe, Alipay, enterprise invoicing)
- Audit log is in a database, exportable to SIEM
- No on-chain anything

This is the "fallback" for maximum regulatory compliance at the cost of losing the decentralization story.

### Recommendation

**Support both.** The `PaymentRail` trait makes this a configuration choice, not an architectural one:

```toml
# agentkeys.toml

[backend]
type = "heima"  # or "mock" or "centralized"

[payment]
type = "crypto_direct"  # or "paymaster" or "centralized" or "mock"

[payment.system_gas]
chain = "heima"
token = "HEI"  # Heima native gas token for extrinsics

[payment.service]
chain = "base"
token = "USDC"  # x402 payments on Base Chain for API services
x402_endpoint = "https://x402.base.org"

[payment.paymaster]
provider = "alipay"  # or "grabpay" or "wechat"
paymaster_url = "https://paymaster.agentkeys.cn"
# Paymaster sponsors BOTH HEI gas and USDC service payments
```

The user's jurisdiction determines the config. The CLI and daemon code is identical. The two-layer split (HEI for system, USDC for services) is invisible to the user — `agentkeys usage` shows both in a unified view.

## 4. v0 Implementation

For v0, both traits have a single implementation:

- `CredentialBackend` → `MockHttpBackend` (HTTP client → mock server)
- `PaymentRail` → `MockPayment` (numbers in DB, no real money)

The traits exist in `agentkeys-core` from day one. Future backends and payment rails are added as new implementations without touching CLI or daemon code.

## 5. Open Questions for Kai (updated from heima-open-questions.md)

The Kai meeting questions are now reframed around the trait interface:

1. **Q2 → `store_credential` / `read_credential`:** Does Heima have a general credential blob store that maps to these trait methods? If not, what's the gap work for `pallet-secrets-vault`?
2. **Q1 → `create_child_session`:** Can the TEE worker mint scoped child sessions as described? What's the scope enforcement model?
3. **Q3 → `read_credential` scope enforcement:** Is scope checked TEE-side at each read, or only at session creation?
4. **Q11 → Open source:** Can the AgentKeys-specific TEE worker additions be open-sourced?
5. **NEW → Paymaster support:** Does Heima support sponsored transactions (paymaster pattern)? If not, what's needed?

## 6. Cross-References

- CEO plan: [`./ceo-plan.md`](projects/idea/agentkeys/plans/ceo-plan.md)
- Architecture (13 components): [`../arch.md`](../arch.md)
- Auth-layer analysis: [`./1-step-analysis.md`](./1-step-analysis.md)
- Kai meeting agenda: [`./heima-open-questions.md`](./heima-open-questions.md)
- Open-source posture: [`./open-source-posture.md`](./open-source-posture.md)

---

*This document is the primary interface specification for AgentKeys. The mock backend in v0 is the first implementation. Kai builds the Heima implementation against this spec. Future backends (centralized, enterprise) also implement these traits.*
