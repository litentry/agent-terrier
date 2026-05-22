# Email-Signing Backends: GCP-managed vs AgentKeys TEE

**Date:** 2026-04-18
**Status:** Design
**Stage:** 5a (alternative backend) → v0.1 (canonical)
**Related:** [#11 biometric gate](https://github.com/litentry/agentKeys/issues/11),
`docs/spec/credential-backend-interface.md`, `docs/docs/wiki/session-token.md`,
`docs/wiki/blockchain-tee-architecture.md`, `docs/stage5-workspace-email-setup.md`

---

## 1. What this doc decides

When a child agent needs to read email (e.g. the OpenRouter OTP during a live
provision), *who signs the JWT that impersonates the target Workspace user*?

Two answers:

- **Backend A — GCP-managed SA key + `iamcredentials.signJwt`.** Google holds the
  private key, never downloadable. AgentKeys calls Google's IAM API to sign
  DWD JWTs on demand.
- **Backend B — AgentKeys TEE.** The RSA private key is sealed inside our own
  enclave. The enclave signs DWD JWTs on demand, same wire format, same Google
  token-exchange flow.

Both back the same trait contract. The CLI and daemon don't know which one is
active. Switching backends is a config change.

**Decision.** Stage 5 ships Backend A as an alternative path. v0.1 migrates to
Backend B (AgentKeys TEE) and Backend A stays available as a permanent
jurisdiction/deployment variant — the same way the existing `CredentialBackend`
spec already supports `MockBackend` (v0), `HeimaBackend` (v0.1), and
`CentralizedBackend` (regulated environments).

## 2. Why an abstraction is required, not optional

AgentKeys already has a clear architectural rule about credential signing
(`docs/wiki/blockchain-tee-architecture.md` §6 rule #2):

> **The TEE holds all private keys and does all computation.** The TEE holds the
> shielding key, the RSA JWT signing key, and per-user custodial wallet keys
> (per `pallet-bitacross` pattern). These are generated independently (not
> derived from a single master seed) and sealed inside the enclave. [...]
> No private key ever leaves the TEE.

In v0, the "TEE" is a mock (a SQLite-backed process that holds what a real TEE
would hold). In v0.1, the TEE is Heima's enclave. In a Stage 5 prototype, we need
a signing authority for Gmail JWTs *today*, before v0.1 lands. A GCP-managed SA
key is a drop-in "TEE-equivalent" for signing: Google holds the key, we never
download it, and we call an API when we need a signature. It's an operator-trust
model rather than hardware-attestation model, but behind the `CredentialBackend`
trait the caller can't tell.

The goal is to specify the contract so Stage 5's GCP implementation and v0.1's
TEE implementation are interchangeable.

## 3. The trait contract (additions to `CredentialBackend`)

Two new methods + one new `AuthRequestType` variant. Both backends implement
them; the CLI, daemon, and provisioner-scripts code call through the trait.

```rust
pub enum AuthRequestType {
    // existing variants: Pair, Recover, ScopeChange, HighValueRelease, KeyRotate ...

    /// Grant a child the ability to read/write mail on a set of Workspace
    /// users. Biometric-gated on the master CLI (see §7). TTL = 30 days to
    /// match the AgentKeys session-key policy (docs/wiki/session-token.md §1).
    EmailImpersonate {
        user_pattern: EmailUserPattern, // exact, prefix, or /Automation OU
        scopes: Vec<EmailScope>,        // Read, Modify, Send
        ttl_seconds: u64,               // ≤ 30 * 86400
    },
}

pub enum EmailUserPattern {
    Exact(String),                   // "stage5test-20260419@wildmeta.ai"
    Prefix(String),                  // "stage5test-*@wildmeta.ai"
    OrgUnit(String),                 // "/Automation" — only our throwaway OU
}

#[async_trait]
pub trait CredentialBackend /* existing */ {
    /// Child side: mint a short-lived email access token, bounded by the
    /// scope previously granted via AuthRequestType::EmailImpersonate.
    /// Returns an opaque access token + its expiration. Both backends cap
    /// ttl ≤ 3600s (Google's max DWD access-token lifetime).
    ///
    /// Authorization: the child's session token proves identity; the backend
    /// checks the stored EmailImpersonate grant matches target_user and scope.
    async fn mint_email_access_token(
        &self,
        session: &Session,
        target_user: &str,
        scope: EmailScope,
    ) -> Result<EmailAccessToken>;

    /// Child side: perform a single email action. Backend mints a token
    /// internally (never returns it to the child) and executes the call.
    /// Preferred entry point for one-shot operations — leaves no token in
    /// the child process at all.
    ///
    /// Authorization: same as mint_email_access_token. Backend audit-logs
    /// every call regardless of backend type.
    async fn email_operation(
        &self,
        session: &Session,
        target_user: &str,
        op: EmailOperation,
    ) -> Result<EmailOperationResult>;
}

pub enum EmailOperation {
    ListMessages { query: String },
    GetMessage { id: String, format: MessageFormat },
    Send { raw_mime: Vec<u8> },
    Modify { id: String, add_labels: Vec<String>, remove_labels: Vec<String> },
    Trash { id: String },
}

pub struct EmailAccessToken {
    pub access_token: String,       // Bearer for api.gmail.com (≤ 1h)
    pub expires_at_unix: i64,
    pub target_user: String,        // echoed for logging / sanity check
    pub scope: EmailScope,
}
```

Callers never see a private key, JSON key file, or signed JWT. The wire is the
trait.

## 4. Backend A — GCP-managed SA key + `iamcredentials.signJwt`

### What Google holds

- **SA private key** — created at SA creation, held inside Google's KMS-class
  infrastructure, **never downloadable**. The `gcloud iam service-accounts keys
  create` step in the current setup doc is *optional* and actually counterproductive
  for this design (§6): the Google-managed key exists with or without a local
  download.
- **DWD authorization** — the policy object created at step B4: "this SA can
  impersonate any `wildmeta.ai` user with scopes `gmail.readonly, gmail.modify`."

### What AgentKeys holds

- **Nothing cryptographic.** The only credential is the OAuth token that
  `agent@wildmeta.ai` has already authenticated with (refresh token in
  `~/.config/gws/`), which grants the `roles/iam.serviceAccountTokenCreator` IAM
  permission on the SA.

### `mint_email_access_token` flow

```
1. child → backend: mint_email_access_token(session, target_user, scope=Read)
2. backend verifies session (JWT signature + expiration) ← standard AgentKeys path
3. backend checks stored EmailImpersonate grant:
     - grant exists for this child? ✓
     - target_user matches grant's user_pattern? ✓
     - scope subset of grant's scopes? ✓
     - grant's TTL not expired (≤ 30 days from issuance)? ✓
4. backend builds DWD JWT payload (iss=SA, sub=target_user, scope=gmail.readonly, ttl=1h)
5. backend → Google IAM: POST /v1/projects/-/serviceAccounts/<SA>/signJwt
       body: { payload: "<JSON payload>" }
       auth: agent@wildmeta.ai's OAuth token with roles/iam.serviceAccountTokenCreator
   → returns signedJwt (string)
6. backend → Google OAuth: POST oauth2.googleapis.com/token
       grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer, assertion=<signedJwt>
   → returns access_token (1h TTL)
7. backend → child: EmailAccessToken { access_token, expires_at, target_user, scope }
8. backend → chain (async): audit extrinsic
     { child, target_user, scope, backend=GCP, signjwt_request_id, timestamp }
```

### Trust assumptions

- **Google operates the KMS correctly.** Same assumption as anyone using GCP
  service accounts. Strong in practice; billions of dollars of infrastructure
  run on this.
- **GCP IAM is the policy gate.** Only principals with
  `roles/iam.serviceAccountTokenCreator` can call `signJwt`. We grant that role
  exactly to `agent@wildmeta.ai`, scoped to this one SA, logged to Cloud Audit
  Logs.
- **DWD authorization is the domain gate.** The SA can only impersonate users
  in `wildmeta.ai` (the domain B4 authorized). Cross-domain impersonation is
  structurally impossible.

### What this backend cannot do that Backend B can

- **Immutable audit** — GCP audit logs are strong, but they're operator-
  controlled (Google is the operator). They're not chain-immutable. This is the
  same "operator-verifiable vs publicly verifiable" tradeoff described in
  `docs/wiki/blockchain-tee-architecture.md` §5 under the pure-TEE-backend column.
- **"Leak of agent@wildmeta.ai is fully bounded"** — if `agent@wildmeta.ai`'s
  OAuth refresh token is stolen, the attacker can mint JWTs for any
  `wildmeta.ai` user (within the DWD scopes) for the token's lifetime. We
  mitigate by narrow IAM, wrapper service with `/Automation` allow-list, and
  revocation of the token on suspicion. But the ceiling is "any user in the
  domain", not "just the granted child's user".

## 5. Backend B — AgentKeys TEE + signJwt

### What the TEE holds

Same shape as the existing TEE-held primitives (`docs/wiki/blockchain-tee-architecture.md` §1):

- **RSA signing key for DWD JWTs** — generated inside the TEE, sealed storage,
  never extractable. Distinct from the TEE's JWT *session-token* signing key
  (which mints bearer tokens for master/children). Two RSA keys, two purposes.
- **DWD authorization registration** — the TEE registers its DWD public key
  with Google Workspace admin console (same one-click flow as B4 today; the
  "service account client ID" is replaced by the TEE's DWD pubkey fingerprint).

### What AgentKeys holds

- **Child session bearer tokens** (existing, 30-day)
- **No signing material** — identical posture to Backend A in that respect.

### `mint_email_access_token` flow

```
1. child → TEE: mint_email_access_token(session, target_user, scope=Read)
2. TEE verifies session token (RSA signature + expiration)
3. TEE reads chain state:
     - EmailImpersonate grant extrinsic for this child? ✓
     - target_user matches grant's user_pattern? ✓
     - scope subset of grant's scopes? ✓
     - grant's on-chain TTL not expired? ✓
4. TEE builds DWD JWT payload (iss=TEE_sa_identity, sub=target_user, scope=..., ttl=1h)
5. TEE signs the JWT locally with its sealed DWD private key
6. TEE → Google OAuth: POST oauth2.googleapis.com/token with the signed JWT
   → returns access_token (1h TTL)
7. TEE → child: EmailAccessToken { access_token, expires_at, target_user, scope }
8. TEE → chain (async): audit extrinsic
     { child, target_user, scope, backend=TEE, jwt_nonce, timestamp }
     signed by user's wallet key (TEE-held), submitted via paymaster
```

### Trust assumptions

- **Intel SGX / AMD SEV / equivalent attestation is correct.** Code inside the
  enclave is the code we signed.
- **Google honors the DWD registration.** Same as Backend A — DWD is still a
  Google-side policy object.
- **Chain is the policy gate.** The `EmailImpersonate` grant is an on-chain
  extrinsic. Revocation is an on-chain extrinsic. Scope changes are on-chain
  extrinsics.

### What this backend gives that Backend A cannot

- **Chain-immutable audit** — every email access is a signed, block-included
  extrinsic. Auditable by anyone with a Heima node.
- **Attacker-compromising-AgentKeys-can't-sign** — even if an attacker roots
  the machine running the AgentKeys backend, they can't extract the DWD
  signing key. The TEE is a mandatory signing gateway, and the enclave refuses
  to sign outside the policy.
- **Per-child blast-radius bound** — if a child's bearer token leaks, the
  attacker gets that child's scope (e.g. one email user pattern), not the
  whole domain. The DWD key itself never leaves the enclave.
- **Revocation via on-chain list** — same ~6s propagation as every other
  revocation in the system. A revoked child immediately fails at step 3.

## 6. Side-by-side

| Property | Backend A (GCP-managed) | Backend B (AgentKeys TEE) |
|---|---|---|
| DWD signing key location | Google KMS (never downloadable) | Our TEE (sealed) |
| Signing operator | Google | AgentKeys TEE operator |
| Policy gate | GCP IAM (`roles/iam.serviceAccountTokenCreator`) + DWD scope list | On-chain `EmailImpersonate` grant + on-chain revocation list |
| Audit log | GCP Cloud Audit Logs | On-chain extrinsic (publicly verifiable) |
| Audit immutability | Operator-controlled (Google) | Chain-finality (validator-attested) |
| Max access-token TTL | 3600 s (Google constraint) | 3600 s (same Google constraint) |
| Grant TTL (our layer) | 30 days (AgentKeys policy) | 30 days (AgentKeys policy) |
| Revocation latency | ~0 s (delete grant from our store) | ~6 s (on-chain list propagation) |
| Leak blast radius (AgentKeys side) | Any user in Workspace domain (DWD is domain-wide) | Only the granted child's user pattern |
| Leak blast radius (key material) | None — key is in Google KMS | None — key is in TEE |
| Infrastructure required | GCP project + one SA | Heima chain + TEE worker + DWD reg |
| Setup time | ~20 min (current `docs/stage5-workspace-email-setup.md`) | Weeks (TEE build + enclave deployment) |
| Appropriate stage | Stage 5 (now) | v0.1 (target) |

Both deliver: no private key in memory or disk, per-child audit attribution,
30-day grant lifetime, 1-hour access-token lifetime, same wire format to Google.

The honest difference: Backend A's audit is operator-trustable; Backend B's is
chain-verifiable. That's exactly the tradeoff the architecture doc
(`blockchain-tee-architecture.md` §5) chose for the credential layer overall.

## 7. How Touch ID gates both backends (issue #11)

This was explicit in the constraints list, and maps cleanly onto the existing
`AuthRequestType` pattern.

### What's gated

| Action | On which side | Gate |
|---|---|---|
| Grant `EmailImpersonate` to a child for the first time | **Master CLI** | **Touch ID required** (per #11 rule — creates credential-access privilege) |
| Change scope (e.g. add `Send` to an existing grant) | **Master CLI** | **Touch ID required** (same #11 rule applies — `ScopeChange` is already biometric-gated) |
| Revoke a grant | **Master CLI** | **Touch ID required** (#11 rule on `revoke`) |
| Mint an email access token within an existing grant | **Child/daemon** | **Silent** (#11 rule — normal ops stay silent) |
| Execute an email operation (`list_messages`, `send`, etc.) | **Child/daemon** | **Silent** (#11 rule — same as `store`/`read`) |

In short: **Touch ID gates the grant, not the use.** Once the master has
approved "child-X may impersonate stage5test-*@wildmeta.ai for gmail-read for
30 days", child-X can mint access tokens and call Gmail APIs silently for 30
days. If the grant expires or is revoked, the next `mint_email_access_token`
call fails.

### Wire-level: where the Touch ID prompt fires

Backend-agnostic. The biometric check sits in the master CLI, **before** the
CLI sends `approve_auth_request(request_id)` to the backend:

```
user types: agentkeys approve <pair-code>
  ↓
master CLI fetches AuthRequest (type = EmailImpersonate, details = {user, scopes, ttl})
  ↓
master CLI displays: "Allow child X to read mail for stage5test-*@wildmeta.ai, 30 days?"
  ↓
master CLI calls require_biometric("grant email impersonation")  ← #11 checkpoint
  ↓
Touch ID / Windows Hello / fprintd prompt → user confirms
  ↓
master CLI calls approve_auth_request(request_id)
  ↓
backend (A or B) persists the grant
```

Backend A stores the grant in its own datastore (SQLite for v0, whatever Stage 5
uses). Backend B stores it as an on-chain extrinsic. Either way, the biometric
check fired *before* the backend ever saw the approval — so the backend doesn't
know or care which ceremony was used to obtain the master's consent. That means
Backend A and Backend B inherit #11's gate for free via the existing
`AuthRequestType` pipeline.

### What's *not* gated by Touch ID — explicit list

- `mint_email_access_token` — silent, agent-side, must work unattended. Gated
  by the prior grant + session-token verification only.
- `email_operation` — same.
- Token refresh when the 1-hour access token expires — silent; the next child
  call triggers a fresh mint.

This exactly parallels how `agentkeys read openrouter` is silent today, while
`agentkeys approve <pair-code>` (which grants the openrouter scope) is
biometric-gated. New backend, same rule.

## 8. The 30-day constraint — how it maps

`docs/docs/wiki/session-token.md` §1: *AgentKeys policy: 30-day TTL for session/bearer
tokens.* The constraint here maps to **the grant**, not to the email access
token. Three nested lifetimes:

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   Child bearer token       = 30 days  (existing #10/#11)     │
│   │                                                          │
│   └── EmailImpersonate grant = 30 days (this spec) ──────────│
│       │                                                      │
│       └── Email access token = 1 hour  (Google constraint)   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

The child's bearer token authorizes its identity ("I am child-X"). The grant
authorizes its scope ("child-X may impersonate user pattern P for scope S").
The access token is the ephemeral artifact actually accepted by Gmail's API.

All three are independent:

- **Access token expires first (1 h).** Child re-requests silently from the
  backend. No user interaction.
- **Grant expires at 30 days.** Child's calls start failing
  `GRANT_EXPIRED`. Master must re-approve (with Touch ID) to extend. This
  re-consent matches the security model: a 30-day standing authorization to
  impersonate arbitrary Workspace users should not be auto-renewable forever.
- **Bearer token expires at 30 days** (existing policy). Child re-authenticates
  through the normal AgentKeys re-auth path. Independent of the grant.

Typically the grant is *shorter* than 30 days for one-off demos (e.g.
24 h for a single stage5 run), but the ceiling of 30 days aligns with the
session-token spec.

## 9. Practicality check (both paths must actually work)

### Backend A — practical today

| Requirement | Status |
|---|---|
| GCP project + SA created | ✅ Done (`wildmeta-agent-provisioner` / `stage5a-sa`) |
| DWD authorized for gmail.readonly, gmail.modify | ✅ Done (B4 of the setup doc) |
| `agent@wildmeta.ai` has `roles/iam.serviceAccountTokenCreator` on the SA | ⚠️ Needs grant (explicit, one `gcloud` command) |
| Custom admin role `stage5a-provisioner` assigned | ✅ Done |
| `/Automation` OU exists for throwaway users | ✅ Done |
| `CredentialBackend` Rust impl for Backend A | ❌ Not yet — needs `GcpEmailBackend` |
| `provisioner-scripts/src/lib/email.ts` reads `EmailAccessToken` from backend (replacing `imapflow`) | ❌ Not yet — tracked as Stage 5 follow-up |

**Verdict: buildable in ~1 week of engineering**, nothing external blocks.

### Backend B — path to practical

| Requirement | Status |
|---|---|
| Heima TEE worker operational for credential signing | In progress (Heima integration TODO list) |
| DWD registration for the TEE's signing identity with Google Workspace | Unblocked technically (same admin-console flow as Backend A); open policy question whether Google accepts a TEE-attested public key as a DWD client ID |
| `EmailImpersonate` pallet extension for on-chain grants | Pallet work — deferred to v0.1 Heima integration |
| `HeimaEmailBackend` Rust impl | v0.1 |
| Attestation pipeline proves the TEE isn't modified | Standard TEE deployment work |
| Revocation list extension for `EmailImpersonate` grants | Pallet work — v0.1 |

**Verdict: aligned with the existing v0.1 Heima work.** No new primitive needed
beyond what the Heima integration already ships (shielding key, JWT signing
key, pallet extensibility). The main open question is the Google-side policy
on DWD with an attested-TEE identity; if Google won't accept it, we fall back
to a hybrid where the TEE operator holds a Google-managed SA key and the TEE
calls `iamcredentials.signJwt` (essentially Backend A, but with the policy
gate shifted to the TEE). That's still a cleaner posture than raw Backend A
because the policy check is chain-authoritative.

## 10. Migration plan

```
now ──────────────── Stage 5 ────────────────── v0.1 ──────────────── v0.2+
         ┌───────────────────────┐         ┌──────────────────────┐
         │ Backend A             │         │ Backend B (primary)  │
         │   GCP-managed SA key  │         │   AgentKeys TEE      │
         │   `signJwt` API       │         │   sealed DWD key     │
         │   IAM + DWD as gate   │         │   on-chain grant     │
         └───────────────────────┘         │   on-chain audit     │
                                           └──────────────────────┘
                                           Backend A stays available
                                           as a jurisdictional / deployment
                                           variant (same pattern as
                                           CentralizedBackend).
```

**Stage 5 — Backend A only**

1. Add `GcpEmailBackend` implementing the new trait methods, backed by
   `iamcredentials.signJwt` + a small in-process grant store (SQLite or a
   file, parallel to `MockBackend`'s session store).
2. Extend `AuthRequestType` with `EmailImpersonate`. Wire the master CLI's
   Touch ID check into `approve_auth_request` handler for this variant
   (per §7).
3. Replace `provisioner-scripts/src/lib/email.ts`'s `imapflow` fetcher with a
   caller that reads an access token from the backend (via `email_operation`
   or `mint_email_access_token`).
4. The per-demo workflow in `docs/stage5-workspace-email-setup.md` shifts
   from "export the JSON and set env vars" to "run `agentkeys approve` once,
   confirm with Touch ID, then all subsequent demos run silently."

**v0.1 — Backend B primary, Backend A optional**

5. Build `HeimaEmailBackend` implementing the same trait. DWD registration for
   the TEE's identity, or hybrid-via-GCP if the direct route doesn't fly with
   Google.
6. The `EmailImpersonate` grant becomes an on-chain extrinsic; revocation
   joins the standard on-chain revocation list.
7. Config chooses the backend:

   ```toml
   [backend.email]
   type = "heima"       # default in v0.1
   # type = "gcp"       # alternative for environments without Heima access
   # type = "centralized" # future; for regulated jurisdictions
   ```

**Always-true invariants**

- The CLI, daemon, and provisioner-scripts code never import GCP or Heima
  libraries directly. They speak the trait.
- `approve_auth_request(EmailImpersonate{…})` is Touch-ID-gated master-side
  regardless of backend.
- `mint_email_access_token` and `email_operation` are silent agent-side
  regardless of backend.
- `audit_event { child, target_user, scope, backend_type, ... }` is emitted
  for every call; the storage layer differs, the event shape doesn't.

## 11. Open questions / follow-ups

1. **DWD with TEE-attested identity** — does Google Workspace admin console
   accept a public key / DCAP attestation as a DWD client ID? If yes, Backend
   B is clean; if no, Backend B proxies through Backend A's signing flow and
   the "no key in Google's hands" property weakens. Track as
   [#TBD — Heima DWD registration feasibility].
2. **Per-child user provisioning still hits the SA-key abstraction** — the
   `users.insert` / `users.delete` calls for throwaway accounts are Admin SDK
   calls that don't go through DWD. Today they're authed by
   `agent@wildmeta.ai`'s OAuth. Backend B inherits the same posture (or builds
   its own TEE-held admin credential), which is an orthogonal problem from
   the Gmail signing path.
3. **Refresh-token rotation for `agent@wildmeta.ai`** — Backend A depends on
   that refresh token being valid. Should be rotated on a schedule and on any
   suspected compromise. Add to `Rotation` section of
   `docs/stage5-workspace-email-setup.md` once Backend A ships.
4. **Cross-scope grant compilation** — can one grant cover both `Read` and
   `Send`? §3 says yes (scopes is a `Vec`), but the corresponding DWD scope
   list in Google admin-console has to be pre-populated with both. Already
   set in B4 today (gmail.readonly + gmail.modify).
5. **Backend A audit export** — Google Cloud Audit Logs can be routed to
   Pub/Sub and then to BigQuery or an external SIEM. Add a section to the
   setup doc with the `gcloud logging sinks create` command for operators who
   want audit off-Google. Not a blocker.

## 12. Cross-references

- `docs/spec/credential-backend-interface.md` — the existing trait we're
  extending. §3's `AuthRequestType` and the replay-resistance invariants
  apply here unchanged.
- `docs/wiki/blockchain-tee-architecture.md` §5 — the same
  "stateless-TEE-plus-chain vs pure-TEE-backend" tradeoff, one layer down.
  Backend B is the stateless-TEE-plus-chain choice; Backend A is the pure-
  operator-backed choice.
- `docs/docs/wiki/session-token.md` §1 — 30-day TTL policy this spec inherits for
  grants.
- `docs/wiki/key-security.md` §1 — two-tier storage model; the `EmailAccessToken`
  returned by `mint_email_access_token` is tier-1 (ephemeral bearer, handled
  like a session token in memory) and `EmailImpersonate` grants are tier-2
  analog (long-lived, persisted).
- [#11](https://github.com/litentry/agentKeys/issues/11) — biometric gate.
  §7 maps every new action onto its classification.
- `docs/stage5-workspace-email-setup.md` — operator setup for Backend A. A
  pointer to this doc for the design rationale is added there alongside this
  commit.
