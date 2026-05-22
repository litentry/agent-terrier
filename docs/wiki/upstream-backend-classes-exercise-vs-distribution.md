# Upstream backend classes — exercise vs distribution

**Status:** decided 2026-05-15. Source of truth for *how a new upstream is integrated* and *which patterns apply*. Cross-link from [`docs/arch.md`](../arch.md) §4b and §7a.

## The two security concerns

Per-upstream design splits into two independent problems. Many earlier drafts conflated them.

| Concern | Question | Whose job |
|---|---|---|
| **Exercise** | On every API call, is this caller authorized to do this exact thing? | Depends on upstream's auth model |
| **Distribution** | How does the right credential reach the right agent and only that agent? | Always ours |

Both must be solved. The *pattern* that solves each depends on the upstream.

## Class A — Per-request authorization (AWS-native)

Upstream signs and validates every API call independently. Examples: AWS S3, SES, KMS, future memory storage in S3.

| Property | Value |
|---|---|
| Exercise enforcement | Upstream (AWS) — every request re-validated against IAM + PrincipalTag |
| Distribution mechanism | Short-lived STS creds, minted via OIDC JWT signed by broker |
| Granularity ceiling | IAM-policy expressive power (prefix gates, tag conditions, action filters, time windows) |
| Per-actor isolation | `aws:PrincipalTag/agentkeys_user_wallet` projected from JWT claims into session tags |
| Credential lifetime | STS-controlled (≤ role `MaxSessionDuration`) |
| Revocation | Wait for TTL OR detach role policy (immediate but global) |

**The §6 STS-to-prefix pipeline IS both distribution and exercise.** There is no separable "credential" — the STS-signed request is the auth. The agent uses STS creds *directly* against the AWS API; the broker is off the hot path.

**Adding a new AWS-native upstream:** typically nothing on the broker side. Define a new bucket / table / queue, write IAM policy gated by the existing `agentkeys_user_wallet` tag, add it to the daemon's allow-list. The §6 pipeline carries it for free.

## Class B — Bearer-token authorization

Upstream issues an opaque token; subsequent API calls present the token; upstream trusts the bearer for whatever scope the token was minted with. Examples: OpenRouter, Anthropic, Groq, Brave Search, any third-party SaaS API.

| Property | Value |
|---|---|
| Exercise enforcement | **Provider-bounded** — only what the upstream exposes per key (spend cap, model allowlist, rate limit, expiry) |
| Distribution mechanism | Provisioner scrapes a per-grant key, deposits ciphertext in `vault_bucket`, agent fetches via Class-A pipeline |
| Granularity ceiling | Whatever provider settings allow + one-key-per-grant blast bound |
| Per-actor isolation | Vault prefix gated by PrincipalTag — same as Class A at the *distribution* layer |
| Credential lifetime | Provider-controlled OR rotated by re-running provisioner |
| Revocation | Delete vault object + revoke key at provider (two-step, not atomic) |

**Distribution rides Class A's rails; exercise punts to the provider.** Once the agent has the bearer in memory, the grant's `scope_path` no longer constrains anything — provider-side limits are the only ceiling. Accept this gap or use a broker proxy (see "Open questions" below).

**Adding a new Class-B upstream:**
1. Write a Playwright scraper at [`provisioner-scripts/src/scrapers/<service>.ts`](../provisioner-scripts/src/scrapers/) that signs up, mints an API key, and **sets provider-side caps** from grant fields (`spend_cap`, `allowed_models`, etc. — whatever the provider exposes).
2. Provisioner deposits ciphertext at `s3://vault_bucket/<wallet>/<service>/<grant_id>/key.json`.
3. Daemon retrieves via Class-A pipeline (mint OIDC JWT → STS → S3 read).
4. Daemon uses the bearer directly against the upstream — **not** through any broker proxy.

## Granular permission story by class

### Class A (AWS-native)

```
Grant scope     →  JWT claims (broker-side projection)
JWT claims      →  STS session tags
STS session tags → IAM policy evaluation per request
IAM policy      →  upstream allow/deny on each API call
```

Every layer enforces. End-to-end fine-grained. This is the "natural" path.

### Class B (bearer-token)

```
Grant scope     →  provisioner mints provider-side key with caps
                   + vault path = bucket/<wallet>/<service>/<grant_id>/
Grant validity  →  broker refuses to sign JWT for vault read if grant expired/consumed
JWT claims      →  STS PrincipalTag → S3 prefix gate (vault read only)
Bearer in agent →  provider-side caps enforce exercise; nothing finer
```

Enforcement narrows progressively until handoff to provider. The "Grant validity" line is the broker's policy point (the §5.2 server-side aggregator + §6 grant from the demo doc).

## Bucket layout consequence

Class A and Class B share the same S3 distribution rail but want *different bucket-level configuration*:

| Bucket | Data class | Versioning | Encryption | Object Lock | Lifecycle | CloudTrail data events |
|---|---|---|---|---|---|---|
| `vault_bucket` | Class B credentials (scraped API keys) | Off | SSE-KMS w/ customer CMK | No | Short TTL → expire on rotate | Every Get/Put |
| `memory_bucket` | Class A agent state (chat history, scratch, working memory) | On | SSE-S3 | No | Glacier after 90d | Sampled |
| `audit_bucket` | Append-only integrity-anchored log | On + MFA-delete | SSE-KMS w/ CMK | **Compliance mode, WORM** | Never expire | Every Get/Put + integrity check |

These cannot share a bucket — S3 bucket configuration (Versioning, Object Lock, BucketEncryption, Lifecycle) only exists at the bucket level. Separate buckets is the only way to express the matrix.

**Mental model:**

```
bucket  = (data class) × (operator deployment) × (environment)
prefix  = (wallet address)
object  = the unit of data
```

Per-actor isolation lives on the **prefix** layer (PrincipalTag → wallet). Per-data-class isolation lives on the **bucket** layer. The wallet does not replace the bucket — they're orthogonal axes, both required.

**Why `$BUCKET` is a variable (not a constant):** the bucket name carries data-class × deployment × environment. S3 bucket names are globally unique across AWS, so each operator account picks its own (`acme-agentkeys-vault-prod`, `litentry-agentkeys-vault-dev`, etc.). The variable absorbs the global-namespace + multi-env reality; it has nothing to do with per-actor isolation.

## Design rule for adding a new upstream

1. **Classify it.** Per-request-IAM upstream → Class A. Bearer-token upstream → Class B. If unsure, ask: "can the upstream re-authorize each individual API call, or does it accept a long-lived token that any holder can use?"
2. **Pick the bucket.** Class A → use the upstream itself OR `memory_bucket` if it's storing daemon-managed state. Class B → use `vault_bucket` for the scraped credential.
3. **Wire the grant.** Both classes consume `Grant{daemon_address, service, scope, expires_at, max_uses}`. The broker enforces grant-existence before signing the OIDC JWT; from there each class continues per the pattern above.
4. **Set provider-side caps (Class B only).** The provisioner scraper MUST attempt to set every provider-side limit the grant carries — spend cap, model allowlist, rate cap. Missing limits = compromised key has broader blast radius than the grant authorizes.

## Open questions / future work

### Broker-as-egress-proxy for Class B fine-grained exercise

The Class-B exercise gap (provider-side limits only) is real. For constraints that exceed provider expressiveness (e.g. "only chat completions where system prompt matches `/^You are/`"), an optional `/v1/proxy/{service}` endpoint at the broker would:

- Daemon never holds the upstream key
- Broker validates each forwarded request against grant fields
- Broker injects the master's key, calls upstream, streams response back

**Trade-off:** broker on hot path (latency, scaling, broker outage = upstream outage). Broker holds upstream key in memory (bigger blast radius — though it already holds the OIDC signing key, so the delta is smaller than it appears).

**Recommendation for v0:** don't ship. Document as a [§7 pluggable surface — "egress enforcement"] for future swap-in. Pay the proxy cost only when an operator genuinely needs constraints the provider can't enforce.

### Atomic revoke for Class B

Today: delete vault object + revoke at provider = two steps, not atomic. Until they're atomic, a window exists where the vault is empty but a cached bearer in an agent's memory still works at the provider. Mitigation: short TTL on scraped keys (provider-side), aggressive rotation cadence, audit of grant revoke → provider revoke latency.

### Vault backend swap (per arch.md §7)

The `vault_bucket = S3` choice is one row of [§7 pluggable surfaces](../arch.md#7-pluggable-surfaces). Future swaps (IPFS / Filecoin / Arweave content-addressed; on-chain pointer + hash) are tracked in [`threat-model-key-custody.md`](../spec/threat-model-key-custody.md) §4 + §9. The Class A vs Class B split documented here is independent of the vault backend — both classes ride whichever backend is configured for `vault_bucket`.

## Related

- [`docs/arch.md`](../arch.md) §4b (this split's home), §6 (per-mint sequence), §7 (pluggable surfaces), §7a (bucket layout)
- [`docs/stage7-demo-and-verification.md`](../stage7-demo-and-verification.md) §5.1, §5.2, §5.3 (Class A pipeline), §6 (grant lifecycle)
- [`crates/agentkeys-provisioner/`](../../crates/agentkeys-provisioner/) (Class B implementation)
- [`provisioner-scripts/src/scrapers/openrouter.ts`](../provisioner-scripts/src/scrapers/openrouter.ts) (Class B reference: OpenRouter)
- [`wiki/key-security.md`](./key-security.md), [`wiki/credential-usage.md`](./credential-usage.md), [`wiki/tag-based-access.md`](./tag-based-access.md) — adjacent wiki pages
