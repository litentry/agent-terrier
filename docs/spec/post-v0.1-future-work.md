# Post-v0.1 Future Work

**Status:** living backlog — items deferred past v0.1.
**Purpose:** capture design directions, hardening work, and extensions that are valuable but not on the v0 or v0.1 critical path. Every item here should eventually be promoted to `docs/archived/development-stages-v2-2026-04.md` with a concrete stage number, or dropped.
**Last updated:** 2026-04-20.

## 1. How this doc relates to the stage plan

- [`docs/archived/development-stages-v2-2026-04.md`](../archived/development-stages-v2-2026-04.md) — the stages we are committed to shipping.
- [`docs/spec/heima-gaps-vs-desired-architecture.md`](./heima-gaps-vs-desired-architecture.md) — deltas between upstream `litentry/heima` and the desired architecture; blockers for current stages.
- **This doc** — ideas that do not block current stages. Items here come from design reviews where we identified a better-but-bigger option, deferred it, and shipped the cheap version.

An item moves out of here when it (a) gets promoted to a numbered stage, or (b) is explicitly dropped as not worth pursuing.

---

## 2. OIDC-federation hardening (beyond Stage 7b)

Stage 7 ships `https://oidc.agentkeys.dev` with URL + TLS + JWKS-signature as the cryptographic trust anchor, hardened with AWS thumbprint pinning, CAA records, short-lived JWTs, and standard belt-and-suspenders. Stage 7b (see stage plan) adds `pallet-oidc-pubkeys` + a watchdog for fast detection-and-revocation of URL compromise. The items below go further.

### 2.1 TEE-hosted OIDC endpoint (attestation-rooted, not URL-rooted)

**Today (Stage 7 + 7b):** the JWKS is served by a thin HTTPS proxy. An attacker who compromises the proxy (DNS, CA, hosting, deploy pipeline) can swap the JWKS before the watchdog fires. The Stage 7b watchdog collapses the blast window from indefinite to ~60 seconds, but the endpoint itself is still not in the TEE.

**Desired:** the OIDC discovery and JWKS endpoints are served from inside the enclave, TLS-terminated by a cert whose private key is derived from the master seed at `derive("oidc/tls/v1")`. Cert is issued via ACME by the enclave itself. DNS-01 challenge answered by a dedicated subdomain that the enclave also signs. Compromise of the hosting tier (VM, K8s node, CDN) becomes irrelevant because the attacker cannot terminate TLS.

**Cost:** non-trivial. ACME client inside the enclave, DNS-01 plumbing, and the hosting shell becomes a dumb TCP forwarder. Probably 2–3 weeks.

**When to promote:** if URL-compromise risk materializes (close call observed), or if an enterprise customer requires this property.

### 2.2 Chain-native relying parties

**Today:** AWS/GCP/Ali can only verify JWTs via the HTTPS JWKS endpoint — they don't speak Substrate.

**Desired:** a Heima client library (WASM-compatible) that third-party services running inside or adjacent to the Heima network can use to verify JWTs directly against `pallet-oidc-pubkeys`. URL-hijack is irrelevant to these consumers because they never touch the URL.

**Cost:** a lightweight verifier crate + docs. 1 week.

**When to promote:** first partner service that runs on or near Heima and can consume chain-anchored trust.

### 2.3 On-chain TLS-cert fingerprints + dual-update requirement

**Today:** AWS thumbprint list holds a hash of the JWKS TLS cert. Rotation = update the thumbprint list.

**Desired:** a new extrinsic `register_oidc_tls_cert_fingerprint(fingerprint, active_from, active_until)`. Deploy pipeline enforces: no TLS cert rotation without a matching on-chain entry. Attacker who compromises only the hosting provider cannot silently replace the cert — they'd also need the chain governance key.

**Cost:** pallet extension (trivial) + deploy-pipeline gate (medium; requires CI/CD integration).

**When to promote:** together with §2.1 (makes the whole OIDC-trust story chain-anchored end-to-end).

### 2.4 Per-tenant OIDC issuer URLs

**Today:** one shared issuer at `oidc.agentkeys.dev` with one ES256 key. All tenants share the same issuer-key blast radius.

**Desired:** each enterprise tenant gets its own issuer URL `oidc.agentkeys.dev/tenant/<id>/` backed by its own derived key at `derive("oidc/tenant/<id>/v1")`. Compromise of one tenant's issuer key does not affect other tenants' federation.

**Cost:** multi-issuer routing in the proxy + per-tenant discovery docs. 1 week.

**When to promote:** first enterprise customer that requires tenant-isolated issuer keys (likely a contractual ask).

---

## 3. MRSIGNER rotation tooling

Stage 7b covers the rotation *mechanism* (attested seed handoff via inter-enclave remote attestation, governance-authorized successor list via `pallet-enclave-successors`). The items below smooth the relying-party-side experience.

### 3.1 `agentkeys oidc-rotate-trust` CLI

A small CLI that takes the operator's own cloud credentials and patches the trust policy on an IAM role / GCP WIF provider / Ali RAM role:

```
agentkeys oidc-rotate-trust --cloud aws --role-arn ... --add-mrsigner <B>
agentkeys oidc-rotate-trust --cloud aws --role-arn ... --remove-mrsigner <A>
```

**Cost:** 1 week per cloud (4 clouds = 4 weeks ideal; 1 cloud = 1 week minimum viable).

**When to promote:** first MRSIGNER rotation event, or when ≥3 customers are using `sub`-pattern MRSIGNER pinning.

### 3.2 Automated rotation orchestration for our own infra

Our own AWS/GCP/Ali accounts are managed by IaC. A GitHub Action can watch `pallet-enclave-successors` for new authorized MRSIGNERs and auto-open a PR that flips the trust-policy variable `MRSIGNER=[A] → [A,B] → [B]` on the timeline dictated by the grace window.

**Cost:** 1 sprint including IaC changes.

**When to promote:** first MRSIGNER rotation event (same as §3.1).

---

## 4. Hardening follow-ups to the daemon credential lifecycle

From [`wiki/key-security.md`](../wiki/key-security.md) §9 "Daemon Priority C" — items explicitly tagged as v0.2+.

### 4.1 Landlock / Pledge-style syscall containment for the daemon

Unix-only; macOS has `sandbox_init` but the ergonomics are ugly. Restrict the daemon to exactly the syscalls it needs. Defense-in-depth against supply-chain attacks on transitive dependencies.

### 4.2 OS-level isolation (namespaces, jails)

Run the daemon in a user namespace or FreeBSD jail. Complements Stage 3 kernel hardening.

### 4.3 Reproducible daemon binary builds

Deterministic builds so that `mrenclave`-style equivalent applies to the daemon: `daemon_hash` from source tree is reproducible by auditors. Establishes "this running daemon matches this tag" without trusting the build pipeline.

---

## 5. Knowledge-base backend expansions

See [`wiki/knowledge-storage.md`](../wiki/knowledge-storage.md) for the current four-candidate matrix (GitHub / AWS S3 / Google Drive / Ali Cloud OSS).

### 5.1 Dropbox / Box / OneDrive as additional non-dev backends

If a user segment emerges that prefers these over raw S3.

### 5.2 Local-first / IPFS / Arweave for crypto-native users

A chain-native audience may want memory stored on decentralized storage. The credential-broker shape still works — we mint an ephemeral Filecoin / IPFS signing key from the master seed, daemon uses it client-side.

### 5.3 Cross-backend migration tooling

User switches from hosted S3 to BYO GitHub — we need an export/import utility that preserves grants and audit trail continuity.

---

## 6. Email system (beyond Stage 6+7)

From [`wiki/email-system.md`](../wiki/email-system.md) §"Open items / follow-ups".

### 6.1 `docs/spec/token-authority-model.md` — the generalized three-layer spec

We currently describe the `TokenAuthority` / `TokenBroker` / `GrantStore` abstraction inline in email-system.md. Once three or more credential types (session tokens, email, knowledge base) share it, extract to a standalone spec.

### 6.2 Email-2FA approval flow spec

The [#11](https://github.com/litentry/agentKeys/issues/11) biometric gate needs a mobile-fallback-via-email section: message templates, magic-link vs 6-digit-code tradeoff, ≤10-minute TTL, replay protection via single-use nonce, CSRF on the magic-link endpoint.

### 6.3 BYO custom-domain email operator runbook

Stage 7 mentions this in deferred items; when a customer brings their own domain, we need a DNS configuration doc, MAIL FROM bounce-handling subdomain setup, DMARC alignment walkthrough. Distinct from the current Workspace DWD runbook at `docs/stage5-workspace-email-setup.md`.

---

## 7. Enterprise integrations

From Stage 7 deferred items.

### 7.1 SAML federation

Enterprises with legacy SAML stacks. Our TEE would need a SAML assertion-signing path; probably reuses the `oidc/issuer/v1` key with a SAML-signing adapter.

### 7.2 SCIM provisioning

When an enterprise onboards / offboards users, their IdP pushes updates via SCIM. Our backend would need a SCIM receiver that creates/revokes grants.

### 7.3 Enterprise SSO into our master CLI

Today the master CLI authenticates via our own flow. Enterprises will want "my employees sign in to AgentKeys via Okta / AzureAD / Google Workspace." Requires the OIDC-consumer direction (we trust their IdP), not just the OIDC-producer direction (Stages 6/7).

---

## 8. Protocol-level / research items

Exploratory work with unclear ROI. Park here so we don't re-open the same conversations.

### 8.1 Kubernetes-native audience for TEE JWTs

K8s ServiceAccount projection accepts external OIDC. Our JWTs could directly authenticate pods. Worth testing in v0.2.

### 8.2 On-chain payment rails on Base (x402)

If we extend the ES256 OIDC path to sign HTTP-payment requests as well, the same federation pattern covers payments. Needs an x402 implementation audit.

### 8.3 Attested audit-event feed for external verifiers

A signed-by-TEE audit-event feed that external parties can subscribe to without Heima-node operation. Useful for regulators / compliance tools. Requires a transport (Kafka? HTTP stream?) and a bootstrapping trust anchor.

---

## 9. Graveyard (items explicitly rejected)

Items we discussed and decided not to pursue. Listed here so we don't re-litigate.

- **AgentMail as a first-party email backend.** Their infra is AWS SES underneath; our SES impl gives us the things their SaaS does not (chain audit, per-child isolation via grants, no static cloud creds, broker-not-proxy). The three-layer abstraction still allows a customer to plug `AgentMailAuthority` if they want — we just don't ship it.
- **Static IAM access keys inside the TEE for AWS/GCP.** Superseded by OIDC federation; violates "no long-lived cloud credentials at rest."
- **Per-user IAM roles on AWS.** Doesn't scale past a few thousand users; superseded by PrincipalTag-via-JWT-claim (see [`wiki/tag-based-access.md`](../wiki/tag-based-access.md)).
- **Reading the user's personal Gmail for OTPs.** Collapses agent-mail and identity-mail into one inbox; fragile against Google's policy changes; see [`wiki/email-system.md`](../wiki/email-system.md) §"What this rules out."
