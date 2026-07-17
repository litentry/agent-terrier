**Status:** IMPLEMENTED + PROVEN LIVE (2026-07-02, PR [#371](https://github.com/litentry/agentKeys/pull/371)). The full mint→storage chain ran against real VE: broker-signed ES256 JWT (TOS-hosted issuer) → `VeStsClient` `AssumeRoleWithOIDC` (VE Signature V4, per-actor session policy) → minted creds did a TOS put/get inside `bots/<actor>/…` and were **AccessDenied** outside it ([`tests/ve_sts_live.rs`](../../crates/agentkeys-broker-server/tests/ve_sts_live.rs)). Cloud-side provisioning: `setup-cloud-ve.sh` steps 50-55 (idempotent, converged). Remaining follow-ups at the bottom.
**Scope:** the AWS→VE seam for the credential-minting + object-storage path only. Chain, signer, OIDC-issuer, systemd/nginx are cloud-agnostic and already port. SES email **stays on AWS** (hybrid — VE has no inbound email). Companion: cloud-side provisioning is `scripts/operator/setup-cloud-ve.sh do_step_50+` (TOS buckets + VE IAM roles + OIDC provider).
**Canonical entry (#376):** operators now reach this stack via `scripts/operator/setup-cloud.sh --cloud ve` / `scripts/operator/setup-broker-host.sh --cloud ve` (the `--cloud` dispatcher on the AWS entries). The cloud-agnostic scaffolding lives in `scripts/operator/lib/{steps,cloud-common,host-common}.sh` and the VE cloud primitives (the five driver seams) in `scripts/operator/lib/cloud-ve.sh`; the `-ve` scripts remain directly callable for surgical re-runs.

## Why a runtime port is needed at all

The broker/worker storage plane calls `aws-sdk-sts` + `aws-sdk-s3` directly. Two of those don't cross to VE for free:

- **TOS is S3-wire-compatible** → `aws-sdk-s3` works against it with an endpoint override. *Easy half.*
- **VE STS is NOT AWS-wire-compatible** → it signs with **Volcengine Signature V4** (different service / credential-scope canonicalization from AWS SigV4) and the federation action is **`AssumeRoleWithOIDC`**, not `AssumeRoleWithWebIdentity`. `aws-sdk-sts` cannot target it by endpoint-swap. Needs a **VE-native STS client**. *Hard half.*

And one architectural fork (below): VE has no OIDC-token→session-tags mechanism, so per-actor isolation moves from PrincipalTags to an **inline session policy**.

## Credential flow (unchanged shape across clouds)

```
client (provisioner / daemon  aws_creds.rs)
   │  POST /v1/mint-oidc-jwt  (broker-signed session JWT in)
   ▼
broker  handlers/oidc.rs  → short-lived ES256 OIDC JWT (carries actor_omni)
   │  AssumeRole{WithWebIdentity | WithOIDC}(OIDC JWT)   ← THE PORT POINT
   ▼
STS (AWS | VE) → temp AK/SK/SessionToken scoped to this actor
   │  X-Aws-Access-Key-Id / -Secret-Access-Key / -Session-Token headers
   ▼
worker (cred/memory/config)  → builds a per-request S3|TOS client, does the op
   └─ isolation enforced at the CLOUD layer, not in the worker (passive relay)
```

The worker is a passive relay either way ([`worker-creds/src/aws_creds.rs`](../../crates/agentkeys-worker-creds/src/aws_creds.rs)); only the **mint** and the **S3-client construction** change.

## The isolation fork — PrincipalTags → session Policy

**AWS today:** [`handlers/oidc.rs`](../../crates/agentkeys-broker-server/src/handlers/oidc.rs) `build_oidc_jwt_claims()` embeds a `https://aws.amazon.com/tags` claim. AWS STS reads *that specific claim* to set session PrincipalTags; the bucket policy enforces `${aws:PrincipalTag/agentkeys_actor_omni}`. This claim is **AWS-proprietary** — VE does not read it.

**VE instead:** `AssumeRoleWithOIDC` takes an inline **`Policy`** parameter (a session policy that scopes *down* the role's permissions). The broker already knows `actor_omni` at mint time (verified session claim, oidc.rs:104). So per-actor isolation = **mint each session with an inline policy scoped to the actor's prefix**:

```jsonc
// session Policy passed to AssumeRoleWithOIDC (exact TRN/condition-key names: CONFIRM live)
{
  "Statement": [
    { "Effect": "Allow", "Action": ["tos:GetObject","tos:PutObject","tos:DeleteObject"],
      "Resource": ["trn:tos:::<vault-bucket>/bots/<actor_omni>/*"] },
    { "Effect": "Allow", "Action": ["tos:ListBucket"],
      "Resource": ["trn:tos:::<vault-bucket>"],
      "Condition": { "StringLike": { "tos:Prefix": "bots/<actor_omni>/*" } } }
  ]
}
```

Trade-off vs AWS: isolation is asserted at **mint time** (broker-built policy) rather than enforced **independently** by a static bucket policy keyed on a tag the broker can't forge. Mitigation: keep a **coarse bucket policy** too (deny cross-bucket, deny public) so the session policy is defense-in-depth, not the sole gate. Aligns with the AGENTS.md per-actor isolation invariants (§17.5) — the layer-1 cap-mint + layer-2 worker chain-verify are unchanged; only the layer-3 cloud-IAM mechanism swaps tag→policy.

## Crates touched (exact seams)

| Seam | File | Change |
|---|---|---|
| Broker mint trait | [`broker-server/src/sts.rs`](../../crates/agentkeys-broker-server/src/sts.rs) (`StsClient`, AwsStsClient L42-119) | add `VeStsClient` impl — `AssumeRoleWithOIDC` via VE-native signer; returns the same `AssumedCredentials` |
| Client-side mint | [`provisioner/src/aws_creds.rs`](../../crates/agentkeys-provisioner/src/aws_creds.rs) | VE variant of the client-side assume-role call (provisioner/daemon path) |
| S3 backend | [`core/src/s3_backend.rs`](../../crates/agentkeys-core/src/s3_backend.rs) (`new` L135, `from_client` L163) | endpoint-configurable client → TOS S3-compat endpoint |
| Worker S3 | [`worker-creds/src/aws_creds.rs`](../../crates/agentkeys-worker-creds/src/aws_creds.rs) (`build_s3_client` L97) | same TOS endpoint override (+ memory/config workers) |

Selection (AWS vs VE) is by env/profile — mirror the chain-profile pattern, NOT a hardcoded branch (No-hardcoded-values + No-silent-override policies). Proposed knobs: `AGENTKEYS_TOS_ENDPOINT` (presence → TOS path) and `AGENTKEYS_STS_PROVIDER=aws|ve`.

## Live probe results (2026-07-02, admin `agentterrier-admin`, cn-beijing)

De-risking probes run with the `ve` CLI v1.0.48 under the admin AK/SK:

- **Account / region / TRN:** AccountId `2127642244`, region `cn-beijing`, caller `trn:iam::2127642244:user/agentterrier-admin`. STS + IAM API **Version `2018-01-01`**. TRN (VE's ARN) format: `trn:iam::2127642244:role/<name>`.
- **TOS S3-compat endpoint — CONFIRMED live:** `https://tos-s3-cn-beijing.volces.com` returns S3-style `<Error><Code>AccessDenied</Code>…</Error>` XML to an unauthed GET (HTTP 403, ~0.67s). Genuinely S3-wire-compatible → `aws-sdk-s3` with this `endpoint_url` is the port. (Distinct from the native `tos-cn-beijing.volces.com`.) Path-style addressing: CONFIRM during the step-1 put/get.
- **IAM OIDC/role/policy surface — CONFIRMED present** via `ve iam` (Version 2018-01-01): `CreateOIDCProvider` · `AddThumbprintToOIDCProvider` · `AddClientIDToOIDCProvider` · `Get/List/Update/DeleteOIDCProvider` · `CreateRole` · `GetRole` · `AttachRolePolicy` · `CreatePolicy`. `ListOIDCProviders` returns empty (Total 0) → none registered yet. This is the full Phase-2 provisioning toolkit.
- **STS action gap:** the generic `ve` CLI `sts` service wraps ONLY `AssumeRole` + `GetCallerIdentity` — **`AssumeRoleWithOIDC` is NOT CLI-exposed**. It lives in VE's 身份认证 (identity-auth) OpenAPI ([docs/6973/1108654](https://www.volcengine.com/docs/6973/1108654), [6973/170368](https://www.volcengine.com/docs/6973/170368)). Consequence: the broker's `VeStsClient` MUST call it via raw HTTP + VE Signature V4 (the CLI cannot be shelled out to for the mint path) — which was the plan anyway.
- **TOS is not a `ve` CLI service** (only `storageebs` for block storage). Bucket provisioning uses the TOS OpenAPI/SDK or console, not `ve tos` — factor into `setup-cloud-ve.sh do_step_50+`.

## VE `AssumeRoleWithOIDC` contract — CONFIRMED live (2026-07-02, [`tests/ve_sign_live.rs`](../../crates/agentkeys-broker-server/tests/ve_sign_live.rs))

The signer ([`ve_sign.rs`](../../crates/agentkeys-broker-server/src/ve_sign.rs), a faithful port of `volc-sdk-golang` `base/sign.go`) is proven live: a signed `sts:GetCallerIdentity` returns **200 OK**, and a signed `AssumeRoleWithOIDC` with a *dummy* token reaches VE's token validation (**`InvalidOIDCToken`**). So signing + endpoint + action + params are all confirmed; only the real token exchange remains (Phase-2 provisioning).

- **Endpoint:** **`sts.volcengineapi.com`** (the DEDICATED STS host — NOT the universal `open.volcengineapi.com` gateway, which 404s `InvalidActionOrVersion` for this action). `Action=AssumeRoleWithOIDC`, `Version=2018-01-01`, `Service=sts`, region `cn-beijing`.
- **Params (POST form body):** `RoleTrn`, `RoleSessionName`, `OIDCProviderTrn`, `OIDCToken` (the broker-issued JWT), `DurationSeconds`, `Policy` (optional inline session policy — the isolation fork). Action+Version ride in the query.
- **Signing — SIGNED, not anonymous (KEY DIVERGENCE FROM AWS):** VE's gateway authenticates EVERY request via Signature V4, so the **broker must hold a VE AK/SK to sign the mint call** (`kDate=HMAC(secret,date)`, NO `AWS4` prefix). Contrast AWS, where `AssumeRoleWithWebIdentity` is anonymous and the broker holds zero creds for minting. Implication: provision a **least-privilege broker signing identity** scoped to `sts:AssumeRoleWithOIDC` only (feeds #372). The OIDC token still selects the actor's role; the signature only gets the request through the gateway.
- **Response:** `Result.Credentials { AccessKeyId, SecretAccessKey, SessionToken, ExpiredTime }` → map to `AssumedCredentials { …, expiration_unix }`. `ExpiredTime` is ISO-8601 (parse explicitly, not a unix epoch).
- **Custom OIDC provider:** the broker is its own issuer — VE IAM `CreateOIDCProvider` (confirmed present) must accept the broker's issuer URL + JWKS/thumbprint (Phase-2 cloud step).

**TOS S3-compat endpoint:** `tos-s3-cn-beijing.volces.com` (CONFIRMED live above; *distinct* from the native `tos-cn-beijing.volces.com`). **Addressing RESOLVED** (2026-07-02, [`tests/tos_live.rs`](../../crates/agentkeys-core/tests/tos_live.rs)): TOS requires **virtual-hosted-style** (`<bucket>.<host>`) and rejects path-style with `InvalidPathAccess: Forbidden path to access server` — a live PUT+GET roundtrip succeeded with `force_path_style=false` and failed with `=true`. So the S3 client must NOT force path-style (opposite of MinIO-style stores). Implemented in [`s3_endpoint.rs`](../../crates/agentkeys-core/src/s3_endpoint.rs).

## Implementation order (TOS-first — smallest verifiable step first)

1. **TOS endpoint seam** *(verifiable in isolation; no STS dependency)* — make the S3 clients in `s3_backend.rs` + worker `aws_creds.rs` endpoint-configurable via `AGENTKEYS_TOS_ENDPOINT`; AWS path unchanged when unset (no regression). Verify: `cargo build` + a live `ve`-provisioned TOS bucket put/get with static AK/SK.
2. ✅ **DONE — VE STS contract + signer** ([`ve_sign.rs`](../../crates/agentkeys-broker-server/src/ve_sign.rs)): `sign.go` ported + proven live (GetCallerIdentity 200; AssumeRoleWithOIDC reaches `InvalidOIDCToken`). Endpoint/action/version/params/signed-not-anonymous all confirmed above.
3. ✅ **DONE — VE STS client** ([`ve_sts.rs`](../../crates/agentkeys-broker-server/src/ve_sts.rs)): `VeStsClient: StsClient`, selected in `main.rs` by `AGENTKEYS_STS_PROVIDER=ve` (unknown values fail loud). Builds the per-actor session policy from the token's `agentkeys_actor_omni` (unverified decode by design — VE validates the signature; a forged claim fails the exchange, a replayed token only scopes to itself). Refuses unscoped mints (no buckets / no omni = hard error).
4. ✅ **DONE — Phase-2 cloud + live isolation proof.** `setup-cloud-ve.sh` steps 50-55: TOS buckets (3 private + public OIDC bucket), ES256 issuer keypair (never overwritten), **TOS-hosted issuer** (EKS-IRSA pattern — discovery + JWKS as public objects, uploaded via `curl --aws-sigv4` on the virtual-hosted URL because the aws CLI pins path-style), `CreateOIDCProvider` (**no Thumbprints** — VE rejects operator-computed SHA-1s and accepts none), data role + coarse `bots/*` policy. Live e2e ([`tests/ve_sts_live.rs`](../../crates/agentkeys-broker-server/tests/ve_sts_live.rs)): mint → put/get inside own prefix ✓ → cross-actor put AND get denied ✓. The SCOPED `agentterrier-broker-setup` identity was authorized to call `AssumeRoleWithOIDC` (the runtime posture, not admin).

   **Live-confirmed contract deltas** (vs the doc's earlier sketch): the session-policy condition key is **lowercase `tos:prefix`** (`tos:Prefix` → `InvalidParameter: does not support the condition key`); the credential expiry field is **`Expiration`** (RFC-3339, `+08:00` offset — not `ExpiredTime`); the minted `SessionToken` visibly embeds the session policy.
5. **arch.md link** — once shipped, link this spec from arch.md §17.x (cloud/storage) per the architecture-as-source-of-truth policy (it describes *built* state; this doc is design until then).

## Open risks

- ~~**Signer correctness**~~ — **RESOLVED**: proven live against `GetCallerIdentity` (200) + `AssumeRoleWithOIDC` (reaches `InvalidOIDCToken`) in `tests/ve_sign_live.rs`. No inferred signing shipped.
- ~~**Session-policy semantics on TOS**~~ — **RESOLVED live**: TOS honors the session policy (cross-actor put/get denied); the ListBucket prefix condition key is **lowercase `tos:prefix`**.
- ~~**`ExpiredTime` format**~~ — **RESOLVED live**: the field is **`Expiration`**, RFC-3339 with offset; parser accepts `Expiration`/`ExpiredTime`, string or numeric.
- **No silent AWS fallback** — implemented: `AGENTKEYS_STS_PROVIDER=ve` boot fails loud if the VE client can't construct; unknown provider values refuse to boot.

## Isolation-fork security analysis — PrincipalTags vs session Policy (and the sovereignty question)

**Where the trust actually sits, in both clouds:** the actor identity (`agentkeys_actor_omni`) is asserted by the **broker-signed JWT** in BOTH models — AWS reads it into session tags, VE reads it into the broker-built session policy. A compromised broker can lie about the omni in either cloud; the defense against that is NOT the cloud layer but **layer 2 (worker chain-verify)** and **client-side encryption** (arch.md §17.5). So the migration does not move the root of trust — it changes only the *mechanism* of layer 3 (cloud IAM).

| | AWS PrincipalTags | VE session Policy |
|---|---|---|
| Scope rule authored by | **Operator, once, statically** (bucket policy) | **Broker code, per mint** (inline policy) |
| Survives a broker mint-code bug | ✅ static bucket policy still gates by tag | ⚠️ an unscoped mint would carry full role scope |
| Broker cloud creds needed | ❌ none (anonymous exchange) | ⚠️ yes (signed gateway) — bigger broker blast radius |
| Scope visibility | tag only; policy lives cloud-side | ✅ the full policy is embedded in the SessionToken — auditable per-mint |
| Cross-cloud portability | ❌ AWS-proprietary tags-from-token claim | ✅ inline session policies exist on AWS/Alibaba/VE — *more* sovereign w.r.t. lock-in |
| Per-mint flexibility | fixed by static policy | ✅ can scope narrower per session (read-only relays, #295 §7a) |

**The honest delta:** on VE, layer 3 loses its *broker-independence* — the scope is asserted at mint time by our code instead of enforced by a static operator-owned policy. Layers 1–2 (chain-anchored) and the encryption layer (signer-anchored KEKs; cloud holds ciphertext only) are untouched and cloud-agnostic — which is exactly why the sovereignty posture survives: **the design never trusted cloud IAM as the primary gate.**

**Mitigation plan (restore layer-3 independence + shrink the new surface):**
1. **Landed:** `VeStsClient` hard-refuses unscoped mints (no buckets / no omni ⇒ error, unit-tested) — the mint-code bug class fails closed, not open.
2. **Landed:** the coarse role policy caps everything at `bots/*` on the three data buckets — even an unscoped session cannot leave the data prefix or touch other services.
3. **Static native TOS bucket policies as the backstop** (the AWS-parity "belt"): provision deny-by-default bucket policies via the native TOS API (the S3-compat `PutBucketPolicy` was refused) restricting access to the data role's assumed-role sessions; probe whether VE supports `PrincipalTag` conditions in TOS bucket policies + a `Tags` param on `AssumeRoleWithOIDC` — if yes, reconstruct the full static tag gate. → still open (native-API bucket policies), tracked under #372's follow-on parity work.
4. **Least-priv broker signing identity** — ✅ **LANDED (#372)**: `agentterrier-broker-setup` now carries [`scripts/operator/policies/ve-broker-setup.json`](../../scripts/operator/policies/ve-broker-setup.json) — ECS read + `sts:AssumeRole`/`AssumeRoleWithOIDC` + IAM read, **zero TOS actions** (the pre-#372 grant carried `tos:*` on `*`). `setup-cloud-ve.sh` step 11 converges a drifted live policy on re-run (`ve iam UpdatePolicy`).

## Storage-plane provisioning identities — scoped + mirrored (#372)

The **provisioning/admin identities** on both clouds are scoped by custom policies whose single source of truth is [`scripts/operator/policies/`](../../scripts/operator/policies/), applied idempotently by the entry points and drift-gated in CI by [`scripts/utils/check-storage-policy-parity.sh`](../../scripts/utils/check-storage-policy-parity.sh) ([`storage-policy-parity.yml`](../../.github/workflows/storage-policy-parity.yml)). Runtime isolation (per-actor STS) is untouched — this scopes the **stolen-operator-credential** blast radius: no object read (ciphertext/metadata leak) and no delete/overwrite (unrecoverable DoS) on the data buckets.

| | AWS | VE | Parity |
|---|---|---|---|
| Identity | `AgentKeyAdmin` group (was `AmazonS3FullAccess`) | `agentterrier-admin` user (was `TOSFullAccess`) | mirrored |
| Canonical policy | [`aws-provisioning-storage.json`](../../scripts/operator/policies/aws-provisioning-storage.json) | [`ve-admin-tos.json`](../../scripts/operator/policies/ve-admin-tos.json) | Sid-keyed, gate-enforced |
| `StorageBucketAdmin` | bucket lifecycle mgmt on `arn:aws:s3:::agentkeys-*` | bucket mgmt on `trn:tos:::agentterrier-*` | mirrored Sid |
| Object grants | mail bucket only (`MailObjectRW` — SES verify flow) | OIDC/JWKS + tos-probe buckets only (`OidcObjectRW`/`ProbeObjectRW`) | documented exceptions (hybrid-email / bucket-hosted issuer) |
| Data buckets (vault/memory/config) | **no object actions** | **no object actions** | mirrored; gate rejects regressions |
| Broker signing identity | none needed (anonymous `AssumeRoleWithWebIdentity`) | [`ve-broker-setup.json`](../../scripts/operator/policies/ve-broker-setup.json) — STS mint only, zero TOS | documented asymmetry |
| Applied by | `setup-cloud.sh` step 16 | `setup-cloud-ve.sh` steps 11 + 56 | both converge drift on re-run |

Accepted residual (both clouds): `ListBucket` on the data buckets (key metadata) — provisioning pre-checks and harness existence checks need it; object **contents** stay client-side-encrypted ciphertext regardless.
5. **Workers on VE keep layer 2 unchanged:** `AGENTKEYS_WORKER_REQUIRE_STS=1` + independent cap chain-verify — a compromised broker still can't drive the workers without passing chain checks.
6. **Stage-3-style negative tests on VE** (cross-actor denial in the harness, mirroring today's live e2e) so the isolation is a regression gate, not a one-time proof. **CI half LANDED:** the `ve-stack-smoke` job in `e2e-ci.yml` (repo var `AGENTKEYS_VE_SMOKE=1`; workflow + harness are operator-internal, not in the OSS mirror) runs the zero-cred public-surface smoke (`e2e/ve-stack-smoke.sh`: DoH DNS co-location, TOS-hosted OIDC discovery+JWKS, TOS S3-compat wire, broker/gate edges) every run, plus `ve_sign_live` + `tos_live` when the `VOLCENGINE_*`/`TOS_TEST_BUCKET` secrets are set. `ve_sts_live` (the full mint→isolation e2e) deliberately stays operator-run — its issuer PRIVATE key must not become a CI secret. The remaining harness-level half (worker put/get cross-actor negatives) lands with follow-up 3 (workers on VE).

## VE stack endpoints — the `agentterrier.cn` domain (#445)

**Convention (revised 2026-07-13, #439/#445):** the VE stack's canonical domain is **`agentterrier.cn`**, at parity with the AWS stack on `litentry.org`; `agentterrier.ai` belongs to the AWS stack (#443 re-federates the backend onto it). The VE stack borrowed `broker./gate.agentterrier.ai` until #445 **Phase A orphaned those records** (Route53 writes from VE tooling are now refused — `setup-cloud-ve.sh` step 55 guard). The `.cn` zone is hosted on **Volcano DNS** (not Route53) and its records **attach once 备案 clears** (#445 Phase B, which also lands the Volcano-DNS upsert tooling). Until then the stack has **no public FQDN** — probes are IP-direct (`VE_BROKER_PUBLIC_IP`), which was already the effective posture (China DPI SNI-resets cert-logged FQDNs).

| Endpoint | AWS twin | Status |
|---|---|---|
| **`broker.agentterrier.cn`** → the VE EIP | `broker.litentry.org` | ✅ **attached** (#445 Phase B — 备案 cleared 2026-07-13): Volcano-DNS A (`setup-cloud-ve.sh` step 55 → `cloud/dns-upsert-ve-cn.sh`) + nginx vhost → `127.0.0.1:8091` + TLS (host step 6). The former `broker.agentterrier.ai` was LIVE 2026-07-02 → orphaned by #445 Phase A. |
| `signer.agentterrier.cn` | `signer.litentry.org` | ✅ **deployed** — `agentkeys-mock-server --signer-only` (:8092 loopback, the same binary+mode AWS prod runs), Volcano-DNS A via step 55 + nginx vhost + TLS (host step 6); unit gated on the master secret (host step 5). **Per-stack, not shared:** the signer verifies the session JWT against the *broker's* session pubkey (it loads exactly one), so the AWS signer structurally cannot serve a VE broker — pointing a VE daemon at it yields an identity-only session (no memory/config). Its `DEV_KEY_SERVICE_MASTER_SECRET` is **generated on the VE host, sovereign per stack** (#464 — this supersedes the earlier mirror-from-AWS decision): the VE broker derives omnis under its own `client_id` (`agentterrier` vs AWS's `agentkeys`), so the same email is a *different* omni per stack — no shared SidecarRegistry entry, no collision, no secret to mirror. Escrow it off-host after first generation: `bash scripts/operator/secrets/escrow-signer-secret.sh ve`. **LIVE STATUS (2026-07-15, owner-accepted for alpha):** the deployed host still carries the pre-#464 **mirrored AWS secret** — generate-once never overwrites an armed value, so the #464 converge left it in place. This is CORRECT-but-not-clean: with `client_id=agentterrier` the same email derives a different omni, hence a different wallet, off the same secret — nothing collides. What remains is custody: that file is the root of every **AWS** master's wallet, sitting on a China host, so a compromise of this box exposes the AWS wallet set, not merely VE's. **Rotate before the first real VE user** — today no master is bound on VE so regenerating is free; after a bind it forks that user's wallet and needs an owner-gated `resetMaster`. Rotation = delete the `DEV_KEY_SERVICE_MASTER_SECRET=` line, re-run host step 3 (generates a VE-only secret), then escrow it. |
| `cred.` / `memory.` / `config.agentterrier.cn` | same on litentry.org | ✅ attached (Phase B) — step 55 UPSERTs them (`VE_{CRED,MEMORY,CONFIG}_HOST` → the broker IP); host vhosts in step 7 |
| `audit.agentterrier.cn` | `audit.litentry.org` | ✅ attached (Phase B) — `VE_AUDIT_HOST`; audit worker deployed in step 7 |
| `email.agentterrier.cn` | `email.litentry.org` | ✅ A record + worker vhost on VE (step 7) — the email WORKER runs here; mail **transport** stays AWS SES (hybrid decision) |
| `channel.agentterrier.cn` | `channel.litentry.org` | ✅ attached (#433) — the #406 pub/sub feed worker, own TOS bucket (`VE_CHANNEL_BUCKET`); host vhost in step 7 (120s long-poll timeout) |
| `weixin.agentterrier.cn` | `weixin.litentry.org` | ✅ attached (#433) — the #407 WeChat gateway PEP (PUBLIC; the 公众号 callback URL, ICP-filed via #397); serves once the operator populates `/etc/agentkeys/weixin-secrets.env` |
| `www.` + apex `agentterrier.cn` | — (litentry.org is deliberately www-less) | ✅ the China website (#397): `apps/website` SSR unit + nginx vhost on the SAME VE host, default-中文 (`/`→`/zh`) |
| ~~`mcp.agentterrier.cn`~~ | `mcp.litentry.org` | deferred with #152 |
| OIDC issuer | `broker.litentry.org` (self-hosted) | **no DNS needed** — TOS-hosted bucket issuer (above), deliberately DNS-decoupled so the #445 orphan/attach does not touch federation. Optional later: move the issuer to `broker.agentterrier.cn` for full AWS parity (needs provider re-registration; the broker binary already serves `/.well-known/*`). |

## Stack tooling (issue [#373](https://github.com/litentry/agentKeys/issues/373) — LANDED)

Stack selection gained the cloud axis ahead of the follow-ups below, with the VE stack rendered **degraded** until they land (the #283 chain-degraded pattern):

- **Fleet console:** the `ve` stack is inventoried from `operator-workstation.ve.env` (board line = broker `healthz` + EIP, probed IP-direct; `c` picker entry `ve (heima · https://broker.agentterrier.cn)` — the #445 target name, unresolvable until Phase B), and the `d` menu gained a VE deploy job — `ssh-broker.sh ve` then `setup-broker-host-ve.sh` (no outer sudo; the script escalates itself).
- **SSH:** `bash scripts/utils/ssh-broker.sh ve` (suggested alias `ssh-agentterrier`) — always `.pem` + `broker-manager`; VE has no EC2 Instance Connect.
- **Daemon/web:** the fleet injects the env-file-derived stack inventory as `AGENTKEYS_STACKS_JSON` → the daemon serves `GET /v1/stack/list` (per-stack broker `healthz` probe + which stack it runs) and reports `daemonBroker` on the chain endpoints; the web chain page renders the selector (active / degraded per stack).
- **Browser isolation:** master-identity pointers are namespaced per **(chain, broker)** (`<key>:<chain>@<broker-host>`, one-shot migration from the #313 chain-only keys) — Heima-AWS and Heima-VE sessions/onboarding never cross. Negative tests: `apps/parent-control/lib/__tests__/identityStore.test.ts` (CI: e2e-ci rust-checks `npm test`).

## Remaining follow-ups (deliberately out of this port's scope)

1. **Broker mint-relay endpoint for clients** — on AWS, clients exchange the broker's JWT with STS *themselves* (anonymous). On VE the exchange is broker-side, so client flows (provisioner `cmd_provision`, daemon) need a broker endpoint that returns the minted creds (the `StsClient` seam is ready; the HTTP surface + backend-client wiring lands with the worker deploy).
2. **`aud` parameterization** — `build_oidc_jwt_claims` (handlers/oidc.rs) hardcodes `aud="sts.amazonaws.com"`; the VE provider registers aud `agentkeys-ve-sts`. Make the aud config-driven when the broker starts minting VE-bound JWTs.
3. **Workers on VE** — deploy *wiring* ✅ landed via the canonical host entry (`setup-broker-host.sh --cloud ve`): step 5 boots the broker (chain env from the `heima.json` profile SoT + the VE cred-plane env: `AGENTKEYS_STS_PROVIDER=ve`, OIDC provider TRN, TOS buckets, TOS-hosted issuer — **plus the W1 onboarding `email_link` block**: the broker builds with `--features auth-email-link` (step 3; without it every `/v1/auth/email/*` route 404s — the live "parent-control sends no verification email" bug) and step 5 arms `BROKER_AUTH_METHODS=wallet_sig,email_link` + `BROKER_EMAIL_SENDER=ses` + `BROKER_EMAIL_FROM_ADDRESS` + `BROKER_EMAIL_LANDING_URL_BASE=https://$VE_BROKER_HOST` (the landing page must live on the broker vhost — the TOS-hosted OIDC issuer default serves no pages) when the hybrid SES creds + from-address exist) and step 7 builds/installs/wires all 5 co-located workers (cred/memory/config with `AGENTKEYS_TOS_ENDPOINT` + per-data-class bucket + KEK-preserved, audit, email→AWS SES hybrid), fronted by nginx, with worker A-records added to the cloud entry (`setup-cloud.sh --cloud ve` step 55). Per the #376/#381 structure, the entry steps are THIN (data + orchestration only); every mechanic is a shared `scripts/operator/lib/host-common.sh` converge/render function — `host_apply_unit`, `host_broker_unit_content`, `host_simple_unit_content`, `host_worker_unit_content`, `host_storage_worker_env_content`, `host_chain_env_lines`, `host_ensure_kek`, `host_deploy_worker`, `host_worker_port`, `host_service_user` — which are exactly the seams the AWS host entry adopts in Stage 3b. **Enable is secret-gated (nothing crash-loops):** the broker starts once the operator places `/etc/agentkeys/broker-ve-sts.env` (the #372 VE signing identity) + the ES256 OIDC key at `BROKER_OIDC_KEYPAIR_PATH`; the storage/audit workers follow the broker; the email worker AND the broker's `email_link` magic-link sender both gate on the same AWS SES creds file (`/etc/agentkeys/worker-email-aws.env` + `BROKER_EMAIL_FROM_ADDRESS` in `operator-workstation.ve.env` — absent ⇒ wallet_sig-only with a loud remediation warn; smoke gate: `e2e/ve-stack-smoke.sh` step 8). **The FROM address must ALSO be a registered SES identity** — a third, easily-missed leg (2026-07-17): with creds armed but no identity, the broker boots `email_link` yet `/readyz` reports `tier2/ses` unready (`sender verify failed … NotFoundException`) forever and parent-control silently sends nothing. `verify_sender_ready` does an exact per-address `GetEmailIdentity` and **deliberately does not fall back to the domain identity** (an explicit per-address identity keeps the verified sender visible in `list-email-identities`). Fix — one command, **instant, no link to click**, because `agentterrier.cn` is an already-verified SES *domain* so a per-address identity inherits its verification (`VerifiedForSendingStatus=true`; the address's own `VerificationStatus` stays `PENDING` forever and is correctly ignored by the probe): `AWS_PROFILE=agentkeys-admin aws sesv2 create-email-identity --region "$VE_SES_REGION" --email-identity "$BROKER_EMAIL_FROM_ADDRESS"`. **Do NOT use the operator helper `scripts/operator/cloud/ses-verify-sender.sh` on this stack** — it verifies by fishing the confirmation link out of the SES *inbound receipt rule* → S3, which exists only for the AWS `$MAIL_DOMAIN`; `.cn` has no inbound mail (STAYS-AWS), so it would poll until timeout. **Still open:** the client mint-relay endpoint (#1 above) + `aud` parameterization (#2) so provisioner/daemon flows work, and the stage-3-style negative cross-isolation tests per the §17.5 invariants.
4. ~~**Least-priv broker signing identity** (#372)~~ — ✅ landed: `agentterrier-broker-setup` is scoped to STS mint + host/IAM read with zero TOS actions ([`scripts/operator/policies/ve-broker-setup.json`](../../scripts/operator/policies/ve-broker-setup.json); see "Storage-plane provisioning identities" above).
5. **WeChat gateway + the #424 pairing-metadata surfaces** ([#433](https://github.com/litentry/agentKeys/issues/433)) — **deploy wiring ✅ landed** (#433): host step 7 builds + wires the `channel` worker (own TOS bucket `VE_CHANNEL_BUCKET` + preserved KEK, chain-verify env, 25s NRT long-poll) and the `channel-weixin` gateway PEP (unit + `weixin.agentterrier.cn` vhost with the 120s long-poll read timeout; bot secrets template at `/etc/agentkeys/weixin-secrets.env` — operator-populated, NEVER overwritten; `WEIXIN_OPERATOR_OMNI` stamped from `operator-workstation.ve.env` fill-if-placeholder with the loud UNARMED warn). Audit anchoring targets the **VE-local** audit worker (loopback :9092 — per-stack isolation, never cross-cloud). The `binding-manifest` / `gateway-contact-registry` config docs ride the VE config worker unchanged (cloud-agnostic cap → STS → worker path). **Still operator-side:** populate the bot transport secrets (ilink QR ceremony or 公众号 oa credentials — callback `https://weixin.agentterrier.cn/wechat/callback`, now ICP-filed) and set `WEIXIN_OPERATOR_OMNI`; **still open:** the stage-3-style #424 master-only doc negatives (rides the credentialed VE harness half, follow-ups 1–2).
6. **Eliminate the broker's static AK/SK (north star)** — the broker holds a long-lived `VOLCENGINE_ACCESS_KEY`/`_SECRET_KEY` only to pass VE's SigV4 gateway for the mint (the KEY DIVERGENCE above). Today the operator provisions it host-only (0600 `/etc/agentkeys/broker-ve-sts.env` — see the operator broker-setup runbook, "VE broker signing secret"); the exposure surface is one host, revocable independently, rotatable via the 2-key window. **Better:** if the VE ECS instance can carry an instance role scoped to `sts:AssumeRoleWithOIDC`, the broker signs with rotating IMDS creds (SigV4 + `X-Security-Token`) and holds no long-lived secret at all — investigate VE ECS instance-role/IMDS support + thread the session token through [`ve_sign.rs`](../../crates/agentkeys-broker-server/src/ve_sign.rs).
7. **Sponsored register/accept runtime (#230/#278) — deploy wiring ✅ landed; secret ceremony operator-side.** Root cause of the 2026-07-16 stranding: the VE broker had the full 0.5 ERC-4337 addresses but **no `BROKER_SPONSOR_SIGNER_KEY` and no bundler**, so `/v1/register/build` answered `503` (`load_accept_config` fails before parsing) — master onboarding could never complete on this stack, and the parent-control "reset + re-onboard" remedy unbound a working master on chain (chain-level — it broke the AWS stack too) with no way to re-bind. Host step 3 now builds `agentkeys-bundler`, step 4 installs it + creates the `/etc/agentkeys/broker-sponsor.env` skeleton (0600, never overwritten), and step 5 renders the loopback bundler unit (`127.0.0.1:${VE_BUNDLER_PORT:-9098}`, enable gated on BOTH keys being armed) + appends `AGENTKEYS_BUNDLER_URL` and the sponsor EnvironmentFile to the broker unit. **Operator ceremony (once) — ONE command:** mint + fund (~2 HEI) a **VE-own** submitter EOA (`cast wallet new`; never reuse the AWS submitter — shared EOA = handleOps nonce races), then from the laptop `printf '%s' "$PRIVKEY" | bash scripts/operator/secrets/arm-bundler-signer.sh --stack ve --address 0x<addr>`. That idempotent operator helper (`scripts/operator/secrets/arm-bundler-signer.sh`) **auto-copies** `BROKER_SPONSOR_SIGNER_KEY` from the AWS Heima host (chain-level VerifyingPaymaster co-sign — must match, and you never handle it), writes both keys to the host's 0600 `broker-sponsor.env`, **records the public submitter address** in `operator-workstation.ve.env` as `AGENTKEYS_BUNDLER_SIGNER_ADDRESS_HEIMA` so the fleet dashboard shows a `bundler` WALLETS row (red below the chain gas floor), enables the bundler, and reports the balance vs. floor. The private key rides stdin → `sudo tee` only — never argv, never the laptop disk. (Manual fallback: hand-edit `broker-sponsor.env` + `setup-broker-host.sh --cloud ve --only-step 5`; the arm helper is the maintainable path.) **Funding is monitored, not automated** — the top-up transfer stays an operator action (the fleet flags the row red when it drops below floor). Guards that make the failure non-stranding regardless, all reading ONE probe — `GET /v1/master/register/preflight` (can the broker build a sponsored register? garbage-body 503-vs-not check; only a definite 503 blocks): **(a)** the daemon refuses `POST /v1/master/reset` when it probes 503 (override `AGENTKEYS_RESET_SKIP_REGISTER_PREFLIGHT=1`) so a reset can never unbind into an un-re-registerable state; **(b)** onboarding calls it BEFORE `navigator.credentials.create()`, so a broker that would 503 the build never causes a passkey to be minted — otherwise every failed attempt orphaned a fresh Secure-Enclave credential (the register can only be BUILT after the passkey, since the build needs its pubkey) and the promised 2nd Touch ID never fired (the 2026-07-17 observation); the ceremony shows a `broker not ready · retry` state with the broker's own reason and a Retry that re-probes; **(c)** the bound-but-no-pointer blocked-state offers passkey **re-login** (discoverable picker, pointer backfill) before any reset.

## Rides the same VE identity: veFaaS sandbox lifecycle (#377 — LANDED broker-side)

The broker's VE credential plane gained a SECOND consumer beyond `ve_sts`:
[`ve_faas.rs`](../../crates/agentkeys-broker-server/src/ve_faas.rs) drives the
delegate hermes-sandbox lifecycle (`CreateSandbox` / `DescribeSandbox` /
`ListSandboxes` / `SetSandboxTimeout` / `KillSandbox`, `service=vefaas`) on the
SAME `ve_sign` signer and the SAME `VOLCENGINE_ACCESS_KEY`/`_SECRET_KEY`
identity — spawn-on-pair/resolve, one instance per delegate (Metadata-labeled,
idempotent), kill-on-unpair, `SandboxSpawn`/`SandboxTeardown` audit envelopes
(arch.md §15.3a bytes 53/54). Cloud grant: `setup-cloud-ve.sh` step 15
([`policies/ve-broker-vefaas.json`](../../scripts/operator/policies/ve-broker-vefaas.json)
— the five instance actions only). Enabled by `SANDBOX_FUNCTION_ID` +
`SANDBOX_GATEWAY_URL` in the broker unit env; it therefore ACTIVATES together
with follow-up 1's cred wiring (the unit carrying the VE AK/SK), needing no
extra step of its own. Live conformance:
[`tests/ve_faas_live.rs`](../../crates/agentkeys-broker-server/tests/ve_faas_live.rs).
