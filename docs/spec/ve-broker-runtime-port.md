**Status:** IMPLEMENTED + PROVEN LIVE (2026-07-02, PR [#371](https://github.com/litentry/agentKeys/pull/371)). The full mint→storage chain ran against real VE: broker-signed ES256 JWT (TOS-hosted issuer) → `VeStsClient` `AssumeRoleWithOIDC` (VE Signature V4, per-actor session policy) → minted creds did a TOS put/get inside `bots/<actor>/…` and were **AccessDenied** outside it ([`tests/ve_sts_live.rs`](../../crates/agentkeys-broker-server/tests/ve_sts_live.rs)). Cloud-side provisioning: `setup-cloud-ve.sh` steps 50-55 (idempotent, converged). Remaining follow-ups at the bottom.
**Scope:** the AWS→VE seam for the credential-minting + object-storage path only. Chain, signer, OIDC-issuer, systemd/nginx are cloud-agnostic and already port. SES email **stays on AWS** (hybrid — VE has no inbound email). Companion: cloud-side provisioning is `scripts/setup-cloud-ve.sh do_step_50+` (TOS buckets + VE IAM roles + OIDC provider).
**Canonical entry (#376):** operators now reach this stack via `scripts/setup-cloud.sh --cloud ve` / `scripts/setup-broker-host.sh --cloud ve` (the `--cloud` dispatcher on the AWS entries). The cloud-agnostic scaffolding lives in `scripts/lib/{steps,cloud-common,host-common}.sh` and the VE cloud primitives (the five driver seams) in `scripts/lib/cloud-ve.sh`; the `-ve` scripts remain directly callable for surgical re-runs.

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
3. **Static native TOS bucket policies as the backstop** (the AWS-parity "belt"): provision deny-by-default bucket policies via the native TOS API (the S3-compat `PutBucketPolicy` was refused) restricting access to the data role's assumed-role sessions; probe whether VE supports `PrincipalTag` conditions in TOS bucket policies + a `Tags` param on `AssumeRoleWithOIDC` — if yes, reconstruct the full static tag gate. → tracked in #372's parity work.
4. **Least-priv broker signing identity** (#372): an `sts:AssumeRoleWithOIDC`-only VE user — the broker's cloud creds can *only* mint scoped-down sessions of the data role, never touch TOS directly.
5. **Workers on VE keep layer 2 unchanged:** `AGENTKEYS_WORKER_REQUIRE_STS=1` + independent cap chain-verify — a compromised broker still can't drive the workers without passing chain checks.
6. **Stage-3-style negative tests on VE** (cross-actor denial in the harness, mirroring today's live e2e) so the isolation is a regression gate, not a one-time proof.

## VE stack endpoints — the `agentterrier.ai` domain

**Convention:** the VE stack lives on `agentterrier.ai`, at parity with the AWS stack on `litentry.org`. The zone is registered + hosted on AWS Route53 (`Z10232242NM9I9WFJTLLC`; the ONE cross-cloud dependency — `setup-cloud-ve.sh` step 55 writes it under the AWS operator profile).

| Endpoint | AWS twin | Status |
|---|---|---|
| **`broker.agentterrier.ai`** → 115.190.149.132 | `broker.litentry.org` | ✅ **LIVE** (2026-07-02): Route53 A (step 55) + nginx vhost → `127.0.0.1:8091` + Let's Encrypt TLS (host step 6). Serves 502 until the broker service is enabled — deliberate. |
| `signer.agentterrier.ai` | `signer.litentry.org` | later — when the signer service deploys on the VE host |
| `cred.` / `memory.` / `config.agentterrier.ai` | same on litentry.org | later — with the workers-on-VE deploy (mirror `dns-upsert-workers.sh` as a step-55 extension) |
| `audit.agentterrier.ai` | `audit.litentry.org` | later — with the audit worker, if it runs on VE |
| ~~`email.agentterrier.ai`~~ | `email.litentry.org` | **never** — email stays AWS SES (hybrid decision) |
| ~~`mcp.agentterrier.ai`~~ | `mcp.litentry.org` | deferred with #152 |
| OIDC issuer | `broker.litentry.org` (self-hosted) | **no DNS needed** — TOS-hosted bucket issuer (above). Optional later: move the issuer to `broker.agentterrier.ai` for full AWS parity (needs provider re-registration; the broker binary already serves `/.well-known/*`). |

## Remaining follow-ups (deliberately out of this port's scope)

1. **Broker mint-relay endpoint for clients** — on AWS, clients exchange the broker's JWT with STS *themselves* (anonymous). On VE the exchange is broker-side, so client flows (provisioner `cmd_provision`, daemon) need a broker endpoint that returns the minted creds (the `StsClient` seam is ready; the HTTP surface + backend-client wiring lands with the worker deploy).
2. **`aud` parameterization** — `build_oidc_jwt_claims` (handlers/oidc.rs) hardcodes `aud="sts.amazonaws.com"`; the VE provider registers aud `agentkeys-ve-sts`. Make the aud config-driven when the broker starts minting VE-bound JWTs.
3. **Workers on VE** — deploy cred/memory/config workers with `AGENTKEYS_TOS_ENDPOINT` + the relay; stage-3-style negative tests per the §17.5 invariants.
4. **Least-priv broker signing identity** (#372) — a dedicated VE user scoped to `sts:AssumeRoleWithOIDC` only (today the scoped `agentterrier-broker-setup` works and admin is never needed at runtime).
