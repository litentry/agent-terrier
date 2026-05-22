# Plan — Issue #74 Step 1c: Device-Key Authentication for `/dev/*`

## Status — v1c interim; v0.2 target = HDKD per-agent omni + WebAuthn-uniform binding

This plan documents the **v1c interim** wire shapes for device-key
binding: bespoke per-identity PoP fields (`pop_sig` over canonical
inputs in `email_request` / `oauth2_start`; SIWE-payload
`Device Pubkey` commit + dual signature for `evm`). These ship in
PR #75's successor work and unblock per-request device-signature
auth on `/dev/*` immediately.

The **v0.2 target** is a structural shift, not just a wire-shape
collapse:

1. **HDKD per-agent omni.** Each agent is a first-class actor with
   its own omni derived from the master via `HDKD(O_master,
   "//<label>")`, its own wallet (`HKDF(K3, O_agent)`), its own
   AWS PrincipalTag, and its own audit slot. The v1c "shared omni
   with multiple device pubkeys" model becomes a degenerate v1.0
   tree (no children).
2. **Agent bootstrap = link-code only.** No identity ceremony for
   agents, no shared bearer, no agent-side recovery. Single test
   surface, single threat model.
3. **Master binding via WebAuthn (uniform).** Collapses the four
   bespoke per-identity PoP shapes into one ceremony — D_pub
   committed atomically inside the WebAuthn challenge. Closes the
   Q7 email-account-compromise → device-takeover gap by requiring
   hardware-attested user presence at re-bind time.

[`docs/arch.md`](../../arch.md) §4 (HDKD actor
tree), §4a (mental model), and §5a (per-actor binding ceremonies)
are the **single source of truth** for the v0.2 target. The
per-identity-type sections in this plan are the v1c wire-shape
reference; they will be marked superseded once the v0.2 binding
endpoints land.

YubiKey-on-Linux as a master tier (roaming-authenticator binding,
lets a Linux box act as a master without a built-in platform
authenticator) is deferred — see
[issue #79](https://github.com/litentry/agentKeys/issues/79).
The agent-role/usage operator reference lives at
[`docs/wiki/agent-role-and-usage-hdkd-per-agent-omni.md`](../../../docs/wiki/agent-role-and-usage-hdkd-per-agent-omni.md).

## Goal

Replace the broker-issued bearer JWT as the sole authenticator on
`POST /dev/derive-address` and `POST /dev/sign-message` with a
**device-key signature scheme**. The broker stops being the single
point of compromise for signer authorization. Identity-type-uniform —
the same wire shape works for `evm`, `email`, `oauth2_google`, and
`passkey` omnis. UX-uniform — no per-request user interaction (no
MetaMask popup, no hardware-wallet prompt) regardless of identity
type.

This plan is the third sub-step under issue #74. Step 1 (already
shipped in PR #75) defined the wire contract and the HKDF backend.
Step 1b (immediate follow-up) deploys `signer.litentry.org` as an
independent listener with bearer-JWT auth — that ships first because
it is purely operational. **Step 1c (this plan) replaces bearer-JWT
auth with the device-key scheme** before any production deployment.
Step 2 swaps HKDF for a TEE worker behind the same wire shape.

## Non-goals

- **The TEE swap.** That is issue #74 step 2; the device-key auth
  pattern is independent of which backend implements `/dev/*`.
- **Multi-device authorization policy.** Step 1c ships single-device
  registration per session. Multi-device (e.g. operator with laptop +
  phone authorized for the same omni) is a v0.2 follow-up.
- **Device-key rotation cadence.** Step 1c ships TTL-bound device keys
  whose lifetime equals the session JWT. Operator-initiated rotation,
  cron-based rotation, or re-keying without re-authentication are v0.2.
- **Hardware-backed device keys.** Step 1c stores the device private
  key in the OS keychain (existing `agentkeys-core::session_store`
  surface). Secure-Enclave / TPM / YubiKey device keys are a v0.2
  enhancement.

## Why this comes after step 1b

Step 1b deploys the signer at a public hostname with bearer JWT
verification. That is a strict improvement over today's tunnel + no
auth, but the broker is still the SPOF (broker compromise → forged
session JWTs → impersonate any omni). Step 1c removes that SPOF.

The order matters because:

- Step 1b is mechanical (DNS + nginx + systemd + a JWT-verify
  middleware) and unblocks the public-listener UX immediately.
- Step 1c changes the wire contract (`signer-protocol.md` v0.2). All
  callers — daemon, CLI, future TEE worker — must implement the new
  signing scheme. That is a coordinated change, not a hot-fix.

Shipping 1b first means production is closer to the target shape
sooner. 1c then upgrades the auth scheme without re-doing the
listener / DNS / nginx work.

## Invariants the design preserves

- Broker holds zero AWS principals at runtime (Stage 7 trust boundary).
- Signer holds the master secret (or, post-step-2, the sealed
  enclave seed) and derives wallets from `omni_account`.
- AWS PrincipalTag-enforced S3 isolation — every minted OIDC JWT
  carries an EVM address that maps 1:1 to a single user.
- Daemon holds **no omni-derived key material** — only an ephemeral
  device key, which has no on-chain value and no derivation
  relationship to any wallet.

## Invariants the design adds

- **Signer never trusts the broker as a transitive authenticator.**
  Verifying a per-request signature requires a user-controlled key
  whose pubkey was bound to the omni at init time. Compromising the
  broker post-init does not enable forging new sign requests.
- **One-shot identity-ceremony cost; zero per-request user interaction.**
  Operator authenticates once at `agentkeys init`; every subsequent
  `/dev/sign-message` call is automatic.
- **Identity-type uniformity.** `evm`, `email`, `oauth2_google`, and
  `passkey` omnis share the same per-request signature shape. Only
  the init-time binding ceremony differs.

## Architecture

```
                          INIT (one-shot per device)
                          ──────────────────────────

  Daemon                                                      Broker                            Signer
  ──────                                                      ──────                            ──────
   1. Generate device keypair (D_priv, D_pub)
      locally; persist D_priv in OS keychain.
   2. Run identity-ceremony:
        evm:    user signs SIWE-shaped binding
                payload {device_pubkey: D_pub,
                         omni: O, exp: T}
                with their EVM key.
        email:  click magic link.
        oauth2: complete OAuth2 callback.
        passkey: WebAuthn assertion that
                attests D_pub.
   3. Submit binding to broker  ───────────────────▶  Verify identity ceremony.
                                                       Bind (omni O, device_pubkey D_pub, exp T).
                                                       Mint session JWT with claim
                                                         agentkeys_device_pubkey = D_pub.
   4. Receive session JWT  ◀──────────────────────────  Return JWT.
      Persist JWT + D_priv in OS keychain.

                          PER REQUEST (automatic, no user interaction)
                          ────────────────────────────────────────────

  Daemon                                                                                       Signer
  ──────                                                                                       ──────
   1. Compute body bytes:
        canonical_json({
          omni_account: O,
          message_hex:  M,
          nonce:        N,        ← 16-byte CSPRNG, single-use per session
          timestamp:    T_now,    ← unix seconds, ±60s window
        })
   2. Sign body bytes with D_priv (EIP-191 envelope or raw secp256k1 — see §"Per-request signature shape").
   3. POST /dev/sign-message
        Authorization: Bearer <session_jwt>
        X-Agentkeys-Device-Sig: <hex>
        body: canonical_json(...)                                ─▶  Verify session JWT signature against
                                                                      broker session pubkey.
                                                                    Extract agentkeys_device_pubkey claim.
                                                                    Verify X-Agentkeys-Device-Sig against
                                                                      claim's pubkey on the body bytes.
                                                                    Verify body.omni_account == JWT.omni_account.
                                                                    Verify nonce not seen (per-session LRU).
                                                                    Verify timestamp within ±60s.
                                                                    → Sign and return.
```

## Per-identity-type init binding (v1c-interim wire shapes)

> **v0.2 supersedes:** the four per-identity sections below
> describe the **v1c-interim** bespoke PoP shapes. The v0.2 target
> collapses these into a uniform WebAuthn binding ceremony for
> masters plus a uniform link-code binding ceremony for agents —
> see [`architecture.md` §5a.1](../../arch.md). The
> identity-source half (email click / OAuth callback / EVM SIWE
> identity verification) survives unchanged in v0.2; only the
> device-pubkey-commit half collapses.

The init-ceremony differs per identity type but always produces the
same broker-side binding: `(omni_account, device_pubkey, expiry,
identity_proof)`.

### `evm` (wallet-sig)

The user signs a SIWE-shaped binding payload with their EVM key. The
device pubkey is part of the signed payload itself, so the EVM
signature simultaneously proves identity ownership AND commits to
the device pubkey.

```
agentkeys.example wants you to authorize a device key for omni X:
0x<wallet_address>

Authorize device key for AgentKeys signer.

Device Pubkey: 0x<device_pubkey_compressed_hex>
Omni Account: <omni_hex>
URI: https://broker.example
Version: 1
Chain ID: <chain_id>
Nonce: <random_hex>
Issued At: <iso8601>
Expiration Time: <iso8601>
```

Daemon:
1. Computes `pop_sig = sign(D_priv, canonical(siwe_payload))` — proof
   that the daemon actually holds `D_priv` for the `D_pub` written
   into the SIWE payload.
2. Submits `{siwe_payload, evm_sig, device_pop_sig: pop_sig}` to the
   broker.

Broker:
1. Verifies EIP-191 ecrecover on `evm_sig` yields the wallet address
   claimed by the payload.
2. Verifies `SHA256("agentkeys" || "evm" || lower(wallet_address)) == omni`.
3. Verifies `pop_sig` against `D_pub` over the canonicalized SIWE
   payload — proves device-key possession (closes the same Q7 gap as
   the email flow).
4. Stores `(omni, device_pubkey, exp)` and mints session JWT with
   `agentkeys_device_pubkey` claim.

This is `EvmSiweSigned` extended with both (a) the device-pubkey
commit inside the SIWE payload and (b) the device-pubkey
proof-of-possession. The two signatures together prove "this user
owns the EVM identity AND this daemon controls the device key" —
neither alone is sufficient.

### `email`

The magic-link click delivers the `device_pubkey` through the link
itself, AND the request is signed with `device_priv` so the broker
verifies the daemon actually possesses the matching private key
(**proof of possession** — addresses the Q7 concern that "what if
attacker substitutes their own pubkey" without proof of possession).

1. Daemon computes `pop_sig = sign(D_priv, canonical(email || D_pub
   || nonce))` where `nonce` is fresh CSPRNG.
2. Daemon calls `POST /v1/auth/email/request` with body
   `{email, device_pubkey: D_pub, pop_nonce: nonce, pop_sig}`.
3. Broker verifies `pop_sig` against `D_pub` over the canonicalized
   payload; rejects on mismatch with HTTP 400 `bad_pop`. This proves
   the requester actually holds `D_priv` — an attacker who only
   observed `D_pub` (e.g. via traffic inspection) cannot substitute
   it.
4. Broker stores `(request_id, email, D_pub, expiry)` and emails the
   operator a link of shape
   `https://broker.example/v1/auth/email/landing/<request_id>?device=<D_pub>`.
5. Operator clicks; broker confirms `?device=<D_pub>` matches the
   stored value (defends against link-forwarding to swap the device
   pubkey).
6. Broker mints session JWT with `agentkeys_device_pubkey = D_pub`.

The defense composes two layers:
- **PoP at request time** (step 3) prevents an attacker from
  initiating an init flow with a pubkey they don't control.
- **`?device=<D_pub>` at click time** (step 5) prevents the
  magic-link URL itself from being repurposed to a different
  device pubkey if the email is forwarded.

An attacker would need to compromise BOTH the network path
(to substitute the pubkey at request time, then forge `pop_sig`)
AND the user's email inbox (to click the legitimate link) — a
much higher bar than today's bearer-only model.

### `oauth2_google`

The OAuth2 `state` parameter carries a hash of the device pubkey
(binds D_pub through Google's redirect), AND the start request
itself carries a `pop_sig` so the broker verifies device-key
possession before issuing any state value (closes the same Q7 gap
as the email flow).

1. Daemon generates `(D_priv, D_pub)` and a fresh `state_nonce`.
2. Daemon computes:
   - `expected_state = SHA256(D_pub || state_nonce)`
   - `pop_sig = sign(D_priv, canonical("oauth2_google" || D_pub || state_nonce))`
3. Daemon calls `POST /v1/auth/oauth2/start` with body
   `{provider: "google", device_pubkey: D_pub, state_nonce, pop_sig}`.
4. Broker verifies `pop_sig` against `D_pub`; rejects with HTTP 400
   `bad_pop` on mismatch.
5. Broker stores `(request_id, D_pub, state_nonce, expected_state)`;
   returns the Google authorization URL with `state=expected_state`.
6. Operator completes Google sign-in.
7. Broker's OAuth2 callback verifies `state == expected_state`
   (proves the same `D_pub` flowed through the OAuth2 round-trip),
   then mints session JWT with `agentkeys_device_pubkey = D_pub`.

Defense composes three layers: PoP at start time (prevents D_pub
substitution by an attacker who only observed it), `state` binding
(prevents callback hijack to a different D_pub), and Google's own
identity verification.

### `passkey`

WebAuthn supports key-attestation in the assertion. The device pubkey
is attested as part of the WebAuthn ceremony. Implementation defers to
step 1c.2 (passkey is not v0.2 broker scope).

## Per-request signature shape

The signed payload is `canonical_json` of the request body:

```json
{
  "omni_account": "<64 hex>",
  "message_hex":  "<even-length hex>",
  "nonce":        "<32 hex>",
  "timestamp":    1746455331
}
```

`canonical_json` = JSON serialized with:
- Keys in lexicographic order.
- No whitespace.
- UTF-8.

The signature is **raw secp256k1 ECDSA** over `SHA256(canonical_json)`
— NOT EIP-191. EIP-191's "Ethereum Signed Message" prefix is for
human-signed Ethereum messages; the device key is a non-human signer
and the EIP-191 envelope adds nothing here. Using raw ECDSA matches
how Heima's `BackendSigned` variant signs payloads.

Signature encoding: `r(32) || s(32)` as 128-char lowercase hex (no
`v` byte; signer doesn't need to recover the address — it has the
pubkey from the JWT claim).

## Signer verification path

Pseudocode:

```rust
fn verify_request(req: SignRequest) -> Result<()> {
    // 1. JWT signature + claim extraction.
    let jwt = extract_bearer(req.headers)?;
    let claims = verify_jwt(&BROKER_SESSION_PUBKEY, jwt)?;
    let device_pubkey = claims.get("agentkeys_device_pubkey")?;

    // 2. Per-request signature.
    let body_bytes = canonical_json(&req.body);
    let device_sig = extract_header(req.headers, "X-Agentkeys-Device-Sig")?;
    verify_ecdsa(device_pubkey, sha256(body_bytes), device_sig)?;

    // 3. Replay defenses.
    if abs(now_unix() - req.body.timestamp) > 60 {
        return Err("timestamp out of window");
    }
    if !nonce_lru.insert(req.body.nonce) {
        return Err("nonce already seen");
    }

    // 4. Cross-binding.
    if claims.omni_account != req.body.omni_account {
        return Err("JWT omni does not match request omni");
    }

    Ok(())
}
```

The signer holds:
- The broker's session pubkey (read from a pinned file at boot;
  shared between broker and signer when co-located on the same host).
- A per-session nonce LRU (in-memory; bounded; expires with the
  session).

The signer holds NO secrets — only public keys. Signer compromise
leaks no auth material.

## Comparison with Heima `ClientAuth` tier model

| Heima variant | What it does | Step 1c equivalent |
|---|---|---|
| `JwtBearer` | Static long-lived TEE-RSA JWT | Step 1b's bearer auth (replaced by 1c). |
| `BackendSigned` | Backend signs userOp; TEE verifies backend ECDSA | Step 1c device-key auth. The "backend" becomes the user's local device, not the broker. |
| `EvmSiweSigned` | Per-call EIP-191 sig from user wallet | Step 1c init binding for `evm` omnis. The per-call sig moves to the device key (cheaper UX). |

Step 1c is **strictly stronger** than all three Heima variants:

- No replay window (vs `JwtBearer`).
- User-controlled, not backend-controlled key (vs `BackendSigned`).
- One-shot init cost; automatic per-request (vs `EvmSiweSigned`).

## Implementation order

| # | Step | LOC est. | Test gate |
|---|---|---|---|
| 0 | `signer-protocol.md` v0.2 — wire contract for device-key auth (request shape, header names, canonical_json definition, signer verification algorithm) | ~150 doc | Review-only |
| 1 | `agentkeys-core::device_key` module — keypair generation, keychain persistence, canonical_json + ECDSA sign helper | ~150 | Unit tests: key roundtrip; canonical_json determinism; sign/verify round-trip |
| 2 | Broker: session JWT mint adds `agentkeys_device_pubkey` claim | ~50 | Existing broker tests still green; new test asserts claim presence |
| 3 | Broker: extend `email_request` / `oauth2_start` / `wallet_sig` flows to accept + bind device pubkey | ~200 | Per-flow integration test asserting binding lands and JWT carries claim |
| 4 | Broker: `/v1/wallet/link` extended to optionally rotate device pubkey | ~50 | Test rotation works without re-doing identity ceremony |
| 5 | dev_key_service handlers: verify `Authorization: Bearer <jwt>` + `X-Agentkeys-Device-Sig` header per algorithm in §"Signer verification path" | ~120 | Integration tests: missing JWT (401); missing sig (401); wrong omni (401); replayed nonce (401); stale timestamp (401); happy path (200) |
| 6 | `agentkeys-core::init_flow` updates: generate device key at init, sign binding payload per identity type, register with broker | ~180 | Both CLI and daemon integration tests pass |
| 7 | `agentkeys-core::signer_client::HttpSignerClient` updated to send JWT + device-sig per call | ~80 | Existing conformance test extended to drive signed requests |
| 8 | Step 1b's bearer-JWT-only path deprecated — protocol doc + handler reject requests without device-sig header | ~30 | All callers must implement device-sig; legacy callers get 401 |
| 9 | TEE-stub conformance test: stub backend implements the full wire contract (JWT verify + device-sig verify); runs against same daemon assertions | ~100 | Identical pass/fail to HKDF backend |
| 10 | Demo doc + operator runbook updated to reflect device-key flow | ~80 | Walkthrough exercises init + sign end-to-end |
| 11 | Live broker host redeploy + smoke walkthrough | n/a | Wallet A / Wallet B isolation proof still passes; no per-request user interaction observed |

**Rough total: ~1200 LOC + protocol-doc revision + 11 stage-gated test waves**, contained to broker auth handlers, dev_key_service handlers, agentkeys-core, and the demo doc. Mock-server gets the new module surface; daemon and CLI are pure consumers of the new helpers.

## Open questions for review

- **Should the device pubkey be in the JWT claim or in a separate
  signer-side registry?** JWT claim is simpler (no shared DB between
  broker and signer); registry decouples the binding from the JWT and
  enables device rotation without re-issuing the JWT. Default proposal:
  **JWT claim** for v1c; registry as v0.2 if rotation pressure
  emerges.

- **Canonical JSON spec.** RFC 8785 is the obvious choice but adds a
  dep. A hand-rolled "sorted keys, no whitespace, no escaping
  surprises" serializer is ~50 LOC. Default proposal: **hand-rolled**;
  pin the algorithm in `signer-protocol.md` v0.2.

- **Nonce LRU sizing.** Per-session nonce LRU bounded by N entries.
  Daemons might issue thousands of sign requests per session. Default
  proposal: **N=10000 per session** (~320 KB at 32 bytes/nonce); evict
  oldest on overflow; nonce reuse after eviction is acceptable because
  timestamp window is ±60s.

- **Device key persistence on a fresh sandbox VM.** **RESOLVED** (Q8) —
  decision recorded in [`architecture.md` §5a.4](../../arch.md).
  Stock `agent-infra/sandbox` does not expose the host's OS keychain;
  `keyring-rs` falls back to a file-backend at
  `~/.agentkeys/daemon-<wallet>/session.json` (mode 0600), which
  survives daemon restarts inside a long-lived container but vanishes
  with the container itself. For ephemeral sandboxes (container
  destroyed between sessions), the operator runs
  `agentkeys-daemon --init-link-code <new-code>` from their
  workstation each new session — same pattern as today's pair-flow
  with the device-pubkey binding added on top. Hardware-backed
  device keys (Secure Enclave / TPM passthrough — passkey path) is
  a v0.2 enhancement.

- **Device key compromise detection.** No automatic detection in v1c.
  Operator runs `agentkeys whoami` to inspect the active device
  pubkey; mismatch with what they expect signals compromise. Default
  proposal: **manual** for v1c; instrumented anomaly detection for
  v0.2.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Device key leaks (keychain extraction by malware) | Same blast radius as a stolen session JWT today: forge until revocation. Mitigation: re-init rotates device key + JWT. Future: hardware-backed device keys (Secure Enclave / TPM). |
| Broker compromise mints fake JWTs with attacker's device pubkey | Bounded by broker session keypair lifetime. Mitigation: short-TTL session JWTs (5h default already); broker session keypair rotates per Stage 7 plan. |
| Replay across sessions | Signer's nonce LRU is per-session; cross-session nonce reuse is irrelevant because session JWT differs (so the device pubkey differs). |
| Clock skew on operator's machine breaks ±60s timestamp window | Document NTP requirement in operator runbook; sign request returns `timestamp_out_of_window` error envelope so daemons can surface a clear message. |
| Implementation bug in canonical JSON serializer breaks signature verification | Pin algorithm in `signer-protocol.md` v0.2 with test vectors; both daemon and signer share the same `agentkeys-core::canonical_json` module; vector-tested on every CI run. |

## Order of operations across issues

1. **Step 1b** (parallel issue, immediate) — `signer.litentry.org`
   listener split + bearer-JWT verification. Public listener live.
2. **Step 1c** (this plan, follow-up) — device-key auth replaces
   bearer-JWT. Wire contract hardens to v0.2.
3. **Step 2** (separate issue, planned) — TEE worker replaces HKDF
   backend behind unchanged wire shape. The device-key auth scheme is
   a hard requirement before step 2 ships, because the TEE worker's
   threat model assumes the signer can't be tricked by a compromised
   broker.

## What lands at v1.0 (post-step-1c)

- Broker compromise no longer enables impersonating signer requests
  for any user.
- Daemon holds an ephemeral device key, no omni-derived key material.
- Per-request crypto verification on every `/dev/sign-message` call.
- Identity-type-uniform UX: one ceremony at init, automatic
  thereafter.
- TEE-swap-ready: the device-key scheme survives the HKDF → TEE
  backend swap unchanged.

---

## CEO review — pending

To be reviewed before implementation lands. Defaults proposed in §"Open
questions" can be flipped during review.
