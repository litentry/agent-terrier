# Signer Protocol — v0

**Status:** v0 contract for the AgentKeys signer edge.
**Conformance:** every signer implementation (`dev_key_service` HKDF backend,
future TEE worker, future threshold-MPC backend) MUST implement this wire
shape unchanged. The daemon depends on this contract; if a swap-in
implementation diverges, the daemon stops working.

## Purpose

The signer is the trust boundary that owns the EVM keypair derived from a
user's `omni_account`. The daemon never holds private key material; it asks
the signer for two things only:

1. The 0x-address derived from a given `omni_account` (so the daemon knows
   what to `link` against the broker).
2. An EIP-191 ECDSA signature over an arbitrary message produced under that
   same derived key (so the daemon can complete the broker's SIWE round-trip).

Issue #74 step 1 ships an HKDF-backed implementation in `agentkeys-mock-server`
(`/dev/*` endpoints, gated by `DEV_KEY_SERVICE_MASTER_SECRET`). Issue #74
step 2 replaces that implementation with a TEE worker: same wire shape,
attested boot, sealed master secret. The daemon's call sites do not
change at the swap.

## Endpoints

Both endpoints are `POST` with `application/json` body, returning
`application/json`. They are unauthenticated at the HTTP layer in v0 — the
daemon and signer share a private network in the dev_key_service
deployment, and an attested mTLS channel in the TEE deployment. **The HTTP
contract is identical in both cases.**

### `POST /dev/derive-address`

#### Request

```json
{
  "omni_account": "<64 lowercase hex chars>"
}
```

`omni_account` is the canonical 32-byte digest defined in
`crates/agentkeys-broker-server/src/identity/omni_account.rs` —
`SHA256("agentkeys" || identity_type || identity_value)` rendered as
lowercase hex.

#### Response — 200 OK

```json
{
  "address": "0x<40 lowercase hex chars>",
  "key_version": 1
}
```

* `address` is the EIP-55-compatible 20-byte EVM address derived from the
  signer's keypair. The signer MUST return lowercase form so it round-trips
  through the broker's lowercase-canonical wallet store.
* `key_version` is the HKDF derivation domain (see "Versioned derivation"
  below). Clients SHOULD record this alongside the address; a future
  master-secret rotation will bump this byte and produce a different address
  for the same `omni_account`.

#### Errors

| HTTP | `error` value | Meaning |
|---|---|---|
| 400 | `invalid_omni_account` | `omni_account` missing, wrong length, non-hex |
| 503 | `signer_disabled` | `DEV_KEY_SERVICE_MASTER_SECRET` unset (dev backend) / TEE not yet attested (TEE backend) |
| 500 | `internal` | Unexpected — bug |

### `POST /dev/sign-message`

#### Request

```json
{
  "omni_account": "<64 lowercase hex chars>",
  "message_hex":  "<even-length hex, no 0x prefix>"
}
```

`message_hex` is the byte sequence the signer will wrap in the EIP-191
envelope (`"\x19Ethereum Signed Message:\n<len>" || message`) and sign with
the keypair derived from `omni_account`. Daemon callers SHOULD send the
SIWE message UTF-8-encoded as hex; the signer MUST NOT interpret content.

#### Response — 200 OK

```json
{
  "signature":   "0x<130 lowercase hex chars>",
  "address":     "0x<40 lowercase hex chars>",
  "key_version": 1
}
```

* `signature` is 65 bytes encoded as `0x` + 130 hex chars: `r(32) || s(32) || v(1)`.
  `v` is normalized to `{0, 1}` (NOT `{27, 28}`) — both forms are
  re-recoverable by the broker, but the signer MUST emit the canonical
  `{0, 1}` form so the wire shape is single-valued.
* `address` MUST equal the address `/dev/derive-address` returned for the
  same `omni_account`. Clients use it to detect derivation drift if the
  master secret was rotated mid-session.
* `key_version` MUST equal the `key_version` from `/dev/derive-address` for
  the same `omni_account`. A change here means the master secret rotated.

#### Errors

| HTTP | `error` value | Meaning |
|---|---|---|
| 400 | `invalid_omni_account` | `omni_account` missing, wrong length, non-hex |
| 400 | `invalid_message_hex`  | `message_hex` missing, non-hex, odd length |
| 503 | `signer_disabled`      | Same as `/dev/derive-address` |
| 500 | `internal`             | Unexpected — bug |

## Error envelope

All non-2xx responses share the shape:

```json
{
  "error":   "<stable machine-readable code from the table above>",
  "message": "<human-readable detail; subject to change>"
}
```

Daemon code MUST match on `error`, never on `message`.

## Versioned derivation

The HKDF info string is **versioned by a single leading byte**, so future
master-secret rotation (or a derivation-domain change) does not silently
re-issue the same address from a different key:

```
HKDF-SHA256(
  ikm    = master_secret (32 bytes),
  salt   = "agentkeys-signer-v0" (UTF-8),
  info   = [key_version_byte] || "agentkeys-evm-wallet" || omni_account_bytes,
  okm    = 32 bytes,
)
```

* `master_secret` is 32 bytes loaded from `DEV_KEY_SERVICE_MASTER_SECRET`
  (hex-encoded env var) for the dev backend. The TEE backend generates it
  inside the enclave at first boot and seals it.
* `key_version_byte = 0x01` for v0. **Reserved range:** `0x01..=0x7f` for
  production rotations; `0x80..=0xff` reserved for testing/staging
  derivations so they cannot collide with prod.
* `omni_account_bytes` is the 32 raw bytes of the `omni_account` digest
  (NOT the hex string).

The 32-byte HKDF output is then validated as a `secp256k1::SecretKey`; if
rejected (probability ≈ 2⁻¹²⁸), the signer extends the HKDF output by
one counter byte and retries. In practice this never fires.

The address is derived per EIP-55: keccak256 of the uncompressed public key
without the `0x04` prefix, take the last 20 bytes, format as
`0x` + lowercase hex.

## Determinism guarantees

* **Same `(master_secret, key_version, omni_account)`** → same address,
  same signing key, every time, across processes, across machines, across
  daemon reinstalls.
* **Different `master_secret`** → different address. (Operators cannot
  recover their derived wallet by re-running the same `omni_account` against
  a fresh deployment without restoring the master secret.)
* **Different `key_version`** → different address for the same
  `omni_account`. This is the rotation knob.
* **Different `omni_account`** → different address. (The whole point.)

## Future: attestation handshake (TEE backend only)

The TEE backend will expose a third endpoint:

### `GET /dev/attestation` — TEE backend only

#### Response — 200 OK

```json
{
  "quote":        "<base64-encoded TEE quote>",
  "quote_format": "tdx" | "sgx" | "nitro",
  "issued_at":    1746455331,
  "key_version":  1,
  "attested_pubkey": "<hex pubkey of the signing key derived from omni_account=0...0>",
  "signer_url":   "https://signer.agentkeys.dev"
}
```

The daemon SHOULD verify the quote against the cloud provider's attestation
service before sending its first `/dev/sign-message` request. The dev
backend returns 404 here — the absence of the endpoint is itself a signal
that this is the dev signer, not a TEE signer.

The HTTP shape of `/dev/derive-address` and `/dev/sign-message` does NOT
change when the TEE backend lands. Only the deployment topology changes
(direct HTTP → mTLS-over-attested-channel) and the new `/dev/attestation`
endpoint becomes available.

## Conformance test obligation

`crates/agentkeys-mock-server/tests/dev_key_service_conformance.rs` ships a
TEE-stub fixture (`TeeStubSigner`) that implements the same wire surface
with an in-memory keypair and is exercised by the same daemon integration
tests as the HKDF backend. Both must pass identical assertions on:

* address determinism for repeated `/dev/derive-address` calls,
* address-equality between `/dev/derive-address` response and `/dev/sign-message` response,
* signature recoverability via `ecrecover` to the same address,
* error-envelope shape for every documented error case.

If you add a new signer backend, add it to that conformance suite.

## What's intentionally out of scope at v0

* **Authentication on the signer edge.** Dev backend is private network;
  TEE backend uses mTLS-over-attested-channel. Neither requires a per-call
  auth token.
* **Rate limiting on `/dev/sign-message`.** The daemon is the only caller.
  When TEE replaces dev, the enclave will rate-limit per `omni_account`.
* **Master-secret rotation policy.** Operators manually rewind via
  `DEV_KEY_SERVICE_MASTER_SECRET` env-var change for dev; TEE step 2
  defines the rotation runbook.
* **Threshold signing.** Future work; would extend the wire with an
  enrollment phase but `/dev/sign-message` shape stays the same.

---

**Last reviewed:** issue #74 step 1, 2026-05-08.
**Owner:** the signer-edge crate (currently `agentkeys-mock-server::dev_key_service`,
post-step-2 `agentkeys-tee-worker`).
