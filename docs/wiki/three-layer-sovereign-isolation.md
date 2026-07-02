**Scope:** why AgentKeys keeps its isolation guarantee **sovereign** — independent of any single cloud provider — even as the storage/credential plane runs on AWS *or* Volcano Engine (火山引擎). This is the sovereignty *lens* on the isolation model; the canonical, operational layer inventory is [arch.md §17.5](../../docs/arch.md) (the four-layer defense-in-depth from issue #90). Read this to understand the *why*; read arch.md for the exact per-layer enforcement table.

## The one-sentence thesis

The root of trust is the **blockchain and the signer — never the cloud**. Two of the three isolation layers are cloud-agnostic and hold that root of trust; only the third is cloud-specific, and it is defense-in-depth rather than the primary gate. So swapping the cloud (AWS ⇄ VE), or even a *total* compromise of the cloud account, never breaks a user's isolation guarantee.

## The three layers

### Layer 1 — Chain-anchored authority (WHO may act)

Identity and authorization live **on-chain**, not in a cloud IAM database:

- Every actor (master, agent/delegate, device) is a node in the on-chain **HDKD actor tree** — a deterministic key hierarchy, not a cloud user record.
- A credential/storage operation is gated by a **capability token** the broker mints only after checking the requester's device + scope **on-chain** (`SidecarRegistry`), and the worker then **independently re-verifies that same authorization against the chain** before touching storage (defense against a compromised broker).

Because the authority record is the blockchain, no cloud operator — not even the account owner — can grant, forge, or widen an actor's authority. Moving clouds changes nothing here: the chain is the same chain.

### Layer 2 — Client-side encryption (WHAT is stored)

The cloud stores **ciphertext only**. Data is sealed **before** it leaves the client with AES-256-GCM, under a per-`(actor, service)` key derived from the **signer** (an independent trust root from the storage bucket):

- The key-encryption key never exists in the cloud; deriving it requires the signer + the specific actor's signing authority.
- The encryption envelope binds the actor and service into its authenticated-additional-data, so a blob swapped between two actors at the storage layer fails to decrypt.

Consequence: an attacker (or operator) with **full read access to every storage object** obtains only opaque ciphertext. Confidentiality does **not** depend on the cloud honoring an access rule — it is a cryptographic property the cloud cannot violate.

### Layer 3 — Cloud IAM per-actor scoping (the swappable layer)

This is the **only** cloud-dependent layer, and it is defense-in-depth on top of layers 1–2:

- **On AWS** — short-lived STS credentials carry **PrincipalTags** (set from the broker's OIDC token) and a static, operator-owned bucket policy restricts each session to `bots/<actor_omni>/*`.
- **On Volcano Engine** — VE has no tag-from-token mechanism, so the broker attaches a **per-actor inline session policy** to each `AssumeRoleWithOIDC` mint, scoping the session to the same `bots/<actor_omni>/*` prefix. (Proven live: a session can read/write its own prefix and is `AccessDenied` on any other actor's — see [ve-broker-runtime-port.md](../../docs/spec/ve-broker-runtime-port.md).)

Same guarantee, different mechanism. The AWS→VE port changed **only this layer** — which is exactly why the migration is possible without touching the trust root.

## Why this is "sovereign"

| Property | Layer 1 (chain) | Layer 2 (encryption) | Layer 3 (cloud IAM) |
|---|---|---|---|
| Root of trust | blockchain | signer | cloud account |
| Cloud-agnostic | ✅ | ✅ | ❌ (per-cloud mechanism) |
| Survives full cloud compromise | ✅ authority unforgeable | ✅ ciphertext only | ⚠️ this layer is the one lost |
| Portable AWS ⇄ VE | ✅ unchanged | ✅ unchanged | 🔁 re-implemented per cloud |

A cloud provider (or a stolen cloud credential) can, at worst, defeat **layer 3** — and even then the attacker faces layer 2 (ciphertext they cannot decrypt) backed by layer 1 (authority they cannot forge). No single cloud is in a position to break a user's isolation. That is the sovereignty property: **the cloud is a commodity storage/compute substrate, not a trusted authority.**

> **Reading the ⚠️/❌ marks correctly:** they are *inherent properties of what layer 3 IS*, not unmitigated gaps. Layer 3 is cloud IAM — so it is cloud-specific (❌ cloud-agnostic) and it is the layer an attacker with the cloud account controls (⚠️ lost on full compromise), **by definition, in any design that uses cloud IAM at all.** That is precisely why it is *not* the root of trust. The sovereignty guarantee lives in layers 1–2, which are all ✅.

## The honest trade-off (and how it is mitigated)

Layer 3's mechanism differs between clouds in one meaningful way: on AWS the per-actor scope is enforced by a **static, operator-owned** bucket policy keyed on a tag the broker cannot forge; on VE it is asserted by the **broker at mint time** (an inline policy the broker builds). So on VE, layer 3 loses its *broker-independence*.

This does not move the root of trust (still layers 1–2), but it does enlarge what a compromised broker could attempt at layer 3. Mitigations (tracked in the VE parity work):

- The VE STS client **fails closed** — a mint with no derivable actor or no configured buckets is a hard error, never an unscoped credential.
- A **coarse role policy** caps every session at `bots/*` on the data buckets, so even a bug cannot escape the data prefix.
- The broker's VE signing identity is **least-privilege** (`sts:AssumeRoleWithOIDC` only) — it can mint scoped sessions but cannot touch storage directly.
- **Layer 2 is untouched on VE**: a compromised broker still cannot read plaintext, and workers still re-verify authorization on-chain (layer 1).
- A native, static TOS bucket-policy backstop is planned to restore the AWS-style operator-owned gate.

**The ideal end-state for layer 3** (what closes the VE ⚠️ gap): a **static, operator-owned, deny-by-default** cloud policy keyed on a per-actor attribute the broker **cannot forge** — on AWS that is the PrincipalTag → bucket-policy pairing; on VE, a native **TOS bucket policy** (plus session tags carried from the OIDC token, if VE supports them), with the broker's per-mint inline session policy demoted to *belt-and-suspenders*. That flips VE's layer 3 from "broker-asserted at mint time" back to "operator-enforced, broker-independent", matching AWS. Tracked in issue #372. Note this only tightens the *defense-in-depth* layer — sovereignty (layers 1–2) already holds regardless.

## See also

- [arch.md §17.5](../../docs/arch.md) — the canonical four-layer defense-in-depth table + cap-endpoint inventory (the operational source of truth).
- [ve-broker-runtime-port.md](../../docs/spec/ve-broker-runtime-port.md) — the AWS→VE storage/credential port, including the PrincipalTags → session-Policy fork and the live cross-actor-denial proof.
- [agent-role-and-usage-hdkd-per-agent-omni.md](./agent-role-and-usage-hdkd-per-agent-omni.md) — the HDKD actor tree that layer 1 anchors to.
