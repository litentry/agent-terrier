A focused operator reference for the **delegate** actor — the identity an AI runtime runs as. It defers to [`../arch.md`](../arch.md) for the authoritative model — read this when you need the operator-facing "what is a delegate, what can it do, how do I create and scope one" view without re-reading the whole architecture.

> **Canonical name** ([`../arch.md` §5](../arch.md#5-canonical-names-one-concept-one-canonical-spelling)): a **delegate** is a scoped app-serving identity. `delegate` is the canonical prose/UX word; **`agent` is the frozen code + on-chain spelling** (`agent_omni`, `registerAgentDevice`, `SidecarRegistry`) — a full rename is a deferred major-version cutover, so you'll still see `agent` in the CLI, contracts, and S3 keys. They name the same thing.
>
> Canonical model: [`../arch.md` §6 — Identity model + HDKD actor tree](../arch.md#6-identity-model--three-layers--hdkd-actor-tree). Binding ceremonies: §10. Sidecar daemon (the delegate's runtime): §12. Workers the delegate calls: §15. Master-as-hub topology (pull/push memory channels): §17.6. Anything here that disagrees with arch.md is wrong — fix it against arch.md.

## What a delegate is

One human operator has **many actors**: one **master** plus N **delegates**. They form a hard-derived (HDKD) tree rooted at the master. Each actor — master and every delegate — has:

- its own **`actor_omni`** (Layer-1 cryptographic anchor, frozen at first bind, survives K3 rotation);
- its own derived wallet (K4), derived on demand inside the signer from `K3_v[epoch]` + `actor_omni`;
- its own per-machine device key (**K10**) registered in the on-chain `SidecarRegistry`.

A delegate is a **node in the actor tree**, not a separate login. "Delegate" and "master" sit on the same axis (actor) but play **distinct roles**.

## Delegate role vs. master role

Same axis, different authority:

| | Master | Delegate |
|---|---|---|
| Bootstrap path | Operator init ceremony (§9 cold-start) | Created + bound *by the master* (§10.2 delegate bootstrap) |
| K11 (WebAuthn) | **Owns it** — required for master mutations (scope grant/revoke, device add, K10 rotation) | **Never holds K11** — cannot perform master mutations |
| Revocation authority | Can revoke any delegate's scope/devices | Cannot revoke; is *subject to* revocation |
| Wallet (K4) | `current_master_wallet` (L2) is the operator's chain identity | Per-delegate K4; used by the signer to mint STS for that delegate |
| Cap-mint requests | Signs its own (K10) + K11 for master ops | Signs with K10; scope is whatever the master granted |

The headline: **a delegate can only do what the master granted it**, and that grant is enforced on-chain (ScopeContract) + at every worker (cap-token re-verification). Compromising one delegate yields bounded damage — it cannot escalate to the master or to other delegates (per-actor binding, §3 trust boundaries).

## What a delegate can do — gated capabilities

Everything a delegate does flows through a **cap-token** the broker mints for it, re-verified by the target worker before any effect. The delegate's reach is exactly its granted scope:

- **Memory** — read/write its own per-actor memory store, filtered by the namespaces its cap allows (`namespaces_allowed`, e.g. `["travel"]`). See the gated-memory model in [`../arch.md` §15.2](../arch.md#152-memory-service) and the memory build-vs-gate decision (operator-internal). Beyond its own store, the **master-hub channels** ([`../arch.md` §17.6](../arch.md), #295/#339) let a delegate **pull** the master's canonical memory it was granted (`memory:<ns>`) and **push** learnings back to the master's absorption inbox (`inbox:<ns>`) — a distinct grant — for the master to curate.
- **Credentials** — fetch API keys for services in its on-chain scope only (§15.1); the credential vault is master-sovereign (store is master-self), a delegate's grant authorizes a *fetch*.
- **Other workers** (email, payment, audit, future home-IoT) — same shape: a deterministic gate (op + resource scope + limits + attribute constraints) over the worker's effect. The general model is the universal gate pattern (operator-internal).

The delegate never holds the KEK, never reaches S3 directly without scoped STS creds, and never sees other actors' data — isolation is enforced four ways (broker cap-mint, worker chain-verify, AWS IAM PrincipalTag, per-data-class buckets; [`../arch.md` §17.5](../arch.md#175-per-data-class-cap-token-binding-issue-90)).

## Creating and using a delegate (operator view)

1. **Create + bind** — from the master device, run the delegate-bootstrap ceremony (§10.2). The master authorizes a new `actor_omni`, registers the delegate's K10 device key, and grants initial scope (services + memory namespaces). K11 user-presence is required because this is a master mutation.
2. **Run** — the delegate process runs in its own sandbox with a local sidecar daemon (the delegate's runtime) holding only K10 (never K11). The daemon mints cap-tokens on the delegate's behalf for each operation.
3. **Scope changes** — widen/narrow what the delegate can touch via scope grant/revoke from the master (on-chain, K11-gated). Changes take effect immediately online; offline reach is bounded by cap-token TTL.
4. **Revoke** — revoke the delegate's devices or scope from the master; the delegate's next cap-mint fails and in-flight caps expire at TTL.

## Per-delegate omni — why it's stable

The delegate's `actor_omni` is the durable anchor for *everything* keyed to that delegate: its S3 prefix (`bots/<actor_omni_hex>/...`), its AWS PrincipalTag, its scope-index key, its AAD. Because it's Layer-1 (frozen, K3-rotation-invariant), **rotating K3 or replacing the master device never migrates the delegate's data or re-keys its identity**. The delegate's memory and credentials stay exactly where they are; only the underlying KEK epoch advances, handled transparently by the in-blob epoch byte.

## See also

- [`../arch.md` §5](../arch.md#5-canonical-names-one-concept-one-canonical-spelling) — canonical names (`delegate` ⟷ frozen `agent` alias)
- [`../arch.md` §6](../arch.md#6-identity-model--three-layers--hdkd-actor-tree) — three identity layers + HDKD tree (authoritative)
- [`../arch.md` §10](../arch.md) — per-actor binding ceremonies (master init, delegate bootstrap, device/K10 rotation)
- [`../arch.md` §12](../arch.md) — sidecar daemon (K10/K11 custody, cap-mint) — the delegate's runtime
- [`../arch.md` §17.6](../arch.md) — master-as-hub topology (the pull/push memory channels)
- Other operator playbooks in this wiki (sibling pages under `docs/wiki/`)
- memory build-vs-gate decision (operator-internal) + universal gate pattern (operator-internal) — how a delegate's capabilities are gated
