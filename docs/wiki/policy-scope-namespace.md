**Status:** reference (2026-06)
**Scope:** clarifies six words that are easy to conflate — **policy, taxonomy, category/attribute, namespace, service, scope** (and the runtime **cap**) — how they relate, and why AgentKeys deliberately keeps them as **distinct layers** rather than one merged concept.

> **Short answer to "should we abstract them into one definition?": no — but unify the *mental model* under one word, "policy attribute (category)."** Policy, scope, and namespace are not synonyms; they are **stages of one pipeline** (author → enforce → a memory-specialized resource). Collapsing them would destroy the property that makes the gate safe: the separation between *what a human meant* (policy), *what the chain enforces* (scope), and *what is being touched* (a service such as a memory namespace). The common currency that flows through all of them is the **category/attribute** — that is the abstraction to teach, not a merged term.

## The pipeline (read top to bottom)

```
 policy (NL + taxonomy)          author intent, human-readable, off-chain, master-only
   │   ── COMPILE (classifier, author-time) ──►
   ▼
 scope grants                    on-chain (operator, actor, serviceHash) edges — the enforcement record
   │   over ──►
   ▼
 categories / attributes         the structured unit the gate checks (payments, access-control{exterior}, media{rating:kids})
   │   specialized per data class ──►
   ▼
 service                         the signed cap string the worker keys on:
   │                               memory → "memory:<namespace>"   (namespace = the memory category)
   │                               creds  → "<credential-service>" (openrouter, stripe)
   │                               IoT    → "home:<room>:<device>"
   ▼   minted as ──►
 cap (token)                     the runtime bearer authorizing ONE service, TTL'd, signed
   │   checked by ──►
   ▼
 GATE: service ∈ scope ?         deterministic set-membership, NO model on the hot path
```

So: **a human writes policy → COMPILE turns it into on-chain scope grants over categories → at runtime a cap names one concrete service → the gate checks service-∈-scope by set-membership.** A **namespace** is simply the **memory** data class's category, carried in the signed service `memory:<ns>`.

## The terms

| Term | Layer | What it is | Set / authored when | Example | Lives in |
|---|---|---|---|---|---|
| **policy** | author intent (off-chain) | the human-readable rules + the readable grant list — *"kids can use their room devices, no spending"* | authored at **COMPILE** (or a default preset) | the NL spec + compiled grant list | `DataClass::Config` → `config/policy.enc` (master-only, encrypted) |
| **taxonomy** | the category tree | the set of categories/namespaces a tenant uses (versioned) | authored/extended at COMPILE | `[business, smart-home, kids, health]` | `DataClass::Config` → `config/memory-taxonomy.enc` |
| **category / attribute** | the structured unit | the classifier's **tag** and the gate's input; the thing a scope is granted *over* | **TAG** (per novel entity, then cached) | `payments`, `access-control{exterior}`, `media{rating:kids}` | the classifier output + the shared **catalog** (entity→category) |
| **namespace** | a memory resource | the **memory** data class's category axis — one specialization of "category", scoped to memory | assigned at memory write (classify) | `travel`, `health` → `memory:travel` | the signed cap field + `memory/memory:<ns>.enc` |
| **service** | the cap resource string | the signed field the worker keys storage/AAD/scope on; `serviceHash = keccak(service)` | per cap-mint | `memory:travel`, `openrouter`, `home:kids-room:light` | `cap.payload.service`; `serviceHash` on chain |
| **scope** | the on-chain grant | the tamper-proof `(operator, actor, serviceHash)` authorization **edge** — the enforcement anchor | `setScope` (COMPILE writes; **master-authorized**, `SCOPE_MGMT` + K11) | `isServiceInScope(op, actor, keccak("memory:travel")) == true` | `AgentKeysScope` contract (on chain) |
| **cap (token)** | the runtime artifact | the signed, TTL'd bearer authorizing **one** scoped operation; never carries the whole policy | cap-mint (per operation) | `{op, data_class, service, actor, sig}` | minted by broker, verified by worker |

## Why not merge them — the differences that matter

- **policy ≠ scope.** Policy is rich, human-readable, off-chain, and **private** (it maps a whole household/business — more sensitive than any one data line). Scope is the **minimal, tamper-proof** on-chain projection of it — only the `(actor, serviceHash)` edges, no prose. COMPILE is the one-way bridge. Editing policy does **not** retroactively kill live caps (revoke for that); see `../plan/classifier-service.md` (operator-internal) §6.1.
- **scope ≠ namespace.** Scope is the *grant relationship*; a namespace is a *resource* a grant can be over. `memory:travel` is a service (a memory namespace); the **scope** is the on-chain fact that a given actor may use it. Other resources (cred services, IoT devices, spend categories) are scoped the same way — namespace is just the memory-flavored one.
- **Same-actor by default; the one sanctioned cross-actor cap-mint is the canonical-memory READ** (master-hub distribution, [#295](https://github.com/litentry/agentKeys/issues/295) P1). Normally a cap is for the master's own data (`operator == actor`) or a delegate using a granted service on its OWN prefix. The exception: a delegate reads the **master's** `memory:<ns>` (`operator = master, actor = delegate`), gated by a real on-chain `memory:<ns>` scope grant. The delegate mints the `CanonicalFetch` cap with its **own** session (`session == actor`), and the read runs **server-side in the worker** — the delegate receives plaintext, **never** AWS creds, so the per-actor S3 wall stays absolute (the worker reads the exact granted object under an operator-tagged, single-object STS it never hands out). See `../plan/master-hub-topology.md` §7a (operator-internal) + arch.md §17.5.
- **category ≠ service.** A category is the abstract tag (`payments`); a service is a concrete instance (`stripe`). Today scope is granted per concrete `serviceHash`; #178 P3 generalizes `isServiceInScope` to **category-set** membership so one grant (`deny payments`) covers every concrete service in the category.
- **The unifying abstraction is "policy attribute (category)."** Memory→namespace, creds→service-category, IoT→device-tier, payment→spend-category are **all** policy attributes (`../research/universal-gate-pattern.md` (operator-internal) — the four primitives). That is the single mental model; the surface words stay distinct because they name **different stages**, and the stage boundaries are load-bearing security boundaries (the gate is deterministic precisely because *a human's intent* is compiled to *an attribute the chain enforces*, with no model in between).

## Naming collision to avoid: two different "tags"

| "tag" | Meaning | Where |
|---|---|---|
| **category tag** | the classifier's output (`stripe → payments`) — a **policy attribute** | `../plan/classifier-service.md` (operator-internal) (this page) |
| **PrincipalTag** | the AWS STS **session tag** (`agentkeys_actor_omni`) that walls one actor's S3 prefix from another's | [`./tag-based-access.md`](./tag-based-access.md) |

They are unrelated — one is *authorization category*, the other is *cloud per-actor isolation*. When a doc says "tag," disambiguate.

## Cross-references
- `../plan/classifier-service.md` (operator-internal) — COMPILE/TAG, the catalog, the determinism guardrail (the source of "category/attribute" + "policy").
- `../plan/web-flow/onboarding-classifier-distribution.md` (operator-internal) — how policy is bootstrapped and distributed to delegates as scopes.
- `../research/universal-gate-pattern.md` (operator-internal) — the four primitives; the unifying "policy attribute" model.
- [`./data-classification.md`](./data-classification.md) — where each data class lives + encryption status.
- arch.md §15.2 (namespace = signed service), §19 (`AgentKeysScope` / cap shape).
