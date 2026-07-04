Your agent's memory in AgentKeys is built from three parts that stay cleanly separated: **the truth** (your canonical memory, which AgentKeys stores and you own), **the engine** (a memory provider like OpenViking or mem0 that *ranks and retrieves* — but never owns your data), and **the gate** (AgentKeys' rule for who is allowed to read what). An agent never talks to your raw memory or to a provider directly — it reads only the slice the gate authorizes, ranked by the engine, delivered into its context. This page explains how those pieces fit together, why you can swap providers freely, and why your namespaces always stay yours.

**Scope:** end users and integrators. For the developer construction model see `../plan/memory-construction.md` (operator-internal); for where bytes are stored see [`./knowledge-storage.md`](./knowledge-storage.md); for how access is scoped see [`./policy-scope-namespace.md`](./policy-scope-namespace.md).

## The three parts

| Part | What it does | Who owns it |
|---|---|---|
| **Truth** (canonical memory) | the durable, encrypted record of what your agent knows — text + labels | **you** (AgentKeys stores it, per-actor isolated) |
| **Engine** (memory provider) | ranks/retrieves: "what do I know that's relevant to *this*?" | swappable — OpenViking, mem0, or none |
| **Gate** | enforces who may read which memory, and audits every read | **AgentKeys** (on-chain scoped, per actor) |

A useful analogy: the truth is the original document, the engine is a search index built *over* it, and the gate is the lock on the filing cabinet. You can rebuild or replace the index any time; the original and the lock don't move.

## How a memory provider plugs in

A memory provider (OpenViking, mem0, …) joins as the **engine** — it sits *behind* the gate and only **ranks** the memory AgentKeys already stores and authorizes. Three guarantees make this safe:

- **It ranks, it never replaces.** AgentKeys keeps the encrypted truth and the access rules; the provider just reorders what's already allowed. Swap the provider and your data and rules don't move.
- **It can reorder but never widen.** The provider can change *which* authorized memories come first, but it can never surface a memory the gate didn't allow — even a misbehaving provider can't leak more than you granted.
- **It's never load-bearing.** If the provider is down or errors, AgentKeys falls back to a simple recency order. Your agent keeps working.

Two kinds of provider, and they are **not** equally private:

- **Self-hosted** (OpenViking, self-hosted mem0) — **the sovereign default.** Runs on your own machine; AgentKeys mirrors a copy of the authorized memory into it for ranking, and the plaintext stays on a machine you control.
- **Cloud** (hosted mem0, Honcho, …) — **an explicitly authorized egress, not "memory never leaves."** AgentKeys won't *replicate* your whole store there, but to rank or extract, a cloud engine **does see the query and the authorized snippets you send it**. So using one is a consent decision: you choose which namespaces may go out, and every call is audited. Reach for cloud only when you've accepted that egress; otherwise stay self-hosted.

## How an agent gets its memory

Agents don't fetch memory one item at a time over the network — that would be slow and would hand the model a tool to rummage through everything. Instead, the relevant, gate-authorized, engine-ranked **top results are placed into the agent's context** at the start of a turn (via AgentKeys' delivery hook). The agent simply *has* the memory it's allowed to see and never sees the whole store. For a small memory there's no ranking at all — the relevant slice is just included directly.

This is also why memory feels instant: the agent reads from its own context (or a local copy the daemon keeps fresh), not from a round-trip to a server on every recall.

## Your namespaces stay yours

You organize memory into **namespaces** (e.g. `user-profile`, `project-x`) — and a provider has its *own* way of organizing things (OpenViking uses `viking://` paths, mem0 uses ids). These never conflict, because your namespace is the **authoritative** one — it's what the gate locks on and the audit records — and the provider's organization is just a **derived copy** AgentKeys maps onto it. Change providers and your namespaces are untouched; only the internal mapping changes.

The same holds for agent-native files like **skills** and `AGENTS.md`/`CLAUDE.md`: these are context **types of their own** (capabilities and instructions, not knowledge) — the *same* context system and curation gate as memories, with **stricter adoption rules per type** (a skill is reviewed like code before you accept it; a persona document is edited only by you). This mirrors how OpenViking itself organizes memories, resources, and skills as one unified context tree. They can optionally be mirrored into a provider for retrieval over a large library, but they always live canonically in AgentKeys first. See [`./data-classification.md`](./data-classification.md) for how AgentKeys separates classes.

## What this means for you

- **Swap providers freely.** Your encrypted memory, your namespaces, and your access rules don't move when you change the engine — only the ranking does.
- **You stay in control of where plaintext lives.** Self-hosted engines keep it on your machines; a cloud engine is an explicit, audited egress you opt into per namespace — not a privacy guarantee.
- **Agents can't promote their own writes.** *Who* authored a memory and whether it's *shared* are stamped by AgentKeys from the authenticated identity and your curation — an agent can't label its own note as "from you" or push it into shared memory. A delegate's write lands in a staging inbox; it becomes shared only when you approve it.
- **Constrained devices still work.** A small voice device that can't run a ranking model can still hold your memory by downloading a precomputed index instead of building one (see [#316](https://github.com/litentry/agentKeys/issues/316)).
- **One shared memory, plus each agent's own.** There's *one shared canonical memory* you curate and distribute to the delegates you authorize — a learning curated once is available everywhere you've granted it. Each delegate **also keeps its own private working memory**, which is never collapsed into the shared one; sharing is additive (you grant a read), not a merge of everyone's notes.

For the underlying construction, sync, and cost model, see `../plan/memory-construction.md` (operator-internal). For the storage and isolation guarantees, see [`./knowledge-storage.md`](./knowledge-storage.md) and [`./tag-based-access.md`](./tag-based-access.md).
