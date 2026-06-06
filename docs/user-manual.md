# AgentKeys — User Manual

The single home for **user-facing behaviors and instructions** — the things an
operator or end user needs to know about how AgentKeys touches their machine.
(Developers: see [`arch.md`](arch.md). Running the wire demo end to end: see
[`operator-runbook-wire.md`](operator-runbook-wire.md).)

> Convention: every user-aware instruction or caveat lives here. If a change
> alters something a user would notice, document it in this file.

## `agentkeys wire` takes over your runtime's hooks

`agentkeys wire <runtime>` installs the AgentKeys IAM hooks — the permission
gate, audit append, and memory injection — into your Task Host's config so the
LLM **cannot bypass** them. That guarantee depends on AgentKeys owning the hook
configuration, so:

> **`agentkeys wire` takes full ownership of the runtime's hooks block. If you
> already have your own hooks there, wire REPLACES them with its managed block.**

For Hermes that is the top-level `hooks:` key in `~/.hermes/config.yaml`. A YAML
config allows only one `hooks:` key, so AgentKeys cannot coexist with a separate
hand-authored hooks block — it replaces it.

What this means for you:

- **Fresh runtime** (no hooks yet): wire appends its managed block; nothing of
  yours is touched.
- **You had your own hooks**: wire removes them and installs its block. Back them
  up first if you still need them.
- **Re-running wire**: only the managed block (between the sentinels below) is
  refreshed; your other config keys (`model:`, `terminal:`, …) are preserved.

The managed block is delimited so you can see exactly what AgentKeys owns:

```
# >>> agentkeys wire (managed block — do not edit; re-run `agentkeys wire`) >>>
hooks:
  ...
hooks_auto_accept: true
# <<< agentkeys wire <<<
```

Remove it any time with `agentkeys wire <runtime> --unwire`.

> Some hosts re-serialize their config and drop comments — e.g.
> `hermes config set model.default …` strips the sentinel comment lines while
> keeping the hooks data. `agentkeys wire` detects a de-sentineled block and
> re-wraps it on the next run, so re-running wire is always safe.

## Setting up your categories (parent-control)

Onboarding ends with a **"Set up your categories"** step (right after you bind
your passkey): pick a starting profile and your taxonomy is authored before you
connect any agent. You can **skip** it there and do it later — the **memory** page
offers the same setup whenever your taxonomy is empty. Either way you author your
**category taxonomy** — the vocabulary agentKeys uses to scope everything an agent
can touch: the **memory** it reads (`memory:<namespace>`), the **credentials** it
uses, and more data classes (payments, …) as you add them. It seeds your memory
categories now; credentials are auto-categorized into the same taxonomy when you
connect an agent. You author it in one of two ways:

> **If init fails with a config-worker error** (e.g. `taxonomy authoring failed —
> the Config data class must be healthy … s3 GetObject: AccessDenied`): the
> encrypted, master-only `Config` store isn't healthy, so **nothing was written** —
> AgentKeys authors real durable data or fails loudly; it never keeps a silent
> in-memory stand-in. Fix the real cause the error names: provision `$CONFIG_BUCKET`
> + the config role (`setup-cloud.sh`), deploy/repair the config worker
> (`setup-broker-host.sh --ref main`), and check the role's S3 Get/Put/List on
> `bots/<actor>/config/*` and the region — then re-initialize. (A dev daemon
> started WITHOUT `--config-url` authors in-memory only, clearly labelled "dev
> only" — that is the one non-durable path, and it exists only when you opt out of
> a config worker entirely.)

- **A · Start from a profile** — pick one of ~10 role presets (the default is a
  rich *adult-household* profile: kids, business, smart-home, finance, family,
  health, travel, personal), preview its categories, and click **initialize
  categories**. This authors your taxonomy in one step. You can re-run it or
  switch presets later — it **merges**, so it never drops categories you already
  have.
- **B · Describe in your own words** — a natural-language box that compiles a
  sentence into a taxonomy. This is shown as **coming soon**; it lands in a later
  release.

> Initializing categories writes only the **category index** (which namespaces
> exist), not any memory contents and not agent permissions — so it needs no
> passkey (K11) confirmation. It is **master-only**: the agents a policy governs
> can't read or change it.

The **plant prepared demo archive** button below is a **test/demo seed** — it
imports a small fixed set of example memories (a trip, a profile) so the page has
data to show. It is idempotent (re-planting is a no-op) and is not the production
path; planting also only adds namespaces to your taxonomy, never removing the
ones a preset authored. (Nothing is planted automatically — onboarding only
authors the category index; memory entries appear only when **you** plant them.)

## Credentials (parent-control)

The **credentials** page is the same data-class abstraction as memory: it lists
the credentials you've vaulted, **categorized by the shared catalog** (`stripe →
payments`, `openrouter → ai-services`), with sensitive categories (payments,
access-control, health, …) flagged — exactly like memory namespaces are grouped
by category. Each is stored encrypted (AES-256-GCM, K3 KEK) at
`bots/<you>/credentials/<service>.enc` through the real chain (cap-mint → STS →
cred worker → S3); the secret is **decrypt-on-read and never shown** in the UI. An
agent can fetch a credential only with a granted `cred:<service>` scope. **Vault a
credential** with the form on that page (service id + secret). Listing is
**master-only** — an agent's single-service cap can't enumerate your vault.
