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
