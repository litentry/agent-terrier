# @agentkeys/dsh-suite

The AgentKeys plugin suite for [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness): the in-loop enforcement of AgentKeys authority inside a delegate's runtime (spec: `docs/spec/delegate-runtime-dsh.md` §4.2, epic #609).

| Subpath | Plugin | Role |
|---|---|---|
| `@agentkeys/dsh-suite/guard` | `agentkeys-guard` | `tools/pre-execute` policy + the **monotonic** `ctx.tools.guard()` backstop: baseline allowed, `tool:<class>` grants projected from chain, unmapped tools denied by absence |
| `@agentkeys/dsh-suite/answerer` | `agentkeys-answerer` | `approval/request` answerer: granted class → `allowed-once` (one-shot callId ledger the guard honors); ungranted → best-effort #573 propose-to-owner, then `rejected` |
| `@agentkeys/dsh-suite/publish` | `agentkeys-publish` | the `publish_to_slot` tool — the delegate's "act" verb: one event to a bound pub slot (a `doc` card to the display, `text` to a chat, a `command`) via `agentkeys-daemon --publish-once`, no shell — the image's `publish-to-slot` helper needs `tool:code`, which no app sheet grants. Guard verdict `publish`: allowed by ANY `channel-pub:<id>` grant, the feed itself is the cap-mint's verdict |

Grants come from the co-located daemon's `GET /v1/sandbox/self/grants` (#611) — the ONE Rust-owned resolution of on-chain scope state. The chain stays the only writable authority (D1); this suite is a fail-closed projection: no grant view ⇒ classed tools deny.

No default exports anywhere (dsh postmortem 0001: the Loader drops `inject` from default-exported plugins).

```bash
npm test        # vitest against the real pinned dsh packages
npm run build   # tsc → lib/
```

Version pins: the `@deepseek-ai/dsh-*` family at one exact version + `@deepseek-ai/cordis` — bumped together with the sandbox image's dsh pin (plan step 9's `dsh-bump` gate).
