# @agentkeys/dsh-suite

The AgentKeys plugin suite for [DeepSeek Harness (dsh)](https://github.com/deepseek-ai/deepseek-harness): the in-loop enforcement of AgentKeys authority inside a delegate's runtime (spec: `docs/spec/delegate-runtime-dsh.md` §4.2, epic #609).

| Subpath | Plugin | Role |
|---|---|---|
| `@agentkeys/dsh-suite/guard` | `agentkeys-guard` | `tools/pre-execute` policy + the **monotonic** `ctx.tools.guard()` backstop: baseline allowed, `tool:<class>` grants projected from chain, unmapped tools denied by absence |
| `@agentkeys/dsh-suite/answerer` | `agentkeys-answerer` | `approval/request` answerer: granted class → `allowed-once` (one-shot callId ledger the guard honors); ungranted → the runtime ask (a grant request filed through the daemon's `POST /v1/sandbox/self/propose`, one per class per ten minutes, loud when it cannot land), then `rejected` |
| `@agentkeys/dsh-suite/actions` | `agentkeys-actions` | the DAEMON-ADVERTISED verbs (2026-09-24): fetches `GET /v1/sandbox/self/actions` from the co-located daemon and registers one tool per entry — today `publish_to_slot` (the "act" verb: one event to a bound pub slot) and `propose_to_owner` (the "propose" verb: one learning into the owner's review queue) — each call ONE bearer-gated `POST /v1/sandbox/self/<verb>` the daemon signs as the delegate (the same code as its `--publish-once` / `--propose-once`). The daemon words the descriptions with the slots THIS install bound and the app's own namespace; nothing is re-derived from env here, nothing forks. Guard verdict `advertised`: allowed by ANY grant of the family the entry declares (`channel-pub:` / `proposal:`), the feed / namespace itself is the cap-mint's verdict |

Every request to the daemon goes through ONE client (`@agentkeys/dsh-suite/daemon-client`: the in-pod bearer, a bounded timeout, the daemon's `error` line as the reason — nothing in this package forks a process). Grants come from the co-located daemon's `GET /v1/sandbox/self/grants` (#611) — the ONE Rust-owned resolution of on-chain scope state. The chain stays the only writable authority (D1); this suite is a fail-closed projection: no grant view ⇒ classed tools deny. The advertised action list and its request bodies are pinned to `e2e/fixtures/bridge-protocol/actions_contract.json`, which the daemon's Rust test reads too.

No default exports anywhere (dsh postmortem 0001: the Loader drops `inject` from default-exported plugins).

```bash
npm test        # vitest against the real pinned dsh packages
npm run build   # tsc → lib/
```

Version pins: the `@deepseek-ai/dsh-*` family at one exact version + `@deepseek-ai/cordis` — bumped together with the sandbox image's dsh pin (plan step 9's `dsh-bump` gate).
