# agentkeys-gate — metered key-custody LLM-egress relay

The thin relay of [#384](https://github.com/litentry/agentKeys/issues/384): the
sandbox agent (Hermes) consumes its LLM as a generic OpenAI-compatible provider,
and pointing that provider's `base_url` at this relay moves the vendor inference
key (Ark — **Bearer-only, not IAM/STS-mintable**) out of every sandbox. The relay
holds the one shared key, forwards each turn, and meters the response's `usage`
field per [#332](https://github.com/litentry/agentKeys/issues/332).

**Custody + metering ONLY — not a control point.** Per arch.md §22d the IAM
guarantee for the agent path is hooks + data-plane caps. The relay does no
retry, no fallback, no caching, no orchestration, and never rewrites the
conversation (its only body mutations: the optional model override, and
`stream_options.include_usage = true` on streamed turns).

## Attribution model (#384, extended per-delegate by #427)

- Every turn's tokens accumulate to **one user** (the owning omni) — budgets
  are per-user and enforced deterministically (`429 budget_exceeded`, no LLM in
  the decision).
- Statistics are kept **per-device** and **per-api-key**, and roll up into the
  user-facing summary served by `GET /v1/usage`.
- **#427 (epic #425 decision 6):** a relay key may carry its own
  `budget_tokens` — a per-DELEGATE ceiling enforced UNDER the user budget
  (same deterministic 429; usage still rolls up to the user). The broker mints
  such keys at delegate SPAWN and disables them at ARCHIVE via the admin
  surface below — a delegate *exists* by the chain (agent-slot allowance) but
  is *usable* only while gate-provisioned. Custody + metering only, still not
  a control point.
- Every turn lands on the ledger as a `GateTurn` (op_kind 90) audit row with
  usage + attribution (arch.md §15.3a); every embeddings call as a `GateEmbed`
  (op_kind 93) row (#572). Embed tokens burn the SAME per-user / per-delegate
  budgets as chat and stay visible as their own `embed_tokens`/`embed_turns`
  dimension in the usage rollup.

## Endpoints

| Route | Auth | What |
|---|---|---|
| `POST /v1/chat/completions` | relay key | the proxied turn (streamed + non-streamed) |
| `POST /v1/embeddings` | relay key | #572 embeddings relay (the in-sandbox OpenViking engine points `OPENVIKING_EMBED_API_BASE` here; no raw vendor key in the sandbox) |
| `POST /v1/embeddings/multimodal` | relay key | #639 the multimodal twin — what OpenViking calls for the doubao-embedding-vision family; same auth, metering and budgets |
| `POST /v1/systemone` | relay key | #722 the System One (TypeSafe **Jev**) decision relay — the household router's typed pick (`agentkeys_protocol::SystemOneRequest` in, the vendor's answer body out, verbatim). Metered into the same budgets (`decide_tokens` / `decide_turns`), audited as `GateDecide` (op 95, counts only — never the `state` text). **503 until the `typesafe` family is provisioned**; the contact gate then runs its deterministic tier |
| `GET /v1/models` | relay key or admin | upstream passthrough |
| `GET /v1/usage` | relay key → own user; admin → `?user_omni=` or all | the rollup summary |
| `POST /v1/admin/keys` | admin | #427 provision/rotate a relay key (broker spawn-finalize; secret returned ONCE) |
| `POST /v1/admin/keys/:key_id/disable` | admin | #427 deprovision (idempotent; usage history + row retained) |
| `GET /healthz` | none | liveness — the process answers |
| `GET /readyz` | none | readiness — `503` while the latest upstream answer refused the ACCOUNT (below), `200` otherwise. The fleet board probes this one for the `gate` row |

Admin mutations write-through to the keys file (0600, atomic tmp+rename) so
restarts re-hydrate; with no keys file configured they are in-memory only and
the boot log WARNs.

A relay key id has ONE spelling: a 32-byte hex id (a delegate's
`device_key_hash`) folds to `0x` + lowercase, whichever spelling the broker
sent, so one delegate is one row — a re-provision rotates THE secret and an
archive disables it. Before this, the resolve path (`0x…`) and the #669 wake
(bare hex — the spawn-context store's form) each minted their own live row
(VE prod 2026-09-29: two delegates held two each). Rows written the old way
still authenticate after an upgrade — a live sandbox keeps working — and the
boot log WARNs per split id until its next provision or disable collapses it.

## Reading an upstream refusal

Every refusal is logged with what was refused and why: `route` (the upstream
path), `model`, `status`, and the upstream's own `code` + `message`. A 4xx is
forwarded to the caller verbatim either way.

| Log line | Meaning → action |
|---|---|
| `WARN … upstream 4xx forwarded … code=InvalidParameter` (any code not below) | THIS request was refused — the caller's body, model or budget. Other callers are unaffected |
| `ERROR … upstream 4xx forwarded — the upstream refused the ACCOUNT … code=AccountOverdueError` | the vendor account behind the ark family key has an overdue balance: Ark answers **every** chat and embedding with 403, whatever key calls (measured VE prod 2026-09-21 and 2026-09-28). Top up the Volcano Engine account; nothing to restart — the next upstream 2xx clears `/readyz` (logged `… standing account refusal is cleared`). `GET /v1/models` answers 200 throughout, so it proves nothing |

Account-scoped codes are listed in `src/refusal.rs` (`ACCOUNT_SCOPED_CODES`) —
add one only with a measured answer. Readiness is process-local: a restart
starts `ready`, because nothing is known until a call is made.

## Configuration (env-first; every flag has a `--` form)

| Env | Meaning |
|---|---|
| `AGENTKEYS_GATE_LISTEN` | bind address (default `0.0.0.0:8077`) |
| `AGENTKEYS_GATE_UPSTREAM_BASE_URL` | explicit upstream root override; unset → the **ark family** resolves it (#338: env `ARK_BASE_URL` > `~/.agentkeys/inference/ark.env` > the built-in Ark default) |
| `AGENTKEYS_GATE_UPSTREAM_API_KEY[_FILE]` | explicit vendor-key override (engine-agnostic); unset → the **ark family** resolves it (env `ARK_API_KEY` > `ark.env` — rotate with `scripts/operator/secrets/rotate-inference-cred.sh ark`; inspect with `volcano-probe creds`) |
| `AGENTKEYS_GATE_MODEL` | optional model / Ark endpoint-id override |
| *(default chat model)* | #722 — a chat body that names no `model` runs on the ark family's `LLM_ENDPOINT_ID` (Ark refuses a chat with none: HTTP 400 `MissingParameter`). A named model always rides through; `AGENTKEYS_GATE_MODEL` still overrides both. Callers: the daemon's perception step, the contact gate's photo description |
| *(typesafe family)* | #722 — the Jev relay's key + base resolve ONLY through the `typesafe` inference family: env `TYPESAFE_API_KEY` (the vendor SDK's own name — a laptop `~/.zshenv` export works) > `<creds-dir>/typesafe.env` (`rotate-inference-cred.sh typesafe`); `TYPESAFE_BASE_URL` optional (default `https://api.typesafe.ai`). Unset = the leg 503s, loud at boot. **Kev** ([jaredpalmer/kev](https://github.com/jaredpalmer/kev), an open model with the same API) works unchanged: `TYPESAFE_BASE_URL` = the Kev server (a path prefix is fine — the gate appends `/v1/systemone`), `TYPESAFE_API_KEY` = its `KEV_API_KEY`. Kev answers with whatever model name it is sent, so also set the contact gate's `AGENTKEYS_WEIXIN_ROUTER_MODEL` to the Kev version (e.g. `kev-9b`) — that name is what the audit and the monitor record. The router's thresholds are measured per model: `router-eval` (`crates/agentkeys-worker-channel-weixin`) |
| `AGENTKEYS_GATE_KEYS_FILE` | JSON: relay keys + per-user budgets (below) |
| `AGENTKEYS_GATE_DEFAULT_BUDGET_TOKENS` | default per-user budget; unset = unlimited (still metered) |
| `AGENTKEYS_GATE_ADMIN_TOKEN` | operator bearer for the all-users usage view |
| `AGENTKEYS_AUDIT_URL` | audit worker base for `GateTurn`/`GateEmbed` appends |
| `AGENTKEYS_GATE_REQUIRE_AUDIT` | fail a non-streamed turn whose audit append fails |

Keys file:

```json
{
  "default_budget_tokens": 1000000,
  "users": [
    { "user_omni": "0x<64 hex>", "budget_tokens": 500000 }
  ],
  "keys": [
    { "key": "gk_…", "key_id": "k1", "user_omni": "0x<64 hex>",
      "device_id": "esp32-lcd4b-01", "label": "kid tablet" }
  ]
}
```

## Wiring Hermes through the relay

In the hermes-sandbox `config.yaml` the Ark provider is a generic
OpenAI-compatible entry; point it at the relay and hand the sandbox a relay key
instead of the vendor key:

```yaml
api_base: http://<relay-host>:8077/v1   # was: https://ark.cn-beijing.volces.com/api/v3
api_key: ${AGENTKEYS_RELAY_KEY}          # was: ${ARK_API_KEY}
```

The sandbox env then no longer needs `ARK_API_KEY` at all — rotating the vendor
key touches ONE place (the relay) instead of every live sandbox.

## Deploy (VE broker host — #384 wiring)

Canonical entry is the unified host bootstrap **`setup-broker-host.sh --cloud ve`**
(#376/#381 — it `exec`s the VE implementation, currently `setup-broker-host-ve.sh`,
since the AWS-host lib migration is Stage 3b). Steps 3–6 there (idempotent) build +
install the binary, write `agentkeys-gate.service` (loopback `127.0.0.1:$VE_GATE_PORT`,
ark family via `AGENTKEYS_INFERENCE_CREDS_DIR=/etc/agentkeys/inference`, relay keys at
`/var/lib/agentkeys/gate/gate-keys.json` — skeleton created, never overwritten; a
writable state dir because the #427 admin surface write-throughs every provision,
and `ProtectSystem=strict` leaves `/etc` read-only, #543), and — when
`VE_GATE_HOST` is set — front it with an nginx vhost + Let's Encrypt TLS
(`proxy_buffering off` so SSE streams flow). The A record rides
`setup-cloud.sh --cloud ve` step 55 (same IP as the broker). Bring-up order:

```bash
# DNS (laptop, AWS Route53 profile):
bash scripts/operator/setup-cloud.sh --cloud ve --only-step 55
# host converge (on the VE host, as broker-manager):
bash scripts/operator/setup-broker-host.sh --cloud ve
# then populate creds + start:
AGENTKEYS_INFERENCE_CREDS_DIR=/etc/agentkeys/inference \
  bash scripts/operator/secrets/rotate-inference-cred.sh ark   # key + LLM_ENDPOINT_ID
sudoedit /var/lib/agentkeys/gate/gate-keys.json                 # add relay keys by hand
                                                                # (delegate keys are minted by the
                                                                #  broker at spawn — #427/#543)
sudo systemctl enable --now agentkeys-gate                      # (re)start after either change
curl -s https://$VE_GATE_HOST/healthz                           # → ok
curl -s https://$VE_GATE_HOST/readyz                            # → {"status":"ready"}
```

No audit worker runs on VE yet, so `AGENTKEYS_AUDIT_URL` is deliberately unset
— the gate warns at boot and metering stays process-local (same GAP as the
worker plane; wired the day the audit worker lands there).

## What this crate deliberately does NOT do

- **Action control** — hooks in the Task Host + data-plane caps own that
  (arch.md §22d); an egress proxy cannot deny an agent's tool calls.
- **Memory injection** — the memory story is hub absorption (#339/#341) + the
  `pre_llm_call` hook seam, not egress rewriting.
- **Persistence** — accumulators are in-memory; the durable trail is the
  per-turn `GateTurn` row. Rebuild-on-restart from the audit feed, broker-minted
  relay keys at sandbox spawn (#369/#337), and the ASR/TTS key families (#338)
  are tracked follow-ups in #384.

Smoke-run locally (mock any OpenAI-compatible upstream):

```bash
cargo run -p agentkeys-gate -- \
  --upstream-base-url http://127.0.0.1:9999/v1 \
  --upstream-api-key test-key \
  --keys-file ./keys.json
```
