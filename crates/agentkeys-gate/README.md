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
  usage + attribution (arch.md §15.3a).

## Endpoints

| Route | Auth | What |
|---|---|---|
| `POST /v1/chat/completions` | relay key | the proxied turn (streamed + non-streamed) |
| `GET /v1/models` | relay key or admin | upstream passthrough |
| `GET /v1/usage` | relay key → own user; admin → `?user_omni=` or all | the rollup summary |
| `POST /v1/admin/keys` | admin | #427 provision/rotate a relay key (broker spawn-finalize; secret returned ONCE) |
| `POST /v1/admin/keys/:key_id/disable` | admin | #427 deprovision (idempotent; usage history + row retained) |
| `GET /healthz` | none | liveness |

Admin mutations write-through to the keys file (0600, atomic tmp+rename) so
restarts re-hydrate; with no keys file configured they are in-memory only and
the boot log WARNs.

## Configuration (env-first; every flag has a `--` form)

| Env | Meaning |
|---|---|
| `AGENTKEYS_GATE_LISTEN` | bind address (default `0.0.0.0:8077`) |
| `AGENTKEYS_GATE_UPSTREAM_BASE_URL` | explicit upstream root override; unset → the **ark family** resolves it (#338: env `ARK_BASE_URL` > `~/.agentkeys/inference/ark.env` > the built-in Ark default) |
| `AGENTKEYS_GATE_UPSTREAM_API_KEY[_FILE]` | explicit vendor-key override (engine-agnostic); unset → the **ark family** resolves it (env `ARK_API_KEY` > `ark.env` — rotate with `scripts/operator/secrets/rotate-inference-cred.sh ark`; inspect with `volcano-probe creds`) |
| `AGENTKEYS_GATE_MODEL` | optional model / Ark endpoint-id override |
| `AGENTKEYS_GATE_KEYS_FILE` | JSON: relay keys + per-user budgets (below) |
| `AGENTKEYS_GATE_DEFAULT_BUDGET_TOKENS` | default per-user budget; unset = unlimited (still metered) |
| `AGENTKEYS_GATE_ADMIN_TOKEN` | operator bearer for the all-users usage view |
| `AGENTKEYS_AUDIT_URL` | audit worker base for `GateTurn` appends |
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
`/etc/agentkeys/gate-keys.json` — skeleton created, never overwritten), and — when
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
sudoedit /etc/agentkeys/gate-keys.json                          # add relay keys
sudo systemctl enable --now agentkeys-gate                      # (re)start after either change
curl -s https://$VE_GATE_HOST/healthz                           # → {"ok":true,...}
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
