**Status:** current. **Scope:** the identifiers + data flowing through the §10.2
*method-A* agent-pairing handshake (agent-initiated, replaces the master-minted link
code). Indexed from [`../arch.md`](../arch.md) §10.2. Source of truth for what the
master's pairing UI ([`apps/parent-control/app/_components/pairing.tsx`](../../apps/parent-control/app/_components/pairing.tsx))
shows and why each field is (or isn't) trustworthy.

## The flow at a glance

```
AGENT (no session yet)                 BROKER                          MASTER (J1_master)
  │                                      │                                  │
  │ POST /v1/agent/pairing/request       │                                  │
  │   { device_pubkey, pop_sig } ───────▶│  verify pop_sig (K10)            │
  │                                      │  mint request_id + pairing_code  │
  │   ◀─── { request_id, pairing_code,   │  store UNBOUND row (no master)   │
  │          device_key_hash, … }        │                                  │
  │  • DISPLAYS pairing_code             │                                  │
  │  • stores request_id (state_file)    │                                  │
  │                                      │   POST /v1/agent/pairing/claim    │
  │                                      │◀── { pairing_code, label,         │
  │                                      │       requested_scope } ──────────│  (master enters the code)
  │                                      │  bind row → operator_omni, label, │
  │                                      │  child_omni                       │
  │                                      │                                  │
  │                                      │   GET /v1/agent/pending-bindings  │
  │                                      │── { pending:[ … ] } ─────────────▶│  the pairing UI list
  │                                      │                                  │  ▶ one Touch ID:
  │                                      │                                  │    registerAgentDevice
  │                                      │   POST /pending-bindings/ack ◀────│    + setScope on chain
  │ POST /v1/agent/pairing/poll          │  (drops the row from pending)     │
  │   { request_id, fresh pop_sig } ────▶│  mint + return J1_agent           │
  │   ◀─── { session: J1_agent }         │                                  │
```

## The identifiers

| Field | Minted by | Entropy | Secret? | Displayed by agent | Shown to master | Lifecycle |
|---|---|---|---|---|---|---|
| **`pairing_code`** | broker (`/request`, `random_b64url(18)`) | 144-bit | **yes** until claimed | **YES** (QR / screen) | **yes** (post-claim) | one-time; consumed at `/claim` |
| **`request_id`** | broker (`/request`, `random_b64url(32)`) | 192-bit | **yes** | **no — never** | yes (the `id` handle) | agent's poll ticket; master's ack/register handle; cleared on `bound` |
| **`device_pubkey`** (K10) | agent (its device key) | — (a key) | no (public identity) | yes | yes (`device public address`) | the agent's durable EVM device identity (`0x…`) |
| **`device_key_hash`** | `keccak256(device_pubkey)` | — | no (public) | yes (`--request-pairing` prints it) | yes (`device key hash`) | the on-chain `SidecarRegistry` key |
| **`pop_sig`** | agent (EIP-191 over the pop payload) | — | no (single-use proof) | no | no (only `PoP verified` summary) | proves K10 possession at `/request` + each `/poll` |
| **`operator_omni`** / **`child_omni`** | broker at `/claim` (HDKD from the master) | — | no | n/a | yes | the actor identity the agent binds under |

Notes:
- **`pairing_code` is "whoever holds it binds."** Before the master claims, anyone who
  obtains it can claim the agent under *their* master — so the agent shows it only to the
  intended owner. After `/claim` it is consumed (a second claim fails); the value the master
  sees in the pending list is therefore inert.
- **`request_id` alone is useless.** Polling requires `request_id` **and** a fresh `pop_sig`
  from the agent's K10 key — which only the agent device holds. A leaked `request_id` cannot
  retrieve `J1_agent` without that key (per [`handlers/agent/poll.rs`](../../crates/agentkeys-broker-server/src/handlers/agent/poll.rs)).
- The two are **not interchangeable**: the agent *shows* `pairing_code`; the broker keys the
  binding by `request_id`; the agent *polls* on `request_id`. See [`handlers/agent/request.rs`](../../crates/agentkeys-broker-server/src/handlers/agent/request.rs).

Where they live: the agent persists `{request_id, pairing_code, device_pubkey, expires_at}`
0600 at `~/.agentkeys/pairing-request-<device_pubkey>.json` (the `state_file` in its output);
the broker persists the row in the `pairing_requests` table ([`storage/pairing_requests.rs`](../../crates/agentkeys-broker-server/src/storage/pairing_requests.rs)).

## Supersede — exactly one OPEN request per device (#224)

Opening a request (`/v1/agent/pairing/request`) **first deletes every prior OPEN
(unclaimed) request for the same `device_pubkey`**, then inserts the new one — atomically,
under the store lock ([`PairingRequestStore::issue`](../../crates/agentkeys-broker-server/src/storage/pairing_requests.rs)).
So re-running `agentkeys-daemon --request-pairing` (especially `--force`, or after a lost
local `state_file`) leaves **exactly one** open request for the device instead of letting
duplicate pending cards accumulate — the original incident was two stale `hermes` cards for
one device, differing only by `request_id`.

- **Authenticated, not a DoS vector.** The handler verifies `pop_sig` recovers to
  `device_pubkey` *before* `issue`, so only the holder of the device key supersedes its own
  open requests. The match is case-insensitive on the address (a key may be sent checksummed
  one run, lowercased the next).
- **CLAIMED rows are never superseded.** A claimed-but-unbound row is the master's bind
  queue; a re-request does not silently delete it. A stale claimed row is removed by the
  master via `decline` (or `purge_expired` once its retention lapses), never by an agent
  re-request. (Combined with the supersede of *open* rows, the operator can no longer create
  duplicate **claimed** rows by claiming two simultaneously-live codes — the older code is
  gone before the new one opens.)

## Declared vs attested — the trust line

The master UI groups a pairing request's fields into two columns for a reason:

- **Attested (trustworthy):** `device_key_hash`, `device_pubkey`. These are bound to the
  agent's K10 key, which the broker verified via `pop_sig` *before* storing the request. The
  master **cross-checks them against the agent's own `--request-pairing` output** (#224) — a
  man-in-the-middle can't substitute a device it doesn't hold the key for. `pairing_code` +
  `request_id` are broker-minted handles (not attested, but tamper-evident: a wrong code never
  claims).
- **Declared (NOT trustworthy):** `device`, `machine`, `runtime`. These are **self-reported,
  not attested** — in fact the daemon currently fills them with cosmetic placeholders
  (`"sandbox device (K10)"`, `"aiosandbox"`, `"hermes"`) in
  [`ui_bridge.rs::pending_binding_to_request`](../../crates/agentkeys-daemon/src/ui_bridge.rs).
  They are context only and must **never** be a basis for approval. The UI marks them
  `⚠ declared by the runtime · self-reported, NOT attested`.

**Rule:** approve a pairing on the *attested* identity (device key hash / D_pub, cross-checked
on the agent) — never on the declared labels.

## Is it safe to show these on the master?

Yes, with the reasoning above:

| Shown field | Safe? | Why |
|---|---|---|
| `device_key_hash`, `device_pubkey` | ✅ | public on-chain identity; showing them IS the point (cross-verify, #224) |
| `pairing_code` (post-claim) | ✅ | one-time + already consumed by the time it reaches the pending list — cannot be re-claimed |
| `request_id` | ✅ (low-risk) | insufficient alone — `/poll` also requires the agent's K10 `pop_sig`; the master legitimately owns this handle |
| `device` / `machine` / `runtime` | ✅ to show, ⚠ to trust | cosmetic + unattested — display is fine; the UI flags them so they're never mistaken for verified facts |

The residual hygiene note: `pairing_code` and `request_id` are high-entropy secrets, so the
UI shows them for cross-reference but they should not be copied into logs/screenshots
needlessly — though neither is exploitable on its own once the request is claimed.

## Master-UI field mapping

`PairingRequest` ([`app/_components/types.ts`](../../apps/parent-control/app/_components/types.ts))
← daemon `pending_binding_to_request` ← broker `pending_bindings` row:

| UI field | Source | Kind |
|---|---|---|
| `pairCode` | broker `pairing_code` | broker handle (the agent's real code) |
| `id` | broker `request_id` | broker handle (master ack/register) |
| `deviceKeyHash` / `dpubFull` | broker `device_key_hash` / `device_pubkey` | **attested** |
| `requestedAt` | broker `created_at` (unix s) | timestamp (UI formats it) |
| `expiresAt` | broker `expires_at` (unix s) | timestamp → **live countdown** (#224) |
| `derivation` | `//<label>` | HDKD path |
| `device` / `machine` / `runtime` | daemon placeholders | **declared** (unattested) |
| `attestation` | `PoP verified · <pop_sig head>` | proof summary |

**#224 — the card renders `expiresAt` as a LIVE countdown** (`ExpiryCountdown`, ticks
1 Hz). `expires_at` is the SAME unix second the agent's `--request-pairing` printed
(`created_at + PAIRING_REQUEST_TTL_SECONDS`, 600 s), so a card whose window has elapsed
reads `⚠ expired` — the visible tell that it is a **stale / duplicate** request to
refuse rather than approve. Together with the supersede rule below, this is the fix for
the original incident (two stale `hermes` cards for one device, indistinguishable from
the live one).
