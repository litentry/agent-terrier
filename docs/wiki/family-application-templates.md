How to write a **family application template** — the content bundle the household installs from the parent-control console as one app: a manifest, a persona, skills docs and knowledge docs. It defers to [`../arch.md` §22f](../arch.md#22f-family-applications--the-actor-os-for-the-household-epic-660) for the model; read this when you are authoring or testing a template.

> **The rule that shapes everything here (arch.md §22f, F0/F1):** a template is **content**, never framework code. The framework knows *kinds* — messaging, display, camera; document, profile; `tool:web`, `tool:schedule` — and never household nouns. If your template needs a framework change, that is a framework issue, not a template feature. CI enforces the content-only shape (`scripts/utils/check-template-content-only.sh`) and the broker validates every bundle it compiles in.

## What an application is

**application** = a template (content) ⊗ a grant set (authority the owner signs) ⊗ one delegate (execution). Installing a template spawns a **fresh delegate** whose grant set is *compiled* from the manifest + the owner's bindings — exactly the sheet the console shows, signed by ONE Touch ID. The delegate's AI runtime (DeepSeek Harness with the AgentKeys plugin suite) receives your persona, skills and knowledge as its system-prompt context; everything it may touch is a chain grant the install minted.

The four verbs the runtime gives an app:

| verb | what the app does | how a template uses it |
|---|---|---|
| **perceive** | events from every bound slot arrive as turns — text, `image`, `audio-clip`, `command` | `skills/perception.md` (the R2 pre-turn prompt per media kind) |
| **act** | publish `text` / `doc` / `image` to any bound `pub` slot | the `publish-to-slot <slot> <kind>` helper from a skill |
| **remember** | keyed objects under `memory:app-<label>`; proposals to the owner via `inbox:app-<label>` | conventions in your skills (keys, shapes) |
| **may** | every action is gated by the grant set; a denied tool is a denied tool, never a fallback | `tools`, `schedule`, and what you *don't* ask for |

## Layout

```
presets/<id>/
  preset.json          # the manifest (id · version · names · slots · resources · tools ·
                       #   availability · budgets · schedule · disclosure · context pointers)
  SOUL.md              # the persona layer (the locked base layer is appended by the system)
  skills/*.md          # what the app does — perception.md is the media pre-turn contract
  knowledge/*.md       # reference the app may cite; distributed as `knowledge` context
```

A template is registered in the broker catalog (`crates/agentkeys-broker-server/src/handlers/presets.rs`, the `BUILTINS` table) and compiled in; a new bundle is a broker redeploy, no client release. The reference application is [`presets/chef/preset.json`](../../presets/chef/preset.json); the synthetic template the conformance suite installs is [`presets/conformance/preset.json`](../../presets/conformance/preset.json).

## The manifest

Every field is additive: a pre-existing role preset (no slots, no resources, no `tools`) still parses and compiles to today's spawn template byte-for-byte. The wire shapes have ONE owner, `crates/agentkeys-protocol/src/app_template.rs` (ts-rs generates the console's types from it).

| field | meaning | rule |
|---|---|---|
| `id`, `version`, `schema` | template identity; `schema` is the manifest schema version (`1`) | `id` matches `^[a-z0-9-]{1,32}$` (it doubles as the default delegate label) |
| `name`, `name_zh`, `description`, `description_zh` | bilingual card text | both languages |
| `slots[]` | the channel endpoints the app needs: `slot` (name your skills use), `kind` (`messaging` · `chat` · `display` · `camera` · `mic` · `speaker` · `sensor`), `direction` (`sub` · `pub` · `duplex`), `required`, `event_kinds`, `audience` (messaging only — the default household tiers allowed to reach the app), `reason` / `reason_zh` | slot names `^[a-z0-9_]{1,32}$`, unique; a required slot must be bound at install |
| `resources[]` | read-only curated inputs: `name`, `kind` (`document` · `profile` · `dataset` · `gallery`), `tags` (matching hints), `required`, `sensitivity_floor`, `reason` | a `sensitive` floor requires a `disclosure[]` line naming the model path |
| `tools` | capability classes: `web`, `schedule`, `code` (bare or `tool:` spelling) | **absent = the product default (`web`)**; present = exactly this set |
| `availability` | `always-on` · `wake-on-event` · `scheduled` | a template with `schedule[]` needs `scheduled` (or `always-on`) so its ticks fire |
| `budgets` | `gate_tokens_per_day`, `gate_turns_per_hour`, `feed_events_per_day` | each ≤ the platform cap |
| `schedule[]` | `cron` (5-field, household local time), `label`, `label_zh`, `prompt` | requires `tool:schedule`; the runtime fires each entry as a clock turn and replies on the app's opchat feed |
| `disclosure[]` | "what leaves your home": `data` → `path` (bilingual) | shown on the install sheet verbatim |
| `context` | which files are the persona / skills / knowledge | every name must exist in the bundle |
| `hidden` | list only on a test stack (`AGENTKEYS_CATALOG_INCLUDE_HIDDEN=1`) | the conformance template only |

What the compiler mints from it (the sheet the owner signs) — for a template installed as label `L`:

- always: `channel-pub:opchat-L` + `channel-sub:opchat-L` (the owner's chat), `memory:app-L`, `inbox:app-L` (an application always has an inbox), `plugin:openviking`;
- per bound messaging slot on transport `T`: `channel-sub:T-L` and/or `channel-pub:T-L` by direction — **and the contact gate's own device actor is granted the mirror direction in the same Touch ID** (and registered in that same Touch ID if it was not enrolled yet), so the family's messages can land on the feed and replies can go back;
- per bound display slot `D`: `channel-pub:D` (and the console's device actor gets pub+sub to render the card and tap it);
- per bound resource: `memory:<ns>` (read-only — never an inbox on that namespace);
- `tool:<class>` for each declared tool class.

## Perception — `skills/perception.md`

A media event (a photo, a voice clip) becomes a **pre-turn** the runtime runs before the agent's turn: the adapter reads the ORIGINAL bytes by reference (never downscaled), sends them to the gate's vision / ASR model with the prompt from your `perception.md` (the `## image` / `## audio-clip` sections), and hands the JSON result to the turn as context. Your prompt must ask for strict JSON and may set `needs_closer_look: true` with a hint — the runtime then asks the contact for a closer photo instead of letting the agent guess. Keep the contract small; the framework never reads the fields, your skills do.

## The card — `doc` events on a display slot

An app publishes one versioned, bilingual **card** document (`card: 1`, `application/vnd.agentkeys.card+json`) to its display slot: `title`, `metrics` (with an optional `progress`), `sections` of items, `alerts`, and `actions`. Every renderer — the console, a shared kitchen tablet, the ESP32 — draws the same card and publishes a tapped action back as a `command` event **from its own device actor**; the app receives it as a turn (`command:<name>`). The schema's one owner is `crates/agentkeys-protocol/src/card.rs`; the golden fixtures under `e2e/fixtures/cards/` are rendered by every renderer's test. Publish with `publish-to-slot <display_slot> doc application/vnd.agentkeys.card+json < card.json`.

## Testing a template

1. `bash scripts/utils/check-template-content-only.sh` — content-only shape, ids, context pointers.
2. `cargo test -p agentkeys-broker-server presets` — the manifest validates (every slot / resource / tool / schedule rule) and the catalog lists it.
3. `cargo test -p agentkeys-protocol app_template` — the compiler's pinned grant sets; add a pin for your template if its sheet matters.
4. `bash e2e/suite.sh --stage 8` — the conformance phase against a live stack: catalog, compile, resources, registries, and the install → inspect → uninstall cycle through `agentkeys app install|show|uninstall` (with the software passkey; the console does it with Touch ID).
5. A headless install of YOUR template: `agentkeys app install --template <id> --label <label> --bind "<slot>=<channel-id>,…" --resource "<name>=<item-id>" --k11-key-file <software passkey> --rp-id <rp>` (CI / test masters only — a real owner installs from the console).

## Install from the console

parent-control → **applications**: pick the template, bind each slot to a registered channel of the right kind (the contact gate's transport — the WeChat iLink bot or Telegram — is the messaging endpoint; the first install that binds it enrolls the contact gate as a device actor in the SAME Touch ID, and a display slot enrolls this console the same way — the **endpoints** tab is the standalone way), bind knowledge items curated on the **Knowledge** page, confirm the audience, review the compiled sheet, Touch ID. The dashboard shows the app's activity, the live card (taps publish `command` events from the console's device actor), the minted sheet, bindings and schedule. **uninstall** revokes every grant (the delegate's and the endpoint actors' on its feeds) and returns the slot; keeping the memory namespace lets a reinstall inherit it.
