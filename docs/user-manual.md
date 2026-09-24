# AgentKeys — User Manual

The single home for **user-facing behaviors and instructions** — the things an
operator or end user needs to know about how AgentKeys touches their machine.
(Developers: see [`arch.md`](arch.md).)

> Convention: every user-aware instruction or caveat lives here. If a change
> alters something a user would notice, document it in this file.

## Your agent's long-term memory: OpenViking, bounded by your grants (#566)

Inside every AgentKeys sandbox, the agent uses **OpenViking as its native
memory provider** (the official dsh memory plugin: a recall before every
step, plus the `mcp__openviking__*` search / read / write tools). Two kinds of
content live in that engine, named the way OpenViking names them, and what
the agent can *recall* of your family's knowledge is bounded by **your
grants**, not by the agent's choices:

- **Resources = knowledge you granted.** Every item of a knowledge namespace
  the application may read (a food-preferences profile, a gene report, a
  device's static files) is mirrored by the AgentKeys **daemon** into the
  engine's `resources/` as a small directory: an abstract and an overview made
  from the item's **title and preview**, and the body itself. Before each turn
  the agent's recall shows it the overview of the relevant resources (up to
  three), and it reads the body when it needs it — so curate the title and
  preview on the Knowledge page: they are what the agent sees first. The
  daemon is the only writer of granted knowledge, and it can only mirror
  namespaces the memory worker authorizes — a namespace you never granted (or
  later revoked) answers 403 at the worker and never enters the engine; a
  revoked one leaves at the next pass (every five minutes, or on "sync now").
- **Memories = what the agent itself learns.** Its diary, inventories and
  learned preferences are files it writes into the engine's `memories/`
  category folders (`events/`, `entities/`, `preferences/`). They live only in
  that sandbox (checkpointed, so an update or relaunch keeps them) and never
  reach another application. The engine's automatic extraction (`remember`)
  is not enabled in the sandbox, so the files the agent writes are its memory.
- **A learning crosses to you as a proposal.** When the agent judges a
  learning durable — a standing preference you stated, a household fact — it
  sends it with its `propose_to_owner` tool into your review queue (rate- and
  size-limited). Accepting it on the Knowledge page makes it an item of the
  namespace you choose; every application granted that namespace then receives
  it as a resource. Nothing an agent learns enters shared knowledge without
  that acceptance. See the wiki page *Knowledge Store and Applications*.
- **A grant request reaches you the same way.** When an application tries a
  capability it was not granted (say web search without the web capability),
  the call is denied on the spot and a *grant request* lands in that
  application's review queue — at most one per capability every ten minutes.
  Approve the capability from the permissions page (the toggle mints the
  grant; the next attempt passes without asking), or ignore the request to
  keep the denial. Nothing is granted by the request itself.
- The memory engine is **never load-bearing**: if it is down or not enabled,
  the agent falls back to its built-in memory and chat keeps working.

Operators: enabling semantic search requires an explicit embedding model
(the embed key/base default through the model gate relay on gate-provisioned
stacks) — see the OpenViking operator runbook (`operator-docs/`, not in
the OSS mirror).

## Onboarding asks for Touch ID twice (parent-control)

The first-run ceremony prompts **Touch ID twice with the same passkey**: once at
**"Bind passkey (K11)"** to *create* it, and once at **"Register master
P256Account on chain"** to *authorize* its on-chain registration. The second
prompt is expected — not a retry or an error — and the progress bar shows which
step each prompt belongs to.

The register step then waits for the on-chain confirmation, which on Heima takes
**~10–30 seconds** — the step sits on "running" while `handleOps` lands. The page
also polls the daemon's onboarding state in the background, so the ceremony
advances as soon as the chain reports the master registered even if the in-flight
request is lost (#232); no reload needed. If nothing confirms within ~2 minutes
the step gives up and the ceremony continues — check the daemon logs /
`GET /v1/onboarding/state`, then re-run onboarding (it is idempotent: an
already-registered master is detected and never re-bound).

## Setting up your categories (parent-control)

Onboarding ends with a **"Set up your categories"** step (right after you bind
your passkey): pick a starting profile and your taxonomy is authored before you
connect any agent. You can **skip** it there and do it later — the **Knowledge** page
offers the same setup whenever your taxonomy is empty. Either way you author your
**category taxonomy** — the vocabulary agentKeys uses to scope everything an agent
can touch: the **knowledge** it reads (`knowledge:<namespace>`), the **credentials** it
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

## Staying signed in across app restarts

Once you've onboarded, restarting the desktop app — or a developer rebuild that
relaunches the daemon — keeps you signed in. Your master session is saved locally
(your public account coordinates plus the short-lived session bearer — **never a
private key**) at `~/.agentkeys/daemon-<wallet>/master-session.json`, owner-only
(`0600`), and restored on launch, so the memory and credentials pages keep working
with **no prompts**.

If the session has expired since you last used it, you're asked for a **single**
Touch ID re-authentication — not a full re-onboarding. Your **agents survive
restarts too**: the actor page rebuilds itself from the chain (the master plus
every bound agent device; revoked ones excluded), so a daemon restart never
shows an empty fleet that is actually still bound.

**Signing out** (the logout button) drops the session but **remembers who you
are**: your on-chain master binding and your passkey are untouched, so the login
screen offers **"Sign back in with Touch ID"** — one prompt, zero emails. Your
passkey signs a fresh challenge and it's verified against your **on-chain master
account** (the chain is the credential registry, not a server-side password
table). You can always pick **"sign in with a different email"** instead — that
is a fresh, separate account.

The real forget-this-machine action is **reset master** (the reset button): it
clears the saved identity AND the on-chain binding so a fresh passkey can
re-onboard, **and it tears down your whole fleet** — every paired agent's
on-chain device binding is revoked, every pending pairing request is declined,
and the local agent list is cleared, so a re-onboarded master starts clean and
re-pairing an old agent requires a fresh pairing ceremony. **If you have paired
agents, the reset asks for ONE extra Touch ID first**: only your master account
can revoke its agents on chain, so the reset batches every revoke into a single
approval *before* the master binding is destroyed (afterwards nobody could
revoke them). Cancelling that prompt cancels the whole reset — nothing is
unbound, your agents stay connected, and you can simply retry. The confirm
dialog states exactly how many agents and pending requests it will disconnect,
and the result message spells out anything that could **not** be torn down
remotely (e.g. the chain helper isn't configured) so a partially-disconnected
fleet never reads as fully disconnected. **A reset is refused when your broker
cannot re-register a master right now** (its sponsored-register path answers
503): unbinding is first-master-final, so completing the reset would strand
your identity with no master anywhere and no way to re-onboard on that stack —
fix the broker (or run the reset from a stack whose broker can re-register)
and retry. After a reset, Touch ID sign-in is gone until you onboard again. (You no longer need the
`--master-device-key-hash` developer flag for the normal web loop — the device
is recovered from your account automatically.)

## Switching stacks — your sign-in is per (chain, broker) (parent-control)

The app talks to exactly **one stack** — a (chain, broker) pair — per daemon
launch: Heima-AWS, Base-AWS, or Heima-VE (the Volcano Engine mirror serves the
**same Heima chain** through a **different broker/data plane**). The **chain
page** lists every stack the operator's environment knows, marks the one your
daemon is running (**active**), and shows a live health flag per broker — a
stack whose broker isn't up yet (Heima-VE until its rollout completes) reads
**degraded**. Switching is not a button in the web app: relaunch the dev stack
on another stack (the fleet console's `c` picker, or
`AGENTKEYS_CHAIN=… AGENTKEYS_BROKER_URL=… bash dev.sh`) and reload.

Your browser sign-in state (passkey pointer + onboarding flag) is kept
**separately per stack** — switching Heima-AWS → Heima-VE shows that stack's
own login screen instead of offering the other stack's identity, and **reset
master wipes only the active stack's** pointers. Same chain, different broker
⇒ different session; nothing leaks across, in either direction.

Deeper than the browser slot: your **identity itself is per stack**. Each
broker derives your account (the *omni*) inside its own namespace
(`client_id`, #464) — the same email or wallet is a **different omni** on
Heima-AWS (`agentkeys`) than on Heima-VE (`agentterrier`), even though both
stacks share the Heima chain. So opening a second stack for the first time is
a **fresh onboarding with a fresh master** — the other stack's master is a
different account and is never "already bound" there; each stack's master is
registered (and reset) independently, with no collisions on the shared
registry.

If a stack's broker isn't ready to register a master yet (its sponsored-register
service hasn't been set up — the normal state for a stack still being brought
up), onboarding stops **before** creating a passkey and shows **"The broker
can't register a master yet"** with a **Retry**. This is deliberate: a passkey
can only be registered *after* it's created, so minting one against a broker
that can't register would leave an unusable passkey in your keychain and the
second Touch ID would never come. Because the check runs first, nothing is
created and nothing is stranded — retry once the operator finishes bringing the
broker up. (If you onboarded a few times on an older build before this, delete
any stray *AgentKeys master device* passkeys in System Settings ▸ Passwords.)

Within **one stack**, if the master is bound on chain but the browser holds no
passkey pointer (new browser profile, cleared storage, second browser),
onboarding offers **"Sign in with the existing passkey (Touch ID)"** — the
picker lists your device's passkeys, your choice is verified against the
on-chain master account, and the pointer is saved. One Touch ID, no reset. The
same sign-in also self-heals a **stale** pointer (bound passkey changed by a
re-onboard elsewhere): if the saved passkey is rejected, the app retries once
with the full picker. **Reset master is the last resort** — only for a passkey
that is gone from every device: it unbinds that stack's on-chain master for
every browser (and is refused while the broker cannot re-register, so it can
never strand you).

## Pairing an agent + granting its permissions (parent-control)

When you accept a pairing, the request card shows a **grant permissions picker**:
every namespace the agent asked for comes **preselected** (an agent that asked
for "memory" generally preselects all of your namespaces), and you can check or
uncheck before approving. The single **accept · Touch ID** then performs BOTH
acts on chain in one block — the device binding *and* exactly the scope grants
you selected. The permissions panel reflects the real on-chain grant immediately
afterwards; there is no separate "now open permissions" step. Unchecking
everything is allowed but never silent: the app asks you to explicitly confirm a
zero-grant bind (the agent would be denied everywhere until you grant later).

To change a bound agent's permissions later, open its actor page: the memory
toggles **stage** your changes (nothing happens on chain yet), then a
**commit · Touch ID** bar lands them as one on-chain `setScope`. Two things to
know about that commit:

- The on-chain grant carries a **single read-only bit for the whole set** — if
  any staged namespace is read+write, the committed grant is read+write for
  every granted namespace. The staged bar tells you which it will be before you
  Touch ID.
- The commit **replaces** the grant set on chain, but the app preserves grants
  it can't show in the memory list (e.g. an agent's `cred:<service>` from
  pairing) — toggling memory namespaces never silently revokes credentials.

Discarding the staged bar (or navigating away) leaves the chain untouched. If
the panel ever shows DENY everywhere, that *is* the real on-chain state — use
the toggles + commit to re-grant.

**Unpairing an agent also prompts Touch ID.** The registry only accepts the
revoke from your master account itself, so "unpair · revoke on-chain" (or
"revoke device" on the actor page) builds the revoke, asks for one Touch ID,
submits it, and marks the agent revoked only after re-reading the registry —
if the prompt is cancelled, the device stays bound and nothing changes.

**A pending pairing request does NOT survive a broker restart — re-request it.**
Before you accept, the request lives only in a short-lived rendezvous (it also
expires on its own countdown). If it vanishes (broker restart / expiry), nothing
is wrong: have the agent run `--request-pairing` again and claim the fresh code.
Everything **accepted** is durable — the binding is on chain, and the app keeps
each paired actor's name, delegate-vs-device kind and granted service names in
your encrypted config store, so devices stay on the devices page with their
channel chips intact across app and broker restarts (#424).

## Updating an agent to a new runtime image (parent-control, #577)

When a new agent runtime image ships, the Delegates page shows an
**"update available"** chip on each agent still running the old one, plus an
**"update N stale agents"** button when several are behind. One click on
**"⟳ update runtime"** (no Touch ID — nothing changes on chain) replaces the
agent's sandbox in place:

- **Kept:** its identity, permissions, chat channel, persona (SOUL.md), skills
  docs, and everything in its canonical memory + config (those live in the
  workers and never leave them).
- **Carried over:** its open conversations. The old sandbox hands its working
  files, open sessions included, to the new one; when that hand-off misses,
  the next message rebuilds the recent exchange from the chat history (see
  [Conversations and the New session button](#conversations-and-the-new-session-button)).
- **Guarded:** if the agent has background jobs running, the update refuses
  and tells you — click **"update anyway"** only if losing their output is
  acceptable.

The button reads its own state. **"✓ up to date"** (disabled): the agent
already runs the current image — nothing to do, and its sandbox is replaced
automatically before its lease ends. **"⟳ update runtime"**: it runs older
bits. **"▶ wake"**: nothing is running — a scheduled application sleeps
between its ticks, and an agent whose re-create failed has no runtime either;
wake re-creates it now (a cold start, up to about two minutes). The card's
**runtime** row always says which: the image tag and engine when a sandbox is
live, "none" when not — the lifecycle chip next to the name reads "no runtime"
then instead of the sleeping sandbox's last report. Asking an application for
a card from the Applications page wakes it first when needed. **Archive** remains the separate, Touch-ID-gated action for actually
retiring an agent — updating never archives.

Each agent's card also shows what is actually running: a **runtime** row with
the live engine + version its sandbox reports (e.g. `dsh` —
hover for the LLM endpoint), and a **sandbox** row with the instance id,
status, and when its lease expires. These reflect the RUNNING instance, not
what was last shipped — so after an update you can see the new version took.

Updating an agent that was spawned before this feature still works; the app
just notes that its old runtime couldn't hand its on-disk files over
("session export unavailable") — that heals from the next update onward.

## Your agent survives its sandbox's daily lifetime (#594)

An agent's sandbox has a fixed maximum lifetime (about a day on the hosted
runtime — the **sandbox** row on its card shows when the current lease
expires). You don't have to do anything about it:

- **It relaunches itself.** Shortly before the lease ends, the system rotates
  the agent onto a fresh sandbox (waiting for background jobs when it can);
  if a sandbox dies anyway — expiry, crash — the next sweep brings it back.
  Your operator can turn this off per stack, in which case the "⟳ update
  runtime" button on the agent's card is the manual "bring it back" action.
- **Its workspace survives.** The agent periodically saves a **checkpoint**
  of its working files (persona, skills, notes it keeps in its home
  directory) into its own protected storage, and every fresh sandbox restores
  the latest checkpoint at boot. Only the agent itself can read or write its
  checkpoint — it lives under the same permission your pairing grant already
  gave it, encrypted at rest.
- **Open conversations carry over.** A planned move hands the open sessions
  over directly, as an update does. When a sandbox died instead, the new one
  restores them from the latest checkpoint (saved every 15 minutes by
  default), so the last few messages may be missing from the session; when
  nothing could be restored, the first message rebuilds the recent exchange
  from the chat history.

## Conversations and the New session button

What your agent keeps in mind during a conversation depends on where a
message came from. Each kind of trigger gets its own session:

| Where the message came from | What the agent sees of the conversation | When the session ends |
|---|---|---|
| Your chat in the console | your recent back-and-forth | after a day of silence, or **New session** |
| Voice on your chat (a device) | the current spoken exchange | after 2 minutes of silence |
| A family member on WeChat | that member's own recent messages, never another member's | after 30 minutes of silence |
| A tap on a card (the kitchen screen) | the card that was tapped | with the reply: every tap starts fresh |
| A camera, microphone or sensor event | only that event | with the reply |
| A scheduled run (the morning plan) | nothing from earlier runs | with the reply |

None of this limits what the agent knows long-term. Its granted memory and
knowledge, its persona and skills, and the application's settings apply in
every session. Anything the agent must remember beyond one session, such as
"no dish from the last three days", it writes into its memory rather than
relying on a conversation.

**New session**, next to **Send** in the chat, ends every open conversation
of the agent: your chat, the family members' threads, and a device talking to
it directly. The next message starts fresh. A "— new session —" divider
marks the point, and the earlier messages stay readable. Nothing else
changes: memory, knowledge, persona, skills and the application's settings
all stay.

An application's template may give a slot or a scheduled run a different
kind of session, for example one shared conversation for the whole family
chat. A session can outlast at most a week of silence.

## Editing your agent's persona + config files (parent-control, #390)

A bound agent's actor page carries an **agent** panel showing the files that
shape it, and letting you edit the ones that are yours to edit:

- **`SOUL.md` (the persona)** — fully yours. Edit it in the panel and **save**:
  it is validated (size cap, nothing secret-shaped like API keys or private
  keys, and it may never claim to *be* AgentKeys — AgentKeys is the key layer,
  the agent is the assistant), stored **versioned** (the last 5 versions keep a
  **roll back** button), and — when a sandbox is connected — applied **live**:
  the agent re-reads it and your very next chat turn speaks under the new
  persona. If no sandbox is connected the save still succeeds and says so
  plainly (`stored canonically; applies at next spawn`) — never a silent
  partial success.
- **`AGENTS.md` / `agent-terrier.md`** — the "how we work with AgentKeys"
  context. The **agent-terrier.md base layer is locked**: it is always appended
  to the agent's context and you cannot edit it (it's what keeps pairing,
  permissions, and companion-app handoffs working). The section above it is
  owner space.
- **`config.yaml`** — view-only (secret-shaped values are redacted).

Two behaviors worth knowing:

- **↻ restart agent (re-source)** reloads all context files. Open
  conversations continue with the new persona and skills; to start a fresh
  one, use **New session** in the chat. Saving a persona does this restart
  for you.
- **Delegates cannot write personas.** An agent may *propose* memories or
  skills into your inbox, but a persona proposal is never adoptable — the
  inbox shows it as `not adoptable`; personas are authored only here. Skill
  proposals add one guard: the **accept button stays disabled until you've
  viewed the body** (skills steer behavior, so review is mandatory).

## Dev stack: a red "Failed to connect to MetaMask" overlay (harmless)

If you run the dev stack (`dev.sh`) with the MetaMask extension installed, the
first page load can show a red Next.js error overlay: *"Failed to connect to
MetaMask"* with a `chrome-extension://…/inpage.js` call stack. That error is
MetaMask's own injected script failing to wake its service worker — AgentKeys
never uses MetaMask or `window.ethereum` (identity is your passkey). The dev
overlay simply surfaces *every* unhandled rejection on the page, including
extension ones; production builds have no overlay. Dismiss it (✕) or set
MetaMask's site access to "On click" for localhost. It typically doesn't
reappear on refresh, and nothing in the app is affected.

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
**Storing is master-only too (single-vault):** your vault is the *only*
credentials vault — agents cannot store credentials of their own (the broker
rejects it with `cred_store_not_master_self`), so an agent can never quietly swap
in a key you didn't authorize, and everything an agent can use is always visible
on this page. If an agent acquires a new key (e.g. via a signup flow), vault it
here yourself and grant the scope.

**Default-key selection (#216).** The on-chain scope stores only a
`keccak(service)` hash, so it can *verify* a service name but can't *enumerate*
names or mark a default. So an agent's authorized service NAMES + your designated
default LLM key live in an **off-chain manifest** (`agentkeys cred manifest
--services openrouter,anthropic --default openrouter` — public names only, never a
secret). The agent then reads them: `agentkeys cred list` shows its authorized
services, and a bare `agentkeys cred fetch` (no service argument) pulls the
**master-designated default** — the no-UI path a screenless device relies on
(`--select N` overrides to the Nth authorized service). Every fetch still
re-verifies the `cred:<service>` scope on-chain, so the manifest is discovery only
and never widens what the agent can reach.

**Default-key selection (#216).** The on-chain scope stores only a
`keccak(service)` hash, so it can *verify* a service name but can't *enumerate*
names or mark a default. So an agent's authorized service NAMES + your designated
default LLM key live in an **off-chain manifest** (`agentkeys cred manifest
--services openrouter,anthropic --default openrouter` — public names only, never a
secret). The agent then reads them: `agentkeys cred list` shows its authorized
services, and a bare `agentkeys cred fetch` (no service argument) pulls the
**master-designated default** — the no-UI path a screenless device relies on
(`--select N` overrides to the Nth authorized service). Every fetch still
re-verifies the `cred:<service>` scope on-chain, so the manifest is discovery only
and never widens what the agent can reach.

## Audit receipts (parent-control)

Every Touch-ID chain action — **accepting an agent**, **committing a scope
change**, and **unpairing a device** — now returns **audit receipts**: the
`AuditEnvelope` hashes the broker recorded for exactly what landed on chain
(an accept yields two — the device bind + the scope grant). You'll see them
in the success toast and on the matching row of the **audit** page.

Opening a receipt-carrying row's **decode** view shows the **real** audit
envelope, fetched from the audit worker by hash (a green "real" banner;
verify independently with
`curl https://audit.litentry.org/v1/audit/envelope/<hash>` —
`keccak256` of the returned CBOR must equal the hash). Rows without receipts
(older events, off-chain actions) keep the amber "preview decode" banner —
the shape is real but the values are reconstructed, not fetched. If the
audit worker is unreachable, a receipt-carrying row degrades to the preview
banner instead of failing.

Scope grants are **set-replace**: the envelope's `service_ids` list is the
FULL replacement grant (an empty set is the revoke-all), so compare two
consecutive grant envelopes to see what changed.

## Channels — how devices and family reach your agents (#404)

AgentKeys separates *who runs* (agents/delegates, which live in cloud sandboxes)
from *how information reaches them* (**channels**). Two things you'll notice:

**Devices are channel endpoints, not agents.** When you pair a device — a
camera, a display, the ESP32 console — its claim attaches **one or more
channels** (a camera gets a *publish* channel; a display gets a *subscribe*
channel; the console gets both). A device **never** runs an agent and **never**
gets memory or credential access — it can only publish to / subscribe from the
channels you grant it. If you try to pair a device with **no** channel, the
accept card won't let you (a device with no channel is inert). Pairing a device
**does not** spin up a sandbox — only adding a *delegate* does.

**The household section has four pages — one per kind.**

- **delegates** — pair + manage *agents* (sandbox delegates): claim the code,
  pick memory namespaces, one Touch ID. Only delegates have a persona
  (`SOUL.md`) and memory scopes.
- **devices** — pair + manage *AI devices* (camera, display, console): claim
  the device's code **with a channel attachment selected from the registry**
  (publish / subscribe per channel), review its accept card (which refuses to
  accept with zero channels), and manage bound devices — their channel chips
  and **edit channels → commit · Touch ID** (set-replace: devices hold *only*
  channel grants; removing every channel is refused — unpair instead). A
  device's actor page shows binding + channels only — no persona, no memory:
  a device is a conduit, not a runtime.
- **channels** — the **channel registry**, the only place channels are
  created, renamed, or deleted. The **channel id is the immutable anchor**:
  it is exactly what the on-chain `channel-pub/sub:<id>` grants hash, so it
  never changes even when you rename the display name. Pairing never creates
  a channel silently — the devices page *selects* from this registry (its
  inline "new channel" button is the same explicit create). Deleting a
  channel is refused while any device/agent still holds a grant on it.
  Entries nobody holds any more (an unpaired device's feed, an uninstalled
  app's chat) show as **orphaned**; the **clear orphaned** button at the
  top removes all of them in one click and one write — entries still in
  use are kept, and the toast says which. It is greyed out when nothing is
  orphaned, and the app refuses (just retry) until it has re-read your
  fleet from the chain, so a chain hiccup can never wipe the registry.
- **contacts** — the WeChat contact gate + your family (tiers, reach, invites).

If you claim a device and then look on the delegates page, you'll find a
banner pointing you to devices — device claims never render there. Every
essential action (bind, channel grant change, unpair, registry-backed
re-grant) returns the same on-chain **audit receipts** as agent pairing,
visible on the audit page.

Because the registry remembers every channel id, the app can re-derive a
device's channel *names* from the on-chain grant hashes even after a daemon
restart — a device only reads "grants on chain (names pending)" if its ids
were never registered here.

**The WeChat contact gate (called the "gateway" until 2026-09-09) lets your family reach agents by chat — one clawbot per family member.** A clawbot is a special contact that lives only in the WeChat account that scanned its QR, so each member gets their own: you first, then everyone you invite. Each family member is a **contact** you add in parent-control with a **tier** (`owner / partner / elder / kid / helper / guest`) and a **reach** (which agents they may talk to; pre-filled per tier, and every app you install later adds itself to the tiers it admits). To route, they either type `/<agent> …` (e.g. `/chef 今晚吃什么`) or just ask — the contact gate's router picks an agent **only from that contact's reach**. When the stack has a decision model (TypeSafe's Jev, reached through the model gate), a plain message goes to the app it belongs to («今晚吃什么» → chef, «讲个故事» → storyteller); the app the member last talked to is context, not a rule, so a follow-up stays with it while a message that clearly asks for another app goes there. When the model isn't sure, the member gets a numbered ask («你是想找 1 chef 还是 2 storyteller？回复 1 或 2，或用 /别名») and their reply — the number, the name, or `/alias` — delivers the original message; an ask expires after ten minutes. When the model is unavailable (no key yet, the gate down), the router falls back to today's rule: a message routes only when it names exactly one of their apps as a word, otherwise it asks them to use `/alias`; the monitor shows which tier answered. It **can never** reach an agent you didn't grant them, no matter how a message is phrased. Privacy note: with the decision model on, the text of each plain message (and the member's tier) is sent to TypeSafe, a US-hosted service, to pick the destination; nothing about the message is stored in the audit trail beyond a hash, the decision and its confidence.

**Connecting is a scan, and the invite is the approval.** In parent-control's Contacts page, step 2 is *you*: mint your code and scan the connect QR with your **own** WeChat — your clawbot appears and you are bound as the owner. Step 3 is the family: mint an invite (name, tier, reach), then open their connect QR when they are with you; they scan it with **their own** WeChat, their clawbot appears, and they are bound with the tier and reach you chose — nothing else to confirm. They get «✅ 绑定成功…» in the new chat: right away when the bot can already reach them, otherwise as the reply to their very first message (a brand-new clawbot cannot speak first). It is sent exactly once; the Contacts page shows who has been told. Their WeChat identity is never shown to you or anyone (you manage them by the name and tier you chose). On the code-based transports (a 公众号 or Telegram) the older flow applies instead: the member texts a 6-digit code to the shared bot and you approve the claim. One thing to know: each member's own WeChat account hosts their bot, and Tencent's policy for personal accounts on this API is undocumented.

Three things the contact gate will not do, by design:

- A **stranger's** message (an openid you haven't added) is silently dropped.
- A **kid** (or any contact) asking an agent outside their reach is refused.
- **Anyone** asking for operator-grade data over chat ("what did we spend this
  week?") gets a **parent-control deep-link**, never the numbers — money/usage
  data needs *your* sign-in, never a matching WeChat account. Kids asking are
  simply refused.

**Contacts see no history.** A family member only ever gets live replies
addressed to them, or an agent's answer from its own memory ("did the kids come
home?" → the doorkeeper answers). **All** of the chat log, every contact, and
every routing decision live **only in parent-control** — you have full
visibility; contacts have none. There is no in-chat "this was logged" notice.

**Your contact list survives a contact gate rebuild (#424).** Every contact change
you make in parent-control (invite / approve / rename / revoke) is also saved
into your encrypted config store; if the contact gate host is ever rebuilt, opening
the contacts page restores the whole list automatically. Only an **unapproved**
claim (someone sent the bind code but you hadn't approved yet) is lost — they
just send the code again. The message history and activity views read the
contact gate's own log files, so a host rebuild starts them fresh (their durable home
is a follow-up); the bind/approve/revoke *actions* themselves anchor on-chain in
your audit trail once the operator arms the contact gate's audit identity — if the
audit section shows no contact gate rows, that arming is the missing step (ask your
operator; the contact gate status card shows whether on-chain audit is armed).

## Migrating an older device-rooted delegate (#369 → channels)

If you paired a device under the older model (where the device's key rooted a
delegate directly), re-pair it once under the channels model — the device
becomes its own endpoint (with channel grants) and the delegate roots in its own
sandbox. After your household finishes migrating, the operator may retire the old
delegation path; a stale device still on it gets a **loud, actionable error**
("delegation is retired — re-bind this device") rather than a silent failure, so
you know to re-pair it.

## Applications — install a household app with one Touch ID (parent-control, #660)

An **application** is a household use case packaged as content — a manifest, a
persona, skills and reference docs — that runs as its own delegate with exactly
the permissions you approve. parent-control → **applications**:

- **Install.** Pick a template from the catalog, bind each slot the app needs
  to one of your registered channels (the family chat goes through the
  WeChat / Telegram contact gate; a display is a paired screen), bind any curated
  resources it may read, confirm who in the household may talk to it, then
  review the **sheet** — every grant the app gets, compiled by the broker from
  the template and your choices — and approve with **one Touch ID**. Nothing
  is granted before that tap; an install always creates a fresh delegate.
- **The family sees it as an alias.** Each allowed household member's reach
  gains the app's name, so `/chef 今晚吃什么` (or a photo with that caption)
  reaches the app through the contact gate. A photo sent without a caption goes to
  the assistant the sender can reach — the last one they used, or the only
  one — never to an assistant outside their reach.
- **Photos and voice.** The contact gate keeps the original bytes beside the
  app's feed; the app looks at the full-resolution photo before it answers
  and may ask for a closer picture instead of guessing.
- **The card.** An app with a display slot publishes a card (today's
  summary, what to cook, alerts, buttons). The console shows the same card
  the kitchen screen shows; tapping a button publishes a command from **this
  console's own device actor** — the first install that binds a display slot
  enrolls the console in the same Touch ID as the install (a console never
  enrolled publishes taps as you, the master). **Ask for the card now**: the
  panel offers one button per schedule entry of the app's template (chef:
  *Morning plan*, *Dinner plan*; an app without a schedule gets one generic
  ask). A click sends that entry's prompt to the app as a turn — exactly what
  its clock does at the cron minute, tagged as asked from the console — and
  the panel watches the display feed for the card. The app's answer is in its
  chat; if no card lands within three minutes the panel says so.
- **Template updates.** When the catalog carries a newer version of an
  installed app's template, the app's page shows **update to vX**. One Touch
  ID applies the new version's permissions and slot directions over your
  existing bindings, and the new skills are applied to the running app;
  nothing is reinstalled. Chef 1.1.0 is such an update: its kitchen screen
  becomes two-way, so the card's **Completed** and **Ready for the next
  meal** buttons reach chef (before it, chef only published to the screen and
  never heard a tap).
- **Endpoints — one Touch ID, never a second prompt.** The first install that
  binds the family chat enrolls the WeChat / Telegram contact gate as a device
  actor in the SAME Touch ID as the install, and the first install that binds
  a display slot enrolls this console the same way; the install sheet lists
  them under "also enrolled by this Touch ID". The endpoints tab shows both
  and is the standalone way to enroll either ahead of time; the contact gate's
  status card says whether the "feed hop" is armed and why not.
- **Where the family chat goes.** The channel you bind to an app's messaging
  slot IS its feed — `family-chat` stays `family-chat`; nothing is derived
  from it. The install (or a rebind) tells the contact gate "chef listens on
  `family-chat`" and grants the gate that channel, so a family message
  addressed to chef lands there and chef's replies come back through it. One
  messaging channel serves one app (the install refuses a channel another app
  already holds). The channels page flags a messaging channel an app holds but
  no gate does, and shows every channel's feed in place (the operator chat is
  the one you can write into there); the application page keeps the same
  panels for quick access.
- **Rebinding a slot is a commit, not a reinstall.** On the application page,
  **edit bindings** → pick the new channel → **commit**: one Touch ID re-signs
  the app's grants (and enrolls the contact gate on the new channel when it
  needs to), the running app re-sources its feeds in place, and a sleeping app
  picks the new channel up at its next wake. No uninstall, no delegate slot
  consumed, and the app keeps its memory. The old channel row stays in the
  registry until you clear it (**clear orphaned** on the channels page).
  The bound channels live in ONE place — the app's **context document**, the
  anchor: an entry in the app's own namespace on the memory plane, whose hash
  the same Touch ID seals on chain (a root on the audit contract). It is never
  in the sandbox image and never frozen in a running instance: the running app
  re-reads the document with its own credential (every 90 s by default,
  `AGENTKEYS_BINDINGS_POLL_SECS`) and re-sources its feeds, the commit also
  pushes the change into it right away when it can reach it, and the broker's
  own row is only a cache of the document. The application page shows each
  app's anchor (version, hash, the sealing tx) and the **document itself** —
  its fields, the raw bytes the seal hashed, and whether they match the sealed
  anchor and the current bindings (**re-read** fetches it again).
- **Anchors survive a broker switch.** A fresh broker has no rows: on the
  endpoints tab, **re-hydrate runtime contexts** reads every app's sealed
  document and has the broker rebuild its rows after checking each hash
  against the operator's roots on chain. Apps installed before the anchor
  existed carry no document yet — **seal existing apps** mints one per app in
  a single batch, one Touch ID.
- **A woken app seeds its own context.** An app the broker wakes for a
  schedule tick, or re-creates at its lease end, applies its template's
  persona, skills and knowledge to its runtime by itself at boot — only what
  is missing, never over an applied persona. (Until 2026-09-22 a woken app ran
  bare and improvised its card as free-form text; the display panel now says
  when the newest documents on the feed are not cards.)
- **WeChat is each member's own iLink clawbot.** The family talks to an app
  through their own clawbot, the one the assistants already use (the iLink
  personal-bot API, one bot per member): text, photos and voice clips all relay, and a voice
  clip carries WeChat's own transcript. The contact gate's receipt
  ("已转达给 chef 📷 [photo]") comes back at once; the app's own answer comes
  back through the same bot.
- **Knowledge.** The **Knowledge** page is the one place for everything your
  household's assistants may know: your canonical memory namespaces and the
  typed items an app binds (the former memory and resources pages). It is
  shaped like a code host: every namespace is a **repository** — the list
  shows its visibility (the highest sensitivity inside), who reads it, what
  is pending and when it last changed; open one for its tabs **Files** (the
  items; the plain notes decrypt on open), **Proposals** (what delegates
  pushed for it — accept merges, a colliding key asks you first),
  **History** (every text a commit replaced — diff it against the current
  text, or **restore** it as the next version), **Access** (who reads it and
  through which grant) and **Sync** (each reader's clone with its launch /
  pull stage and **sync now**). **All items** groups everything by type,
  sensitivity or tag. **+ add knowledge** pastes text or
  uploads a file — plain text, markdown, CSV, JSON, a PDF, or an image (up to
  5 MB); the text is what an app reads (a PDF's text is extracted; an image
  becomes a gallery caption) and the file's bytes are kept beside it.
  Every item has a **type** — a plain note by default; an app slot asks for a
  type, and the install wizard can **retype** an item when you bind it (the
  type is metadata, so a retype is not a new version). **Give it a type**
  registers an older, untyped note under its own key.
  Re-adding an id makes the next version and replaces the previous text
  (the previous text stays in **History** — the last 20 per item; on the
  console daemon `AGENTKEYS_KNOWLEDGE_HISTORY_KEEP` raises that, up to 100);
  remove drops the item (it refuses while an app is bound to it unless you
  confirm). **The grant is the namespace**: binding one item grants the app
  the whole namespace, the page says who reads each namespace, and a namespace
  bound to several apps is stored once — each app's sandbox keeps a derived
  copy that the daemon's mirror refreshes (every 300 s by default) and can
  never write back. An app's own page lists its bound items with **edit**; the
  row names the other apps that read the same item, and a saved edit reaches
  all of them at their next refresh. An install wizard slot with no matching
  item offers to add one right there. **Nothing is overwritten silently:** if
  an item changed while you were editing it (another tab, another device),
  the save is refused and the modal shows the difference — load the current
  text, or overwrite on purpose. A merged proposal that lands on a key that
  already exists shows the same diff and asks: replace the entry, or keep
  both.
- **Launching.** An installed app goes through `booting → restoring →
  syncing k/n → ready` on its card (and on its delegate's card, and as a
  status line in its chat), read from the app's own feed. `degraded` means
  the knowledge engine is down or a pull failed — the app still answers, from
  what it has, and says so in front of its reply; a family member who writes
  to it meanwhile gets the receipt "still loading its knowledge". A reply
  waits for `ready` at most `AGENTKEYS_KNOWLEDGE_READY_WAIT_SECS` (60 s by
  default). **sync now** on the app's page makes it pull at once. Every pull
  leaves one audit row (`delegate.lifecycle`: namespaces, lines, ms, errors),
  never a log stream. A respawned app restores its engine index with its
  checkpoint, so its first pull is a delta.
- **Uninstall** revokes every permission (the delegate's, and the contact gate's
  and console's on the app's feeds), returns the agent slot, and tears the
  sandbox down. Keeping the app's memory lets a reinstall inherit it.

What is not there yet: an app cannot send a picture back to the family chat
(text replies only); the 公众号 (OA) transport has no async reply path — use
iLink or Telegram for an app's family chat; a scheduled app runs its timed
turns only while the "Scheduled reports" capability (`tool:schedule`) is on
its sheet.

## The kitchen display — a shared tablet as its own device (device-display, #675)

A shared screen (a kitchen tablet, an old phone on the fridge) shows your household app's card and lets anyone tap its actions — **without ever holding your master authority**. The display is its own *device* in your family, exactly like an ESP32 screen: it has its own key (made in that browser, never leaving it), it is paired once with one Touch ID, and it can be revoked on its own without touching your console or your phone.

**Setting one up (about a minute):**

1. Open the display app on the tablet (`apps/device-display`, `http://<your-dev-host>:3119`, or the hosted URL your operator gives you; `?broker=…&feed=…&label=…` in the link pre-fills the settings). Enter your family's broker address once. It shows a **pairing code** and a QR.
2. On your parent-control console go to **Devices → claim a device**: type the code, keep the label (`kitchen-display` by default), attach the display feed of the app you installed (the feed name is on the tablet, `kitchen-display` by default) with **listen + speak**, then approve with **one Touch ID**.
3. The tablet switches to the card by itself. Taps such as *Completed* or *Ready for the next meal* reach the app as commands attributed to **the display** — the console's Applications dashboard lists them under recent commands with that device's identity.

**Good to know:**

- The code is valid for 10 minutes; tap *New code* if it expired. A paired display re-connects on its own after a reboot (no code needed).
- *Settings* on the tablet changes the broker, feed or label; *Forget this device* wipes its key — pair again afterwards (the old device stays listed until you revoke it in the console).
- Nothing on the tablet can read your memory, credentials or other feeds: its grants are exactly the two channel attachments you approved.
- Use the browser's *Add to Home Screen* for a full-screen kiosk; the *Full screen* button also asks the tablet to keep the screen awake.
