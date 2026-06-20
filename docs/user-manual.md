# AgentKeys — User Manual

The single home for **user-facing behaviors and instructions** — the things an
operator or end user needs to know about how AgentKeys touches their machine.
(Developers: see [`arch.md`](arch.md). Running the wire demo end to end: see
the internal wire operator runbook (`operator-docs/`, not in the OSS mirror).)

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
fleet never reads as fully disconnected. After a reset, Touch ID sign-in is
gone until you onboard again. (You no longer need the
`--master-device-key-hash` developer flag for the normal web loop — the device
is recovered from your account automatically.)

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
