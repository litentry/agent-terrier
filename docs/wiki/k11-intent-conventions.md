# K11 intent conventions — typed contract, uniform Touch ID prompts

Every K11 WebAuthn ceremony in AgentKeys renders an operator-readable confirmation block on its localhost page. The contract is **typed** — scripts pass a single JSON payload describing the operation, and the shared Rust renderer in [`crates/agentkeys-cli/src/k11_intent.rs`](../../crates/agentkeys-cli/src/k11_intent.rs) produces the canonical headline + per-field rows. No more ad-hoc `--intent-field "Label=Value"` strings duplicated across 7 bash scripts; no more drift between "Chain ID" vs "Chain"; no more raw role bitfields ("Role bitfield=3" replaced by "Permissions: CAP_MINT | RECOVERY").

See [`wiki/k11-webauthn-intent-rendering.md`](./k11-webauthn-intent-rendering.md) for the underlying rendering mechanism (the `K11IntentContext` type + `assert_webauthn_*_with_intent` entry points). This page covers the *content convention* — the typed enum, JSON wire shape, formatting rules, and per-operation conformance.

## Why uniform

Master-mutation ceremonies (scope grant/revoke, device add/revoke, K10 rotation, recovery) all share the same trust-model property: the operator's eyes are the load-bearing safety check. If one ceremony's confirmation page says nothing while a neighbor ceremony's page renders a detailed intent block, the operator learns to ignore the page entirely. The uniform rule means every prompt shows the same envelope — operator confidence comes from "I always see what I'm signing", not from "I sometimes see what I'm signing if the script remembered to pass intent".

## The typed contract

The single source of truth is the [`K11OpIntent`](../../crates/agentkeys-cli/src/k11_intent.rs) enum. One variant per master-mutation operation. Each variant carries its **typed payload** — fields are decoded properly (role bitfields, amounts, hashes) by the renderer, not by per-script string surgery.

### Wire format (JSON)

Scripts construct a JSON object matching one of the enum variants and pass it via:

- **CLI**: `agentkeys k11 assert ... --intent-op-json '<JSON>'`
- **Daemon companion (multi-party ceremonies)**: POST body field `intent_op` to `/v1/companion/approve`

Both surfaces parse the same JSON through `K11OpIntent::from_json()` → `render()` → `K11IntentContext`, so PRIMARY and COMPANION prompts are byte-for-byte uniform for the same operation (only the `Asserting role` row differs).

Tagged-enum discriminator: `kind` field with snake_case variant names.

```json
{
  "kind": "set_recovery_threshold",
  "operator_omni": "0x941cb1c3260518bbf40eac7d02663517fc7cff304d9b03e80d2cc54126c6bef2",
  "new_threshold": 2,
  "chain_id": 212013,
  "operator_nonce": 4,
  "asserting": { "kind": "primary", "device_key_hash": "0xde64…" }
}
```

### Variants + payloads

| `kind` | Operation | Required fields |
|---|---|---|
| `set_scope_grant` | `AgentKeysScope.setScopeWithWebauthn` | `operator_omni, agent_label, agent_omni, services[], read_only, max_per_call, max_per_period, period_seconds, max_total, chain_id, scope_nonce, asserting` |
| `set_scope_revoke` | `AgentKeysScope.revokeScope` | `operator_omni, agent_label, agent_omni, chain_id, scope_nonce, asserting` |
| `register_companion_as2nd_master` | `SidecarRegistry.registerAdditionalMasterDevice` (companion) | `operator_omni, new_device_key_hash, companion_rp_id, roles, chain_id, operator_nonce, asserting` |
| `register_spare_master` | `SidecarRegistry.registerAdditionalMasterDevice` (synthetic 3rd master) | `operator_omni, new_device_key_hash, roles, chain_id, operator_nonce, asserting` |
| `set_recovery_threshold` | `SidecarRegistry.setRecoveryThreshold` | `operator_omni, new_threshold, chain_id, operator_nonce, asserting` |
| `recovery_device_revoke` | `SidecarRegistry.recoverViaQuorum` | `operator_omni, target_device_key_hash, recovery_threshold, chain_id, operator_nonce, asserting` |
| `revoke_master_device` | `SidecarRegistry.revokeDevice` (master target — catastrophic) | `operator_omni, target_device_key_hash, chain_id, asserting`; optional: `recovery_threshold_remaining, operator_nonce` |
| `revoke_agent_device` | `SidecarRegistry.revokeDevice` (agent target) | `operator_omni, target_device_key_hash, chain_id, asserting`; optional: `agent_label, operator_nonce` |

Amount fields (`max_per_call`, `max_per_period`, `max_total`) are **strings** to survive JSON's 53-bit integer range — a U256 value can exceed it. The renderer decodes `"0"` (or `"0x0"` or `""`) as the word `"unlimited"` so operators don't squint at a raw zero.

`asserting` is a sub-discriminated enum:

```json
{ "kind": "primary",   "device_key_hash": "0xde64…" }
{ "kind": "companion", "device_key_hash": "0xb322…" }
```

### Formatting rules (the centralized part)

The renderer applies these transformations to every payload — once, in Rust, instead of repeated across 7 bash scripts:

| Raw input | Rendered output |
|---|---|
| `roles: 3` | `Permissions: CAP_MINT \| RECOVERY (raw 3)` |
| `roles: 7` | `Permissions: CAP_MINT \| RECOVERY \| SCOPE_MGMT (raw 7)` |
| `roles: 0b1000` | `Permissions: bit3(unknown) (raw 8)` (future-bit surfaces explicitly) |
| `max_per_call: "0"` | `Max per call: unlimited` |
| Three zero amounts | Single row `Spending limits: unlimited` (drops the per-row noise) |
| `operator_omni: 0x941c…6bef2` (66 chars) | `0x941cb1…6bef2` (truncated for prompt width) |
| `chain_id: 212013` | `Heima Mainnet (212013)` |
| `chain_id: 31337` | `Anvil local (31337)` |
| `period_seconds: 86400` | `1d` |
| `period_seconds: 3700` | `1h 1m 40s` |
| `read_only: true` | `Access mode: read-only` |
| `read_only: false` | `Access mode: read + write` |

Single source of truth: change a label or unit once in `k11_intent.rs` and every K11 emit-site picks it up.

## The envelope (required fields, in this order)

Every `K11IntentContext` passed to `assert_webauthn_*_with_intent()` MUST include these rows, in this order:

| Row | Always | Example value |
|---|---|---|
| **`Operator omni`** | yes | `0x941cb1c3260518bbf40eac7d02663517fc7cff304d9b03e80d2cc54126c6bef2` |
| **`Asserting role`** | yes | `PRIMARY (key hash 0xde64…)` or `COMPANION (key hash 0xb322…)` |
| Operation-specific detail rows | varies | e.g. `Target device key hash=0x…`, `Services=openrouter,brave-search`, `Recovery threshold=2` |
| **`Effect`** | yes (chain-mutating ops) | one-line plain-English description of what changes on chain after the tx lands |
| **`Chain ID`** | yes | `212013` |
| **`Operator nonce`** | yes (chain-tx ops) | `42` |

The headline (`intent.text`) is a single sentence describing the operation. The Effect row is what makes the consequence concrete — the operator should understand from the Effect row alone what the world looks like AFTER they tap.

## Required headline + Effect text by operation

This is the canonical phrasing table. Scripts implementing a K11 ceremony for an operation MUST use the headline + Effect verbatim from this table (or extend the table in the same PR).

| Operation | Headline (`intent.text`) | Effect row |
|---|---|---|
| `setRecoveryThreshold` | `Set recovery threshold to N (M-of-N master quorum)` | `future master-device revokes will require this many active master signatures` |
| `registerAdditionalMasterDevice` (companion) | `Register companion device as 2nd master` | (auto-derived from role bitfield) |
| `registerAdditionalMasterDevice` (synthetic spare) | `Register synthetic 3rd master (spare) device` | `adds a 3rd master to the operator's quorum (used by harness step 9 to demo M-of-N revoke)` |
| `recover` (M-of-N device revoke) | `Revoke master device via M-of-N recovery quorum` | `removes <target> from the operator's active master set; future cap-mint by this device is rejected on-chain` |
| `setScopeWithWebauthn` | `Grant agent '<label>' access to: <services>` | (per-row detail: services, read_only, max amounts, period) |
| `revokeScope` | `Revoke all scope grants for agent '<label>'` | `agent loses access to ALL services this scope previously granted` |
| `revokeDevice` (master) | `⚠ REVOKE MASTER device — this disables the operator's master entirely` | (per-row detail: target device hash, role bits being revoked, recovery threshold remaining) |
| `revokeDevice` (agent) | `Revoke agent device key hash <hash>` | `agent device can no longer mint caps; previously-issued caps still work until expiry` |
| `rotateK10` (device-key rotation) | `Rotate device key from <old> to <new>` | (TBD — wire when shipped) |

**Warning-prefix convention** (`⚠` U+26A0 + space): use the warning emoji prefix in the headline ONLY for **catastrophic, hard-to-reverse** operations — master-device revoke is the canonical example. The warning marker tells the operator's eye to slow down before tapping. Agent-device revoke (lower blast radius, recoverable) does NOT get the prefix. Don't over-use it; if every prompt has the warning, none of them do.

If you're adding a new master-mutation operation:
1. Add a row to this table in the same PR.
2. Use the canonical headline + Effect across every script that runs that operation's K11 ceremony.

## Multi-party ceremonies — both prompts MUST match

When an operation requires more than one master signature (recovery via M-of-N quorum), every participating master sees a K11 prompt. **All prompts MUST render the same headline + the same operation-specific rows + the same Effect.** The only field that differs per-master is `Asserting role`.

This means: the script that orchestrates the multi-party ceremony (`heima-recovery.sh` is the canonical example) computes the canonical intent envelope ONCE and:
- Passes it to the local `agentkeys k11 assert` invocation (for PRIMARY).
- Embeds it in the JSON POST body to the companion's `/v1/companion/approve` endpoint (for COMPANION). The companion daemon's handler reads `intent_text` + `intent_fields` from the POST body and renders them on its own Touch ID confirmation page.

Implementation:
- `ApproveRequest` ([`crates/agentkeys-daemon/src/companion.rs`](../../crates/agentkeys-daemon/src/companion.rs)) accepts optional `intent_text: Option<String>` + `intent_fields: Vec<String>` fields. Each `intent_fields` entry is a `Label=Value` string; the handler splits on the first `=`.
- The companion's `approve` handler calls `assert_webauthn_for_chain_with_intent()` — same code path that primary uses, so the rendering on the localhost confirmation page is identical apart from the role badge color (purple for companion vs blue for primary).

## Conformant K11 emit sites

| Site | Operation | Conformant? |
|---|---|---|
| [`scripts/heima-scope-set.sh`](../../scripts/heima-scope-set.sh) | scope grant | ✅ |
| [`scripts/heima-scope-revoke.sh`](../../scripts/heima-scope-revoke.sh) | scope revoke | ✅ |
| [`scripts/heima-device-revoke.sh`](../../scripts/heima-device-revoke.sh) | revoke device | ✅ |
| [`harness/scripts/heima-device-add.sh`](../../harness/scripts/heima-device-add.sh) | register companion as 2nd master | ✅ |
| [`harness/scripts/heima-register-spare-master.sh`](../../harness/scripts/heima-register-spare-master.sh) | register synthetic 3rd master | ✅ |
| [`harness/scripts/heima-set-recovery-threshold.sh`](../../harness/scripts/heima-set-recovery-threshold.sh) | set recovery threshold | ✅ |
| [`harness/scripts/heima-recovery.sh`](../../harness/scripts/heima-recovery.sh) PRIMARY + COMPANION | M-of-N device revoke | ✅ (both prompts uniform; companion via POST body) |
| Future master-mutation script | (new) | MUST follow this convention before merging |

## What does NOT count as conformant

- **Building ad-hoc `--intent-field "Label=Value"` strings** instead of the typed `--intent-op-json` payload. The raw flags are kept ONLY as an escape hatch for one-off operations not yet wired into the typed enum; production scripts MUST use the typed path so formatting + label drift is impossible.
- Drifting from the canonical `kind` names in the variant table. A typo'd `"kind": "set_scope_revokes"` deserializes to a "tag mismatch" error — fail-loud, not silent-fallthrough.
- Passing intent on the primary side but not on the companion side of a multi-party ceremony. Multi-party callers MUST pass the SAME `K11OpIntent` payload to both, with only the `asserting` discriminator differing — `heima-recovery.sh` is the canonical example.

## Verification

### Built-in unit tests

The typed renderer ships with regression tests in [`crates/agentkeys-cli/src/k11_intent.rs::tests`](../../crates/agentkeys-cli/src/k11_intent.rs):

- `roles_decode_canonical_combinations` — answers the user-reported "Role bitfield = 3 should show a readable permission" feedback: `format_roles(3) == "CAP_MINT | RECOVERY (raw 3)"`.
- `roles_surface_unknown_future_bits` — bit3+ surfaces as `bit3(unknown)` so a future role expansion doesn't silently render as "the same 3 permissions."
- `truncate_hash_collapses_long_values` — 64-hex-char omni renders as `0x941cb1…6bef2` instead of full 66 chars.
- `unlimited_amount_renders_as_word` — `"0"` → `"unlimited"`, non-zero passes through unchanged.
- `duration_human_units` — `3600 → 1h`, `86400 → 1d`, `86461 → 1d 0h 1m 1s`.
- `chain_id_labels_known_networks` — 212013 → "Heima Mainnet"; unknown IDs surface as `chain_id N`.
- `scope_grant_renders_concisely` — when all amounts are `"0"`, a single `Spending limits: unlimited` row replaces the verbose three `Max *` rows.
- `register_companion_renders_decoded_roles` — end-to-end: JSON in → rendered "Permissions: CAP_MINT | RECOVERY (raw 3)" out.
- `recovery_uniform_across_primary_and_companion` — both prompts produce identical headline + identical operation rows; only `Asserting role` differs.

Run: `cargo test -p agentkeys-cli --lib k11_intent`.

### Live confirmation page

To sanity-check the typed pipeline end-to-end against the actual Touch ID confirmation page:

```bash
# Trigger any K11 ceremony with --webauthn — the localhost server
# renders the confirmation page + prints its URL to stderr.
bash harness/v2-stage1-demo.sh --only-step 13 --webauthn

# Open the URL, confirm:
#   - Headline is the canonical phrasing from the variant table above.
#   - Role bitfields render as permission names, not raw integers.
#   - Operator omni is truncated, not full 66 chars.
#   - Chain ID has a human label.
#   - `Spending limits: unlimited` appears when all amounts are 0.
```

For multi-party ceremonies (`heima-recovery.sh`), run both daemons + diff
the rendered HTML of primary vs companion pages — only the `Asserting
role` row + the role badge color should differ. A future PR will add an
integration test that crawls the localhost server per operation +
asserts the rendered DOM matches expected fixtures, so the convention
becomes mechanically enforced rather than convention-only.

## Cross-references

- [`wiki/k11-webauthn-intent-rendering.md`](./k11-webauthn-intent-rendering.md) — the rendering mechanism (`K11IntentContext`, HTML page structure, fallback behavior when no intent is supplied).
- [`docs/arch.md`](../arch.md) §10.1 — master init + K11 binding model.
- [`wiki/audit-envelope-add-op-kind.md`](./audit-envelope-add-op-kind.md) — when a new master-mutation op_kind PR lands, it MUST also extend the K11 intent table above with the canonical headline + Effect for that op.
