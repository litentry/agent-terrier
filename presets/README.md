# Presets — repo-resident delegate bundles (#428, epic #425 S3/O3)

A preset is the customization unit for a spawned delegate: a persona
(`SOUL.md`, the #390 `persona` context kind), skills docs (`skills/*.md`,
the #390 `skills` kind), and a manifest of *suggestions* (`preset.json`).

**Content, never authority.** A preset may *suggest* channels, context
namespaces, and schedules — but grants only ever come from the phase-1 spawn
template (`channel-pub/sub:opchat-<label>` + `memory:<ns>`) or an explicit
later ceremony (Touch ID). Installing a preset grants NOTHING beyond the
template; suggestions render in the agent panel as inert affordances until
the operator grants them.

## Layout

```
presets/<id>/
  preset.json     # id, version, names/descriptions (EN + 中文), suggestions, schedule
  SOUL.md         # the persona layer (#390 — the locked base layer is appended
                  # by the system at apply time, never stored here)
  skills/*.md     # TOOLS.md-class skills docs, distributed with the persona
```

The catalog is **broker-served and compiled in** (`include_str!`, like the
chain profiles): `GET /v1/presets` lists summaries, `GET /v1/presets/:id`
returns the full bundle. Versioned with the deployed ref — shipping a new or
edited bundle is a broker redeploy, no client release (a marketplace later
means new bundles server-side under the same wire shapes).

Wire shapes are owned by `agentkeys-protocol` (`PresetSummary`,
`PresetBundle` — the one-owner rule, #203). Adding a bundle: create the
folder, register it in the broker's `handlers/presets.rs` `BUILTINS`,
done — the registry test pins id-uniqueness + manifest parseability.

## Application templates (epic #660)

Since #662 a preset can also be an **application template**: the same
`preset.json` gains slots · resources · tools · availability · budgets ·
disclosure · context pointers (all additive — a role preset parses unchanged),
and the bundle may carry `knowledge/*.md`. Installing one from the console
compiles exactly the sheet the owner signs. Authoring guide:
[`docs/wiki/family-application-templates.md`](../docs/wiki/family-application-templates.md).
`chef/` is the reference application; `conformance/` is the hidden synthetic
template the framework suite installs. `scripts/utils/check-template-content-only.sh`
gates that a template is content only (F0/F1).
