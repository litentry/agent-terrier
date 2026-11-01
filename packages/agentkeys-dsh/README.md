# Agent Terrier agent plugins

This package connects a DSH runtime to the shared agent authorization, channel and tool interfaces. It does not start or download a model.

The sessions plugin owns the runtime home. Set its `homeDir`, or explicitly supply `DSH_HOME`; there is no default home. The selected path must be absolute and cannot be a filesystem root. Invalid explicit configuration is an error, even if the environment supplies another path. The bridge uses that same session home; its optional compatibility `homeDir` must resolve to the same path. The runtime composition supplies its protected `--state-dir` once through the sessions plugin. Standalone plugin callers remain responsible for directory ownership and permissions.

Model relay environment names are owned by `agentkeys-protocol::model_runtime`. The checked-in TypeScript module is generated from that owner; protocol tests detect drift. `AGENTKEYS_MODEL_BASE_URL` and `AGENTKEYS_MODEL_API_KEY` travel together. `AGENTKEYS_MODEL_ID` optionally selects the model. The speech URL, when present, belongs to the same relay. Adapter credentials stay outside the container.

The web-search plugin is optional and requires an explicitly configured search-capable relay. A local model server alone does not supply web search. With no configuration the plugin reports unavailable; explicit endpoint and key settings must be supplied as a pair and cannot borrow half of an inherited pair. Redirects are refused. Offline qualification excludes web search.

Local, from the repository root, regenerate names:

```sh
cargo run -p agentkeys-protocol --example export-model-runtime > packages/agentkeys-dsh/src/generated/model-runtime.ts
```

Local, from the public repository root, use the shared workspace lockfile:

```sh
npm ci --prefix packages --ignore-scripts
python3 terrier test focused --component dsh
```

The [local runtime image](../../docs/wiki/local-agent-image.md) reuses these plugins. Its component checks and the complete application journey have separate qualification status.
