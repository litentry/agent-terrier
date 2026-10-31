# Agent Terrier agent plugins

This package connects a DSH runtime to the shared agent authorization, channel and tool interfaces. It does not start or download a model.

Model relay environment names are owned by `agentkeys-protocol::model_runtime`. The checked-in TypeScript module is generated from that owner; protocol tests detect drift. `AGENTKEYS_MODEL_BASE_URL` and `AGENTKEYS_MODEL_API_KEY` travel together. `AGENTKEYS_MODEL_ID` optionally selects the model. The speech URL, when present, belongs to the same relay. Adapter credentials stay outside the container.

The web-search plugin is optional and requires an explicitly configured search-capable relay. A local model server alone does not supply web search. With no configuration the plugin reports unavailable; explicit endpoint and key settings must be supplied as a pair and cannot borrow half of an inherited pair. Redirects are refused. Offline qualification excludes web search.

Local, from the repository root, regenerate names:

```sh
cargo run -p agentkeys-protocol --example export-model-runtime > packages/agentkeys-dsh/src/generated/model-runtime.ts
```

Local, from this package directory:

```sh
npm install --ignore-scripts
npm run typecheck
npm test
```

The public container image and complete application journey remain under qualification. Passing these plugin checks does not prove that journey is ready.
