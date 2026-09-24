# In-pod daemon ↔ dsh contracts

Two contracts, one fixture each, both read by a Rust test and a TypeScript test so a renamed field fails on whichever side drifted.

## `actions_contract.json` — the daemon-advertised actions (dsh → daemon)

Owner: `agentkeys-protocol`'s `sandbox_actions` module (`advertised_actions`, `SandboxPublishRequest`, `SandboxProposeRequest`; plan `docs/plan/dsh-plugin-abstraction.md` PR 1). The `advertised.response` block is `advertised_actions(pub_slots, own_namespace)` verbatim — descriptions included — and the two receipts show the fields a 2xx reply carries (`outcome` + `summary` always).

- Rust: `sandbox_actions::tests::the_advertised_actions_match_the_shared_fixture`
- TypeScript: `packages/agentkeys-dsh/tests/actions.spec.ts`

## `session_contract.json` — typed sessions (daemon → bridge)

The in-sandbox daemon → dsh bridge contract for typed sessions. The shape has one owner, `agentkeys-protocol`'s `session_window` module (`BridgeChatSession`, `BridgeSessionReset`, `session_reset_body`). Two tests read `session_contract.json`, so a renamed field fails on whichever side drifted:

- Rust: `session_window::tests::the_bridge_session_contract_matches_the_shared_fixture`
- TypeScript: `packages/agentkeys-dsh/tests/bridge-sessions.spec.ts`

Edit the fixture only together with both parsers.
