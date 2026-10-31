# Architecture and ownership

This document describes the public source tree. The complete local runtime is still under development in [epic #1](https://github.com/litentry/agent-terrier/issues/1); this source-boundary revision is not a full localhost release.

## Components

| Component | Canonical owner | Consumers |
|---|---|---|
| Shared identity and cryptographic primitives | `crates/agentkeys-types`, `crates/agentkeys-device-core`, `crates/agentkeys-core` | Native and browser clients, broker and workers |
| Transport-free wire schemas | `crates/agentkeys-protocol` | Native clients and browser WASM |
| Native service client | `crates/agentkeys-backend-client` | CLI and daemon |
| Browser service client | `crates/agentkeys-web-core` | Web console and browser display |
| Authorization and request coordination | `crates/agentkeys-broker-server` | Product clients and workers |
| Independent worker verification | `crates/agentkeys-worker-creds` | Storage and compute workers |
| Smart contracts and contract tests | `crates/agentkeys-chain` | Local deployment and chain clients |
| Headless product operations | `crates/agentkeys-cli`, `crates/agentkeys-daemon` | Developers, tests and the future local manager |
| UI tokens and components | `design-system` | `apps/parent-control`, `apps/device-display` |
| Agent runtime plugins | `packages/agentkeys-dsh` | Agent environments |
| Protocol examples | `e2e/fixtures` | Shared drift and conformance checks |

The device-core crate contains reusable protocol and cryptographic primitives. It does not require firmware or a hardware toolchain for the public workspace build.

The public source excludes hardware firmware, inherited operator documentation and the full operator console. The duplicated design-only applications preview is removed; the product applications UI remains the owner. Both browser apps import one design system and build one WASM client through `scripts/build-browser-core.py`. Generated browser output is ignored by version control and checked again for embedded personal paths before distribution.

`.public-source.json` is the source-surface allowlist; `scripts/check-public.py` enforces it and checks source/artifact contents without printing matched credentials. Synthetic negative-test exceptions require an exact source-line hash and a review reason. They cannot exempt files, directories or unapproved repository links. The scanner supplements manual diff review; it does not prove arbitrary binary or encoded data safe.

Browser compilation remaps Rust source paths. The display build also makes route-manifest source metadata relative to the app root: the framework otherwise embeds workstation paths in its production manifest. Asset URLs and route behavior are unchanged; the artifact privacy check must pass after a framework update.

The card schema has one owner in `agentkeys-protocol::card`. Its TypeScript output lives in `design-system/generated/`; the renderer and both apps consume those generated types. Existing `CardView*` names are aliases, not separate field definitions. Regenerate with `cargo test -p agentkeys-protocol -p agentkeys-daemon export_bindings` after changing a card field.

## Trust boundaries

1. The chain owns identity and authority.
2. Broker state must not create a second authorization source.
3. Actor keys stay with the actor; development signing is explicit and limited.
4. Every access is scoped to an actor, proof and grant.
5. Owner-signed chain mutations may be relayed; the broker does not sign as an owner.
6. Readable personal data remains off-chain.
7. Each cross-component contract has one definition.

Independent checks at broker, worker and storage boundaries remain necessary even when they share types and pure helpers.

## Migration gates

The source tree still contains runtime-specific integrations that must be replaced by neutral interfaces before local release. That work is tracked by [#3](https://github.com/litentry/agent-terrier/issues/3); real local chain/signing, storage, Docker and models follow in [#4](https://github.com/litentry/agent-terrier/issues/4), [#5](https://github.com/litentry/agent-terrier/issues/5), [#6](https://github.com/litentry/agent-terrier/issues/6) and [#7](https://github.com/litentry/agent-terrier/issues/7).

The complete CLI and light manager must call these owners rather than duplicate their implementation. Release acceptance requires a public-only clean install and an offline core journey after downloads. Existing inherited documentation is not the new local setup contract.

| Remaining overlap | Owner | Removal gate |
|---|---|---|
| Runtime lifecycle and provider-specific implementations | Broker runtime interface | #3 establishes neutral contracts; #6 supplies the local adapter; no provider implementation in the public release |
| Repeated worker authorization helpers | Worker verification and protocol types | #3 and #5 consolidate pure policy while retaining independent enforcement at each boundary |
