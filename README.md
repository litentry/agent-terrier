# Agent Terrier

Agent Terrier is an open-source agent platform with on-chain authorization, a shared Rust core, a command-line client and a web console.

The standalone local development environment is being built in [epic #1](https://github.com/litentry/agent-terrier/issues/1). This revision is the source-boundary foundation; a complete localhost quickstart is not yet available.

## Development

Run these commands locally from the repository root:

```sh
python3 scripts/check-public.py
python3 -m unittest discover -s scripts/tests
cargo metadata --no-deps --format-version 1
cargo fmt --all -- --check
```

The console and browser display share the checked-in `design-system/` package and a generated browser client. Install `wasm-pack` and the `wasm32-unknown-unknown` Rust target first. Run locally from the repository root; the initial Rust build is cached for subsequent runs:

```sh
npm --prefix apps/parent-control install --ignore-scripts
python3 scripts/build-browser-core.py
npm --prefix apps/parent-control test
```

The component suite runs without a browser. Use `--release` when building the browser client for distribution. Both build modes remove personal source paths from the binary; run the privacy check again after generating artifacts.

See [architecture and ownership](docs/arch.md) and [contributing](CONTRIBUTING.md). Never use production wallet keys or credentials in development examples.

For contract development, install Python 3 and Foundry, then run locally from the repository root:

```sh
./terrier contracts setup
./terrier contracts test
```

See the fresh [contract development wiki source](docs/wiki/contract-development.md) for offline tests, focused checks and cache configuration.

The [local chain guide](docs/wiki/local-chain.md) covers `terrier chain start/deploy/status/logs/stop`, disposable signing identities, persistent restart and explicit deployment recovery. These commands deploy the actual contracts locally; the complete application environment remains under development.

The [local owner guide](docs/wiki/local-owner.md) covers headless owner registration, device/delegate binding and grant revocation. The [local model guide](docs/wiki/local-models.md) covers `terrier models config/probe` and a reproducible macOS qualification with external networking blocked.

The [local storage guide](docs/wiki/local-storage.md) documents the isolated object service, its fast negative tests and explicit real-chain qualification. Product worker integration remains in progress.

## License

Apache-2.0 is the default project license. Existing Solidity and DSH licenses remain explicit exceptions; see [licensing](docs/wiki/licensing.md) and [NOTICE](NOTICE).
