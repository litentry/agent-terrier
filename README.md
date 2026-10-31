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
