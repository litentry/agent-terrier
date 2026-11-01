# Contributing

Work from a public checkout and keep changes focused on one issue. The crate prefix remains `agentkeys-` to preserve existing code and protocol compatibility.

Use `docs/arch.md` to find the owner of a component. Extend an existing module instead of adding a second wire schema, configuration resolver or lifecycle controller. Browser-facing types come from the shared Rust definitions.

Run the relevant component or crate tests locally. UI component tests use controlled clients and run without browser startup. Browser navigation, rendering and security integration still require their own acceptance.

Before submitting a PR, run the public-content check, review every new file and include exact validation results. Keep keys, tokens, local state, screenshots containing personal data and deployment configuration out of commits. Report suspected vulnerabilities privately to the repository maintainers without posting credentials or exploit data in public issues.

The local runtime migration remains open in [epic #1](https://github.com/litentry/agent-terrier/issues/1). Passing source checks does not establish a runnable full release.

The default contribution license is Apache-2.0. Preserve existing file-level notices and third-party attribution; see [licensing](docs/wiki/licensing.md) before moving or importing code.

The two browser applications and `design-system` use the root npm workspace and lockfile. Locally from the repository root, install with `npm ci --ignore-scripts`, then use the application’s existing `typecheck`, `test` and `build` commands. Keep one React installation for both apps and the shared components; do not restore declaration-only React aliases or per-app lockfiles. The separate `packages` workspace owns agent runtime dependencies and remains the image-build input.

Full native regression is explicit: locally from the public checkout, run `python3 terrier test regression`. The nightly GitHub workflow reuses this lane and the existing service qualifications. Ordinary PRs retain affected selection. See [test lanes](docs/wiki/test-lanes.md#nightly-deterministic-workflow) for schedule, report and acceptance limits.
