Use the CLI to select a bounded test lane. Ordinary iteration starts no browser, Docker container or model server. The commands below run locally from the public checkout.

| Lane | Who runs it | Scope | Warm target | Status |
|---|---|---|---|---|
| `focused --component …` | Developer or coding agent, local CLI | Selected Rust library/binary tests or UI/DSH component tests | 30 seconds | Available; measure build and execution separately |
| `source` | GitHub Actions on every PR/main push; also local CLI | Privacy, Python checks, web-server isolation and dependency closure | Within the 3-minute PR budget | Available |
| `core --component …` | GitHub Actions runs core on every PR/main push; developer or coding agent adds local component selection | Source lane, shared protocol, capability denials, protected files and selected component | 3 minutes; 5-minute budget reserved for future risk routing | Core wired into GitHub; automatic affected-component routing remains open |
| Deterministic full qualification | Planned nightly GitHub Actions | Actual chain/storage/Docker/CLI/API and limited browser integration | Scheduled; not part of ordinary PR wait | Existing individual qualifiers; consolidated scheduling remains open |
| Extended public qualification | Planned weekly/manual reviewed-revision runner | Clean install, downloaded real models, persistence and bounded platform coverage | Scheduled; record actual duration | Existing model qualifier; complete release scenario remains open |

These are targets, not measured hosted-runner guarantees. Cold setup is reported separately when the CLI performs it; cache restoration and queue time are outside this process. Fixture cleanup is included in test execution and is not separately measured. Reports mark those unmeasured values as null. A target miss does not skip tests or hide a failure.

```sh
python3 terrier test focused --component protocol
python3 terrier test focused --component runtime
python3 terrier test focused --component managed
python3 terrier test focused --component broker
python3 terrier test focused --component signer
python3 terrier test focused --component ui
python3 terrier test core --component storage
python3 terrier test source
python3 terrier test core --component broker --plan
```

Rust builds use locked, offline dependencies. Download them explicitly with `--online` when needed. Install an application's declared npm dependencies before selecting its component. The DSH and managed lanes use the single `packages` workspace: locally from the public checkout, run `npm ci --prefix packages --ignore-scripts`. DSH includes shared plugin tests and [runtime process checks](./local-agent-image.md). The separately selected managed lane builds the native daemon/controller and plugins, then tests automatic process startup, authorization, saved sessions and cleanup with fixture services; it requires no Docker, browser or model download. The core lane includes its cheap configuration validation, not those process builds. UI checks run component tests without a browser; they do not replace browser-specific acceptance. The daemon component currently exposes a pre-existing dependency on an unavailable private enrollment helper; it reports that failure and must not be treated as qualified until the product path is replaced.

The runner reports setup, compilation and test execution separately. Rust test executables come from Cargo's structured artifact output, and a zero-test or ignored-only run fails. Ignored tests are listed as ignored; they are never counted as evidence. Unavailable tools, build failures and timeouts fail. Timeouts terminate the owned process group.

For a machine-readable report, pass `--report` with a new absolute path outside the checkout. The file is private and is never overwritten. JSON goes to stdout; progress and the private diagnostic directory go to stderr. Review diagnostic logs before sharing them. GitHub Actions records the checked revision, publishes a timing summary and retains the structured core report for seven days; it does not upload raw diagnostic logs. Local runs identify themselves as a working copy without asserting a revision. This does not yet measure GitHub queue time or retain reviewed trace artifacts.

The hosted core job restores a cache keyed by the toolchain and dependency manifests. Only a successful main-branch push saves that cache. Checkout credentials are not persisted. The job has a 15-minute failure ceiling for initial toolchain/dependency builds; this is not its warm performance target. Cold and hosted timings still require measurement. The cheaper source job remains separate for early feedback.

Untrusted contributions run on GitHub-hosted infrastructure without private deployment credentials. A future personal-machine schedule must consume reviewed revisions only. This page describes public qualification; deployment checks belong to the deployment repository.

Local, in the public checkout: `./terrier test focused --component relay` runs model-relay unit, process-configuration and HTTP-flow tests with deterministic upstream fixtures. `./terrier test focused --component bundler` selects transaction-service unit/HTTP/receipt checks. Real-model and real-chain qualification remain separate explicit commands.
