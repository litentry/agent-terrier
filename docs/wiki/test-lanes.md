Use the CLI to select a bounded test lane. Ordinary iteration starts no browser, Docker container or model server. The commands below run locally from the public checkout.

| Lane | Who runs it | Scope | Warm target | Status |
|---|---|---|---|---|
| `focused --component …` | Developer or coding agent, local CLI | Selected Rust library/binary tests or UI/DSH component tests | 30 seconds | Available; measure build and execution separately |
| `affected --changed-file …` | GitHub Actions on every PR; developer or coding agent, local CLI | Core checks plus changed workspace packages and their transitive consumers | Same 3-minute PR target; broad changes can exceed it | Wired into the hosted PR job; complete hosted timing evidence remains open |
| `source` | GitHub Actions on every PR/main push; also local CLI | Privacy, Python checks, web-server isolation and dependency closure | Within the 3-minute PR budget | Available |
| `core --component …` | GitHub Actions runs core on every PR/main push; developer or coding agent adds local component selection | Source lane, shared protocol, capability denials, protected files and selected component | 3 minutes; 5-minute budget reserved for future risk routing | Core runs on every PR/main push; PRs add affected components |
| `qualification --component storage` | Developer or coding agent, explicit local CLI; GitHub Actions nightly | Existing real-chain object/worker/broker/CLI scenarios and shared client tests | Record actual duration; no PR budget | Available; no model or browser startup |
| Deterministic regression and qualification | GitHub Actions nightly and manual dispatch | Full native targets, component checks, actual chain/storage/Docker/CLI/API, built-web boundary and synthetic provisioner browser fixtures | Scheduled; not part of ordinary PR wait | [Hosted run passed](https://github.com/litentry/agent-terrier/actions/runs/41277417261) for its recorded revision; product browser enrollment remains open |
| `qualification --component security --revision …` | Developer or coding agent, explicit local CLI; weekly Codex schedule on the maintainer Mac | Four isolated guard mutations with existing positive/negative tests | Outside ordinary PR budget | Available; schedule configured, first scheduled execution not yet recorded |
| Extended public qualification | Weekly Codex schedule on the maintainer Mac; manual local CLI | Clean install, downloaded real models, persistence and bounded platform coverage | Scheduled; record actual duration | Existing model qualifier is scheduled; independent clean install and complete release acceptance remain open |

These are targets, not measured hosted-runner guarantees. Cold setup is reported separately when the CLI performs it; cache restoration and queue time are outside this process. Ordinary fixture cleanup is included in test execution; security qualification records its disposable-copy cleanup separately. Reports mark those unmeasured values as null. A target miss does not skip tests or hide a failure.

```sh
python3 terrier test focused --component protocol
python3 terrier test focused --component runtime
python3 terrier test focused --component managed
python3 terrier test focused --component broker
python3 terrier test focused --component cli
python3 terrier test focused --component signer
python3 terrier test focused --component ui
python3 terrier test core --component storage
python3 terrier test source
python3 terrier test core --component broker --plan
python3 terrier test affected --changed-file crates/agentkeys-gate/src/lib.rs --plan
```

Rust builds use locked, offline dependencies. Download them explicitly with `--online` when needed. Install browser dependencies from the root workspace with `npm ci --ignore-scripts` before selecting the UI component. The DSH and managed lanes use the single `packages` workspace: locally from the public checkout, run `npm ci --prefix packages --ignore-scripts`. DSH includes shared plugin tests and [runtime process checks](./local-agent-image.md). The separately selected managed lane builds the native daemon/controller and plugins, then tests automatic process startup, authorization, saved sessions and cleanup with fixture services; it requires no Docker, browser or model download. The core lane includes its cheap configuration validation, not those process builds. UI checks run component tests without a browser; they do not replace browser-specific acceptance. The daemon component covers chain-confirmed local binding cleanup. The services qualification includes explicit destructive stack reset using disposable state; the Docker qualifier covers owned runtime removal and foreign-stack preservation. Full browser acceptance remains separate.

The runner reports setup, compilation and test execution separately. Rust test executables come from Cargo's structured artifact output, and a zero-test or ignored-only run fails. Ignored tests are listed as ignored; they are never counted as evidence. Unavailable tools, build failures and timeouts fail. Timeouts terminate the owned process group.

For a machine-readable report, pass `--report` with a new absolute path outside the checkout. The file is private and is never overwritten. JSON goes to stdout; progress and the private diagnostic directory go to stderr. Review diagnostic logs before sharing them. GitHub Actions records the checked revision, publishes a timing summary and retains the structured core report for seven days; it does not upload raw diagnostic logs. Ordinary local runs identify themselves as a working copy without asserting a revision; security qualification records its explicitly selected source revision and recipe digest. This does not yet measure GitHub queue time or retain reviewed trace artifacts.

The hosted core/affected job restores a cache keyed by the toolchain and dependency manifests. Only a successful main-branch push saves that cache. Checkout credentials are not persisted. The job has a 15-minute failure ceiling for initial toolchain/dependency builds; this is not its warm performance target. Cold and hosted timings still require measurement. The cheaper source job remains separate for early feedback.

Untrusted contributions run on GitHub-hosted infrastructure without private deployment credentials. A future personal-machine schedule must consume reviewed revisions only. This page describes public qualification; deployment checks belong to the deployment repository.

Local, in the public checkout: `./terrier test focused --component relay` runs model-relay unit, process-configuration and HTTP-flow tests with deterministic upstream fixtures. `./terrier test focused --component bundler` selects transaction-service unit/HTTP/receipt checks. Real-model and real-chain qualification remain separate explicit commands.

The CLI component includes native local-agent HTTP tests for redirect, proxy and remote-endpoint refusal plus receipt tests for partial completion and lost-response recovery without resubmission. It starts no Docker container. The explicit [agent lifecycle qualifier](./local-agents.md#explicit-qualification) requires a reviewed preloaded image and local Docker socket.

The explicit storage lane is documented in [local storage](./local-storage.md#test-lanes-and-evidence). It forwards only the explicit contract-cache/compiler/tool selectors beyond the scrubbed tool environment, reuses all existing fixtures and rejects empty or skipped-only qualification output. Real-worker fixtures verify that the selected ignored Rust test actually ran. No new scenario supervisor or signing implementation is introduced.

## Built web boundary check

Locally from the public checkout, after installing browser dependencies and building the shared WASM client:

```sh
python3 terrier test qualification --component ui
```

This explicit lane reuses the fast UI checks, then builds and serves the real console on a disposable loopback port. It verifies the root page and a JavaScript asset, then requires the removed anonymous development routes to return HTTP 404 with no request to a controlled test bridge. The bridge has a positive control and synthetic responses only. The test uses an explicitly unavailable application backend and no host credentials; it is an HTTP boundary check, not authenticated browser acceptance. Build and server logs are retained privately on failure. Ordinary UI iteration still starts no server or browser.

## Affected changes

Locally from the public checkout, pass each changed repository-relative path with `--changed-file`, or provide a JSON array using `--changed-files-json`. Include both previous and current paths for renames and paths of deleted files. The selector covers native library tests and existing curated component suites; directly changed native integration-test directories also select their integration targets. The selector reads Cargo’s current workspace metadata and follows reverse path dependencies transitively; it does not maintain a second dependency graph. Source/privacy and core authorization negatives always run. UI/display and runtime-plugin paths add their canonical component suites. The structured plan/report records the selection and the path owners.

Unknown paths and packages without a supported test target fail with an explicit mapping error. Contract changes select the shared Foundry unit runner; provisioner changes select type checking and deterministic component tests without a browser. Workspace manifests and shared fixtures conservatively expand to all workspace consumers. This first selector covers current workspace consumers, not downstream repositories, a removed package’s former dependency graph or full integration qualification. Hosted collection binds the complete file list to the event’s exact base/head merge revision. It keeps deleted and both renamed paths, rejects stale revisions, missing pages and duplicate entries, and refuses changes larger than the [GitHub API’s 3,000-file bound](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files). Split such a change before rerunning. The read-only collection token is present only in that step; test children do not inherit it. The nightly workflow reuses these CLI owners; weekly real-model/clean-install qualification remains open.

The generated display route tree is ignored; the framework and route generator own it. The display component generates its route types, checks TypeScript and runs component tests without starting a browser. Local command from the public checkout: `python3 terrier test focused --component display`. Install the root browser dependencies and build the shared WASM client first, as for the console.

The PR job prepares browser/plugin dependencies only when the canonical plan selects those components. Browser setup builds the shared WASM client; tests still use component runners without a headless browser. Setup before the CLI is outside its timing report. The dataset CLI has no standalone test target: broad native selection records an explicit compile check, while its catalog validation library retains its own tests. A compile check is not counted as a passing test. Unknown ownership still fails with an explicit mapping requirement. Complete integration qualification is separate from these fast checks.

## Contract and provisioner lanes

Local, from the public checkout:

```sh
python3 terrier test focused --component contracts
python3 terrier test focused --component provisioner
python3 terrier test qualification --component provisioner
```

Contract checks call the existing contract build/test owner, using its verified archive, compiler pin and optional explicit compiler selector. Add `--online` to permit dependency/compiler preparation; the default uses prepared inputs only. Foundry suite counts must contain a positive executed-test count and zero failures; empty or skipped-only output fails. These unit checks use the local EVM simulator and start no RPC node.

Install provisioner dependencies locally with `npm ci --prefix provisioner-scripts --ignore-scripts`. Its default npm test command runs component tests only. The explicit qualification additionally selects its existing browser fixtures. Prepare their browser locally with `npm exec --prefix provisioner-scripts -- playwright install chromium`. Those tests use synthetic pages and mocked email/provider clients; they neither create real accounts nor qualify the product's browser enrollment. Their raw diagnostic logs are private and are not uploaded automatically.

## Reusable service qualification

Local, after building the public service binaries and preparing contract dependencies:

```sh
python3 terrier test qualification --component chain --component services --component storage
```

The chain selection reuses deployment, signing, binding, owner, login and transaction-service scenarios. Services reuses full backend restart and cleanup checks. Storage keeps its existing seven-scenario selection. The chain, services, agents and website selections are refused by ordinary focused/core lanes; real services are never silently started on a PR.

The explicit `qualification --component agents` selection reuses the existing real-contract Docker lifecycle scenario. Set `AGENT_TERRIER_TEST_AGENT_IMAGE` to a reviewed preloaded image and `AGENT_TERRIER_TEST_DOCKER_SOCKET` to the local Unix socket. Missing inputs fail. The runner forwards these explicit selectors only for that qualification; it does not inherit unrelated runtime or model settings. This deterministic lane does not claim real-model or complete browser acceptance.

## Nightly deterministic workflow

The public qualification workflow runs nightly at 02:23 UTC and can be dispatched manually. It runs on an isolated GitHub-hosted Linux runner with read-only repository permission, no deployment credentials and no model downloads. GitHub schedules use the default branch and can be delayed; see [GitHub schedule semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule). Manual dispatch records the selected revision.

The PR and nightly workflows share one component setup action for Node, contract tooling, browser build dependencies and plugins. The nightly job prepares public dependencies, runs the complete native workspace targets, strict formatting/lint and component lanes, builds service executables and an image from that revision, then invokes the existing chain/service/storage/agent/UI/provisioner qualifications and the prebuilt website lifecycle qualifier. The built image stays on that disposable runner; this workflow publishes no image or release. Its two-hour failure ceiling is a cold-build bound, not a performance target. [Run 41277417261](https://github.com/litentry/agent-terrier/actions/runs/41277417261) passed for `b8f9da88771f6c0411f9c8350d9e6752b38f7b99`: native regression 368.455 seconds, component checks 138.712 seconds and service qualification 580.877 seconds. Image build and managed Docker isolation also passed. These are separate job-step measurements, not a total pipeline or later-revision guarantee.

Local, from the public checkout, the native step is:

```sh
python3 terrier test regression --report "${TMPDIR:?Set a temporary directory}/native-regression.json"
```

Choose a new report path for every run. This explicit lane builds all native test targets, then executes the workspace suite. The report separates build from execution and records aggregate passed/failed/ignored counts. Empty or ignored-only aggregate results fail; ignored tests are not qualified by that result. Explicit chain/storage/Docker scenarios provide separate integration evidence. Component flags cannot narrow the regression lane. Ordinary PRs continue using affected selection.

Only structured reports are retained for seven days. They include the tested revision, platform, timings, counts and failures; raw logs and generated development state are not uploaded. A missing report is labeled incomplete. Cache saves require a successful main-revision job. The schedule neither submits fixes nor promotes production. A separate weekly Codex schedule requests the existing real-model and isolated mutation checks on the maintainer Mac. Independent installation and authenticated product browser acceptance remain separately tracked work.

`qualification --component website` starts the real prebuilt console through the existing service owner, checks origin isolation and restart/cleanup, and launches no browser. It requires prepared service binaries and website output. Full authenticated browser flows remain separate.

Cargo packages can declare `package.metadata.terrier.qualification-only-tests` for integration targets that require external local services. When affected, these targets still compile in the fast lane; the plan/report names them as compile-only and lists deferred qualification. Ordinary integration targets still execute, and unknown target declarations fail. The nightly workflow explicitly executes the managed Docker isolation/disk qualifier with its reviewed image. An ignored test is never reported as an executed pass.

Selected native suites compile in one Cargo invocation, then the CLI runs only the requested package/target binaries with their original test filters and working directories. Workspace metadata and Cargo artifact records bind each executable to its package, manifest, target kind and name. Missing or ambiguous artifacts fail the lane. Qualification-only targets remain compile-only in ordinary checks. This avoids repeated dependency builds without dropping selected authorization tests or starting a browser.


## Isolated security guard checks

Weekly or explicitly on a prepared developer Mac, from the public jj checkout:

```sh
python3 terrier test qualification --component security --revision "${REVIEWED_PUBLIC_REVISION:?Set the exact reviewed public commit}" --report "${TMPDIR:?Set a temporary directory}/security-qualification.json"
```

This bounded selection needs jj and downloaded Cargo dependencies. It exports only regular tracked files from that exact revision into a new private temporary directory, applies the public privacy gate, and uses a separate build directory. It starts no product service, browser, Docker container or model. It never changes the active checkout or deploys a mutated binary. Run only reviewed source on a personal machine; untrusted contributions belong on isolated hosted runners.

Four fixed mutations disable the operation, data-class, chain-scope or actor-proof guard, one at a time. The existing authorized positive and specific negative tests must first pass on the original source. After each mutation, the positive control must still pass and the exact negative test must fail with its expected assertion. A compilation failure, timeout, missing test, ignored test, crash or unexpected error is a qualification failure. These checks establish that the selected tests detect those specific missing guards; they do not prove every possible security defect is covered. Real boundary scenarios separately verify denials and unchanged state.

Source and build copies are removed after both success and failure; private logs remain in the reported diagnostics directory. The structured report records the exact source revision, content-manifest digest, guard outcomes, build/execution and cleanup timings. Dependencies stay in the ordinary download cache, while compiled mutation artifacts are never shared with product builds. This intentionally incurs a cold build and remains outside ordinary PR checks. The weekly local agent run below requests this check; its first scheduled execution remains unverified.

The [reviewed macOS arm64 report](../qualification/security-guards-macos-arm64.json) records all four detected mutations against `8aac8193cc6de6ac34d434a124b5a605ae6c4211`: 68.587 seconds total, including 5.001 seconds source setup/privacy, 60.229 seconds compilation, 2.937 seconds test execution and 0.394 seconds cleanup. It used a new build directory with already-downloaded dependencies. Eight baseline checks and four mutated positive controls passed; all four exact negative assertions caught their disabled guard. This is bounded mutation evidence, not complete security or release certification.

## Weekly local agent run

The maintainer's Codex schedule requests a run every Sunday at 09:00 local time. It selects an exact reviewed public revision in an owned jj workspace, runs the available canonical security, Docker and prepared-model qualifications, and keeps raw diagnostics and generated identities private. Configuration of that schedule is not evidence of a completed scheduled run. Missing preparation or an unavailable acceptance scenario is reported as incomplete.

The scheduled agent may reproduce a new failure, implement a scoped correction, run local validation and privacy review, and submit or update a fix PR. It deduplicates existing work and does not merge those scheduled PRs. It preserves unrelated local services and active development. The automation is configured in the maintainer's Codex app; cloning this repository does not install it. Complete independent clean-install coverage remains open.
