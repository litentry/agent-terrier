**Status: local development acceptance passed for the recorded configuration.** The [machine-readable manifest](../qualification/localhost-macos-arm64-2026-11-03.json) records the independent public build, exact image, offline application check, browser checks and measurements. The release remains open while [hosted-history review](https://github.com/litentry/agent-terrier/issues/2) awaits confirmation. A current-source privacy review does not certify retained historical content.

## Tested configuration

The final application source is `c274e54f670750a757fc05c37a15061b5ba6d476`. It was fetched into an independent anonymous public checkout and built without private source inputs. The recorded Linux arm64 runtime image is `sha256:71412c2f934a337b3ec9c3476948d81a3fb9d6f58048a8e8bc960acefce2b23c`. It was built locally using the public Dockerfile; no prebuilt registry image is promised.

The manifest pins Cargo/npm/contract inputs, Rust 1.96.0, Solidity 0.8.20, contract set 0.5.1 and the [model recipe](../../presets/local-models.json): Ollama 0.34.4, Qwen3 1.7B chat and Nomic embedding v1.5. Use the [quickstart](./quickstart.md) and [image instructions](./local-agent-image.md) to build this source. Record the image ID produced by your build; locked inputs do not imply bit-identical image output across builders.

| Environment | Evidence | Boundary |
| --- | --- | --- |
| macOS 15.7.4 arm64, Apple M3 Pro, 18 GiB RAM; Linux arm64 Docker image | Independent public setup, local chain/owner/storage, real models, CLI, browser journeys and stateful restart | This is measured hardware, not a minimum requirement or a broad hardware matrix |
| GitHub-hosted Linux x86_64 | [Core source/security run](https://github.com/litentry/agent-terrier/actions/runs/41579666251) on the final source; [earlier deterministic nightly](https://github.com/litentry/agent-terrier/actions/runs/41277417261) including image/Docker/service checks | Earlier nightly results apply to their recorded revision; they do not qualify Linux real-model or physical-browser behavior |
| Other hosts, model pairs and physical authenticators | Not qualified | Run the relevant scenarios before claiming support |

## Acceptance evidence

The [quickstart](./quickstart.md) was walked through from the public checkout with fresh state: prepare/test contracts, build native/browser/image inputs, start the stack, probe actual models, register/login an owner, create an agent, receive real model output, plant/read knowledge, stop/start and read the retained knowledge. Downloads and build caches were reused; no previous application state or company account was needed. The manifest preserves that walkthrough's exact source rather than attributing its timings to a later revision.

The final-source offline check took **116.942 seconds**. The operating-system restriction rejected an external socket while allowing local loopback and Unix controls. The same scenario then exercised real chain authority, local signing, a container with networking disabled, supervised inference, publish tools, correlated channel replies, persistent semantic knowledge, grant removal, foreign-owner denials, conversation recovery, model restart, revocation and retained data. Knowledge reached `ready`; the channel reply took 2.245 seconds. Negative cases checked the specific refusal and unchanged protected state or usage, with permitted operations as positive controls.

Computer use separately exercised the actual website with a temporary Chrome virtual authenticator: public approval download, owner CLI approval, PRF sign-in, logout/repeat sign-in, agent creation, local-model chat, browser notes read through the CLI, CLI notes shown after restart, and browser-created credentials read by the same owner's CLI. An interrupted creation recovered after service restart without a second chain submission; the chain height stayed unchanged and one runtime context remained. Automated real-chain parity checks also rejected a foreign owner and an invalid session without changing stored ciphertext.

Browser evidence retains its tested revisions in the manifest. The product source after the credential-parity fix is identical to the final candidate; the intervening change affected test orchestration, fixtures and their documentation. This is bounded acceptance of the listed journeys, not every console feature. Screenshots, local identities, keys and raw traces are excluded from public evidence.

## Measured timings

| Check | Executor | Measured result | Interpretation |
| --- | --- | --- | --- |
| Recorded source/test PR | GitHub Actions | 152 seconds from run creation to completion; 8 seconds to core job start | Within the proposed 3-minute warm target for this change |
| Final-source main check | GitHub Actions | 172 seconds total; 3 seconds to core job start | Separate source and core jobs run concurrently |
| Main core job setup | GitHub Actions | 14 seconds before the CLI; another 4.173 seconds inside the CLI | Checkout/cache/toolchain setup is not hidden inside test execution |
| Main compilation and execution | GitHub Actions | 102.225 seconds build; 13.204 seconds execution | Core lane total 119.617 seconds |
| Main post-test work | GitHub Actions | 2 seconds report upload; 30 seconds cache save | Post-action cleanup rounded to zero at the API's timestamp resolution; fixture cleanup is included in execution |
| Local core lane | Developer/coding agent on the measured Mac | 35.615 seconds, including 8.941 build and 26.662 execution | No browser, Docker or model server startup |
| Fresh native output in the public checkout | Developer/coding agent on the measured Mac | 81.370 seconds | Dependency downloads were cached; not an empty-machine installation time |
| Final candidate native/WASM/console/display rebuilds | Developer/coding agent on the measured Mac | 15.407 / 1.338 / 4.640 / 1.125 seconds | Reused compatible local build output |
| Final runtime image rebuild | Local Docker | 104.757 seconds | Reused compiler/base caches |
| Complete offline application scenario | Developer/coding agent on the measured Mac | 116.942 seconds | Scheduled/manual qualification, outside the ordinary PR lane |

The manifest links the two completed hosted runs. Run creation to job start is observable scheduling delay, not a provider-internal queue metric. Full cold toolchain/model/dependency download times and independently timed fixture cleanup were not captured; they are not reported as zero. Focused <=30 seconds, ordinary cached PR <=3 minutes and risk-sensitive review <=5 minutes remain targets, not guarantees. The existing runner uses the stricter 3-minute core/affected target and reports misses; no required test is skipped to meet a budget. Expensive deterministic checks remain nightly, and real-model/clean-setup/mutation checks remain weekly or manual as described in [test lanes](./test-lanes.md).

## Exact-artifact privacy review

The final image review scanned 3,144 regular files across all 15 layers, printable binary strings, image configuration and build history. The scanner reported 60 matches: 52 in unchanged pinned public base content and eight in unchanged public dependency build paths or examples. The base layers were matched by digest; dependency files were byte-compared with integrity-checked locked public archives. There were **zero first-party and zero unreviewed findings**. This is a provenance-reviewed scan, not a claim that the raw scanner reported zero.

The final console static output (15 files), display output (15 files) and WASM package (six files) passed the public scan. The Dockerfile-specific context allowlist excludes state, keys, local build output and source-control history. New documentation and the rendered wiki are reviewed separately before publication. Source and generated references are canonical; private logs and screenshots are not copied into the wiki. Pattern scanning remains a supplement to review, not proof against arbitrary encoded content.

## Known limits

- Local software signing trusts the host administrator and provides no production wallet custody or TEE guarantee. Use fresh development identities only.
- Browser acceptance uses a virtual authenticator. Physical PRF-capable devices, display enrollment and unlisted browser workflows require separate checks.
- Owner-encrypted v3 credentials are readable through the owner CLI; delegated decryption of that format is unavailable. The development CLI's worker-encrypted path has separate delegated-read tests.
- Optional audit archive, speech and OpenViking engine integrations are unavailable or unqualified. Canonical persistent knowledge works without OpenViking. Individual capability-ID revocation is unavailable; chain scope/device revocation and expiry remain enforced.
- Browser pending transactions are in memory. Keep the tab open until completion; reload or sign-out loses the recovery record.
- Disk controls detect low space and excess usage; they are not hard per-agent filesystem quotas.
- Same-version restart, retained data and bounded port-manifest migration have evidence. Arbitrary old-state upgrades, production data migration and bit-identical builds are not promised.
- The source/image combination is recorded, but a general binary registry release and retained hosted-history clearance have not been completed.

Historical reports keep their original results, including failures and unqualified paths. New evidence supersedes their scope only where this page explicitly records another check.
