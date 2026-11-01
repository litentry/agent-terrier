This reference is generated from the public `terrier` command parser. Run commands locally from the repository root. Regenerate it with `python3 scripts/generate-cli-reference.py`; the source test lane rejects stale output.

See [local services](./local-services.md), [local agents](./local-agents.md) and [test lanes](./test-lanes.md) for prerequisites, state effects and measured qualification. Every signing identity is development-only. Command availability does not imply complete browser or release acceptance.

## terrier

Agent Terrier local development tools

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| subcommand | yes | manage, stack, test, models, contracts, chain, services, cred, agent, owner, device | Select a command below. |

## terrier manage

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |

## terrier stack

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| action | yes | start, status, doctor, logs, stop, restart |  |
| --chain-port | no |  | Loopback RPC port; defaults to the saved profile |
| --bin-dir | no |  |  |
| --broker-port | no |  |  |
| --runtime-image | no |  |  |
| --docker-socket | no |  |  |
| --model-dir | no |  | Own a local model runner using predownloaded models |
| --model-binary | no |  | Installed Ollama executable; requires --model-dir |

## terrier test

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| lane | yes | source, core, focused, affected, qualification |  |
| --component | no | protocol, runtime, broker, signer, relay, bundler, daemon, storage, cli, ui, display, dsh, managed |  |
| --changed-file | no |  | Changed repository-relative path; include old and new paths for renames |
| --changed-files-json | no |  | JSON array of changed repository-relative paths |
| --online | no |  | Explicitly fetch Cargo dependencies before Rust tests |
| --report | no |  | New JSON report path outside the checkout |
| --plan | no |  | Print selection without running tools |

## terrier models

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| action | yes | config, probe |  |
| --base-url | no |  |  |
| --chat-model | no |  |  |
| --embedding-model | no |  |  |

## terrier contracts

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| action | yes | setup, build, test |  |
| --offline | no |  | Use downloaded dependencies only |
| --match-test | no |  | Run matching contract tests |

## terrier chain

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| action | yes | start, status, stop, logs, deploy |  |
| --port | no |  | Loopback RPC port for chain start |
| --offline | no |  | Deploy using downloaded dependencies only |
| --resume | no |  | Explicitly resume an interrupted deployment |

## terrier services

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| action | yes | start, status, doctor, logs, stop |  |
| --bin-dir | no |  | Directory containing built public service binaries |
| --broker-port | no |  | Broker port for the first service startup |
| --runtime-image | no |  | Enable the managed runtime with a reviewed preloaded local image |
| --docker-socket | no |  | Explicit local Docker Unix socket; required with --runtime-image |
| --model-dir | no |  | Own a local model runner using predownloaded models |
| --model-binary | no |  | Installed Ollama executable; requires --model-dir |

## terrier cred

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| action | yes | store, fetch |  |
| service | yes |  |  |
| --name | yes |  | Local owner name |
| --secret-stdin | no |  | Read exact UTF-8 input for store |

## terrier agent

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| subcommand | yes | spawn, archive, receipt, bridge | Select a command below. |

## terrier agent spawn

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| --name | yes |  | Existing local owner name |
| --memory-ns | no |  |  |
| --label | yes |  |  |
| --preset-id | no |  |  |
| --memory-inherited | no |  |  |

## terrier agent archive

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| --name | yes |  | Existing local owner name |
| --memory-ns | no |  |  |
| --device-key-hash | yes |  |  |

## terrier agent receipt

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| --name | yes |  | Existing local owner name |
| --user-op-hash | yes |  |  |

## terrier agent bridge

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| --name | yes |  | Existing local owner name |
| --device-key-hash | yes |  |  |
| --sandbox-id | no |  |  |
| --path | yes |  | Existing broker-allowlisted route |
| --method | no | GET, POST |  |
| --json-stdin | no |  |  |
| --timeout-seconds | no |  |  |

## terrier owner

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| action | yes | register, grant, revoke, bind, unbind, login |  |
| --name | yes |  | Local owner name |
| --actor-omni | no |  |  |
| --service | no |  |  |
| --read-only | no |  |  |
| --enrollment-file | no |  |  |
| --broker-url | no |  | Loopback broker endpoint for owner login |

## terrier device

| Argument | Required | Choices | Description |
| --- | --- | --- | --- |
| -h, --help | no |  | show this help message and exit |
| action | yes | identity |  |
| --name | yes |  |  |
| --operator-omni | yes |  |  |
| --label | yes |  |  |
| --kind | yes | device, delegate |  |

