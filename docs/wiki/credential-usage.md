# Credential Usage Guide

How to store, read, inject, and manage API keys with AgentKeys.

> **Breaking change in v0.x (issue #16):** the `agent` argument is now a `--agent` flag instead of a leading positional. Existing scripts using `agentkeys store 0xABC openrouter sk-xxx` must migrate to `agentkeys store --agent 0xABC openrouter sk-xxx`. Quick migration: `sed -i '' -E 's/agentkeys (store|read|run) (0x[0-9a-fA-F]+|[a-zA-Z0-9_-]+@[a-zA-Z0-9._-]+|[a-zA-Z][a-zA-Z0-9_-]*) /agentkeys \1 --agent \2 /g' your-scripts/*.sh`. Omit `--agent` entirely to default to the current session wallet.

## Storing credentials

```bash
agentkeys store <service-name> <api-key>                    # uses session wallet
agentkeys store --agent <wallet|alias> <service-name> <api-key>   # explicit target
```

The service name is a free-form string you choose. Pick names that match the env var convention your tools expect (see "Env var naming" below).

```bash
# Default form: stores against the current session's wallet
agentkeys store openrouter sk-or-v1-abc123
agentkeys store anthropic sk-ant-abc123

# Explicit target (sub-agent, alias, or different wallet)
agentkeys store --agent 0xAGENT openrouter sk-or-v1-abc123
agentkeys store --agent my-bot brave-search BSA-abc123
```

## Reading credentials (debug path)

```bash
agentkeys read <service-name>
agentkeys read --agent <wallet|alias> <service-name>
```

Prints the plaintext credential to stdout. Use for debugging only -- the credential crosses your terminal buffer and may end up in shell history.

```bash
agentkeys read openrouter                  # session wallet
agentkeys read --agent 0xAGENT openrouter  # specific wallet
agentkeys read --agent my-bot openrouter   # via alias
# prints: sk-or-v1-abc123
```

## Running with env injection (production path)

```bash
agentkeys run -- <command>
agentkeys run --agent <wallet|alias> -- <command>
```

Spawns a child process with credentials injected as environment variables. The credential never touches stdout, shell history, or the parent process's terminal buffer.

```bash
agentkeys run -- python my_agent.py                  # session wallet
agentkeys run --agent 0xAGENT -- python my_agent.py  # explicit
# my_agent.py sees OPENROUTER_API_KEY=sk-or-v1-abc123 in its environment
```

### Env var naming convention

The service name is converted to an env var name automatically:

```
SERVICE_NAME → upper-case, hyphens to underscores, + "_API_KEY" suffix
```

| Service name | Env var |
|---|---|
| `openrouter` | `OPENROUTER_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `brave-search` | `BRAVE_SEARCH_API_KEY` |
| `github` | `GITHUB_API_KEY` |

### When the convention doesn't match

Some tools expect non-standard env var names:

| Tool | Expected env var | AgentKeys convention | Mismatch? |
|---|---|---|---|
| OpenRouter | `OPENROUTER_API_KEY` | `OPENROUTER_API_KEY` | No |
| Anthropic | `ANTHROPIC_API_KEY` | `ANTHROPIC_API_KEY` | No |
| GitHub CLI | `GITHUB_TOKEN` | `GITHUB_API_KEY` | Yes |
| OpenAI | `OPENAI_API_KEY` | `OPENAI_API_KEY` | No |
| Brave Search | `BRAVE_SEARCH_API_KEY` | `BRAVE_SEARCH_API_KEY` | No |
| AWS | `AWS_SECRET_ACCESS_KEY` | `AWS_API_KEY` | Yes |

For mismatches, use `--env KEY=service` for explicit mapping:

```bash
agentkeys run --env GITHUB_TOKEN=github -- gh pr list
agentkeys run --agent 0xAGENT --env GITHUB_TOKEN=github -- gh pr list
```

Or use `read` + shell wiring:

```bash
GITHUB_TOKEN=$(agentkeys read --agent 0xAGENT github) gh pr list
```

### Recommended service names

Pick service names that produce correct env vars automatically. When in doubt, check what env var the tool expects and work backward:

| Tool expects | Store as | Result |
|---|---|---|
| `OPENROUTER_API_KEY` | `openrouter` | Match |
| `ANTHROPIC_API_KEY` | `anthropic` | Match |
| `OPENAI_API_KEY` | `openai` | Match |
| `GITHUB_TOKEN` | Use `--env` (planned) or `read` workaround | N/A |

## MCP credential delivery (daemon path)

For cloud LLM agents that connect via MCP, credentials are delivered through the MCP `get_credential` tool instead of env vars:

```
Agent → MCP get_credential("openrouter") → Daemon → Backend → Credential
```

The agent never sees the raw env var -- it calls the MCP tool and gets the credential in the response. This is the primary path for cloud LLM sandboxes (ChatGPT, Claude, Kimi Claw) where there's no shell to set env vars.

## Credential lifecycle

```bash
# 1. Store
agentkeys store --agent 0xAGENT openrouter sk-or-v1-abc123

# 2. Use (pick one)
agentkeys run --agent 0xAGENT -- python agent.py     # env injection (production)
agentkeys read --agent 0xAGENT openrouter             # stdout (debug only)
# or via MCP get_credential("openrouter")             # daemon/cloud path

# 3. Audit
agentkeys usage 0xAGENT                               # who read what, when

# 4. Rotate
agentkeys store --agent 0xAGENT openrouter sk-or-v1-NEW  # overwrite with new key

# 5. Revoke access
agentkeys revoke                                      # self-revoke: invalidate current session + wipe local keychain
agentkeys revoke 0xAGENT                              # revoke all active sessions for the given wallet

# 6. Tear down completely
agentkeys teardown 0xAGENT                            # delete all credentials + revoke all sessions
```

### Revoke vs teardown

| Command | Session tokens | Wallet | Credentials | When to use |
|---|---|---|---|---|
| `agentkeys revoke` (no args) | Current session invalidated + local keychain wiped | Survives on backend | Survive (inaccessible without a new session) | You're done for the day / device handoff |
| `agentkeys revoke 0xAGENT` | All active sessions for that wallet invalidated (ownership checked) | Survives | Survive | Kick a compromised child agent off — credentials stay so you can re-pair |
| `agentkeys teardown 0xAGENT` | All sessions revoked | Survives (account still exists) | **Deleted** | Fully retire an agent — credentials gone |

After `revoke`: re-running `init` (same mock token / OAuth) gives you a fresh session for the same wallet, and the old credentials are accessible again. After `teardown`: `init` gives a fresh session but starts with an empty credential set.

## Security comparison: `read` vs `run` vs MCP

| Path | Credential exposure | Use case |
|---|---|---|
| `agentkeys read` | Crosses stdout, visible in terminal, may land in shell history | Debugging, one-off checks |
| `agentkeys run` | Only in child process env, never in parent terminal | Local agent execution |
| MCP `get_credential` | Only in daemon memory, delivered over MCP pipe | Cloud LLM agents |

Always prefer `run` or MCP over `read` in production. See `wiki/key-security.md` for detailed security analysis.

## Env-var naming convention

When `agentkeys run` injects credentials it uses the convention:

```
SERVICE.to_uppercase().replace('-', '_') + "_API_KEY"
```

Examples:

| Service name stored | Env var injected |
|---|---|
| `openrouter` | `OPENROUTER_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `github` | `GITHUB_API_KEY` |
| `my-custom-llm` | `MY_CUSTOM_LLM_API_KEY` |

### Overriding with `--env KEY=SERVICE`

Some tools expect non-standard env var names (e.g. the GitHub CLI expects `GITHUB_TOKEN`, not `GITHUB_API_KEY`). Use `--env KEY=SERVICE` to map a credential to an arbitrary env var name:

```bash
agentkeys run 0xAGENT --env GITHUB_TOKEN=github -- bash deploy.sh
agentkeys run 0xAGENT --env OPENAI_API_KEY=openrouter -- python agent.py
```

`--env` overrides take priority over the auto-convention: if the same env var would be set by both the convention and an `--env` flag, the `--env` value wins.

Multiple `--env` flags are supported:

```bash
agentkeys run 0xAGENT \
  --env GITHUB_TOKEN=github \
  --env HF_TOKEN=huggingface \
  -- python train.py
```
