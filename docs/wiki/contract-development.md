The public contracts can be built and tested from the command line on macOS or Linux. This covers contract development; complete local product onboarding is still being implemented.

## Prepare and test

Install Python 3 and Foundry's `forge` command. Terrier finds `forge` on `PATH`, then in the usual `.foundry/bin` directory. Set `AGENT_TERRIER_FORGE` to select an explicit executable.

Run locally from the repository root:

```sh
./terrier contracts setup
./terrier contracts test
```

Setup downloads the exact public dependency revision and verifies its archive checksum from [foundry.lock](../../crates/agentkeys-chain/foundry.lock). It does not require an account, repository credentials, a submodule command or an operator script. The Solidity compiler version is pinned in [foundry.toml](../../crates/agentkeys-chain/foundry.toml).

After an initial successful build, run locally from the repository root to require cached dependencies and compiler:

```sh
./terrier contracts test --offline
./terrier contracts test --offline --match-test test_SetScope_RejectsNonMaster
```

The focused command is useful while editing. The complete suite remains available through the same CLI. An offline command fails if a required download is missing; it does not silently fetch it.

## Source and artifact ownership

The checked-in Solidity files are the source of truth. Terrier prepares a generated build copy in the local cache, containing only contract source, bytecode and the checksum-verified dependency. Relative library paths prevent workstation directories from entering Solidity metadata. The cache is regenerable and is not a second source tree to edit or publish.

`AGENT_TERRIER_CACHE_DIR` selects the cache directory; otherwise Terrier uses `XDG_CACHE_HOME/agent-terrier` or the home directory's `.cache/agent-terrier`. Build directories are isolated by checkout and locked while in use. Cleanup during synchronization removes stale source files only inside a marked build directory. Symlinks, unowned directories and unsafe dependency archives are refused.

The commands do not load deployment settings or wallet credentials from the shell, and they do not deploy contracts. Development signing, persistent local-chain startup and the full application quickstart are separate acceptance steps in [the local-chain issue](https://github.com/litentry/agent-terrier/issues/4).
