# Heima setup — FAQ

Troubleshooting + edge cases for [`docs/chain-setup.md`](https://github.com/litentry/agentKeys/blob/main/docs/chain-setup.md) + [`scripts/setup-heima.sh`](https://github.com/litentry/agentKeys/blob/main/scripts/setup-heima.sh).

## Q. `chain mismatch: profile says chain_id=X but RPC reports Y`

Step 3 caught a misconfigured RPC. Usually means `AGENTKEYS_CHAIN=heima` is set but the chain profile's `rpc.http` points at Paseo (or vice versa). Either:

- Edit the chain profile JSON in [`crates/agentkeys-core/chain-profiles/`](https://github.com/litentry/agentKeys/tree/main/crates/agentkeys-core/chain-profiles).
- Override per-run via `AGENTKEYS_CHAIN_PROFILE_FILE=./my-profile.json`.

Never set `AGENTKEYS_CHAIN=heima` and then point at a Paseo RPC — many downstream balance / nonce reads will return wrong-chain data.

## Q. Step 6 says "deploy skipped" but I expect a fresh deploy

`heima-bring-up.sh` runs `cast code` on every claimed address in `operator-workstation.env` and short-circuits if all six addresses already have bytecode on chain. Force a redeploy with:

```bash
# Clear the saved addresses for this chain, then re-run
PROFILE_UC=$(printf '%s' "${AGENTKEYS_CHAIN:-heima}" | tr 'a-z-' 'A-Z_')
sed -i.bak "/^.*_CONTRACT_ADDRESS_${PROFILE_UC}=.*/d" scripts/operator-workstation.env
bash scripts/setup-heima.sh --only-step 6
```

Mainnet deploys cost real HEI — confirm you actually want a redeploy before clearing.

## Q. Mainnet deploy refuses with "MAINNET_CONFIRM=1 required"

The mainnet path has a paranoid guard against accidental redeploys. Pass `MAINNET_CONFIRM=1` only when you're sure:

```bash
MAINNET_CONFIRM=1 AGENTKEYS_CHAIN=heima bash scripts/setup-heima.sh --only-step 6
```

## Q. Paseo step 5 (fund deployer) hangs

Paseo collators were halted at block 2,905,430 (frozen since 2026-01-15 per CLAUDE.md). When they're down, `heima-fund-account.sh` can't reach the chain. Three options:

- Wait for the parachain to recover.
- Switch to `--chain anvil` for local dev work.
- Switch to `--chain heima` mainnet (fund from your personal wallet — no sudo on mainnet).

## Q. K11 enrollment stub refuses on mainnet

Per arch.md §22b.1: stage-1 K11 stub on mainnet requires `AGENTKEYS_ALLOW_STAGE1_STUBS=1`. The flag exists to keep accidental stub enrollments off mainnet — the on-chain `length != 0` gate accepts stubs but the bytes aren't cryptographically bound.

For real Touch ID:

```bash
bash scripts/setup-heima.sh --webauthn
```

For one-time deliberate stub on mainnet (dev / debug):

```bash
AGENTKEYS_ALLOW_STAGE1_STUBS=1 bash scripts/setup-heima.sh
```

## Q. Step 12 (scope set) skipped — what now?

Step 12 needs a real K11 ceremony (master-mutation, not just creation). Re-run the orchestrator with `--webauthn`, or invoke `heima-scope-set.sh --webauthn` directly:

```bash
bash scripts/heima-scope-set.sh \
  --webauthn \
  --agent demo-agent \
  --services openrouter \
  --session-id alice
```

## Q. Why are steps 13 + 14 "intentionally append-only"?

The audit log + tier-A relay are designed to grow. Each re-run advances `entryCount` and adds a fresh row — that's the audit trail working as intended, not a regression. If you re-run setup-heima.sh weekly for sanity, the audit log will accumulate ~weekly rows.

To check the entry count any time:

```bash
cast call "$CREDENTIAL_AUDIT_ADDRESS_HEIMA" "entryCount()(uint256)" \
  --rpc-url "$(agentkeys chain show heima | jq -r .rpc.http)"
```

## Q. Per-step re-run fails with "missing session JWT"

Steps 9–13 read `~/.agentkeys/${SESSION_ID}/session.json` to derive the operator's `actor_omni`. If the JWT expired or was deleted, re-mint:

```bash
agentkeys init --session-id alice --email alice@example.com
```

Then re-run the orchestrator from the failing step.

## Q. `forge script` errors with "header validation error: `prevrandao` not set"

`forge script`'s simulator validates the chain's block header against the target EVM revision before broadcasting. Heima is a Substrate/Aura parachain via Frontier, so its header has no `prevrandao` field, and a `paris`+ simulator rejects it. Keep `evm_version = "london"` pinned in [`crates/agentkeys-chain/foundry.toml`](https://github.com/litentry/agentKeys/blob/main/crates/agentkeys-chain/foundry.toml) for the `forge script` deploy path; if you bumped it for unrelated reasons, revert. Note this is a *header-validation* workaround only — Heima's actual EVM execution level is **Cancun** (PUSH0 + transient storage run on-chain), not London. The full diagnosis is in CLAUDE.md "Heima EVM compatibility level".

## Q. Anvil contract addresses are different every run — is that wrong?

No. Anvil starts fresh per process; the deterministic deployer key + nonce-0 still produces the canonical first address (`0x5FbDB2315678afecb367f032d93F642f64180aa3` for P256Verifier), but `operator-workstation.env`'s pinned addresses are for the persistent chains (heima / heima-paseo), not for anvil. The `verify-heima-contracts.sh` flow + chain-namespaced env keys handle this — anvil reuses the deploy-time addresses for the lifetime of one anvil process.

## Q. I want to redeploy ONLY one contract

The atomic deploy is by design — each downstream contract takes the prior address via constructor, so partial redeploys break wiring. If you need a single-contract upgrade, use a proxy pattern (out of scope for stage-1) or do a full redeploy + update the env file.

## Related

- Operator runbook: [docs/chain-setup.md](https://github.com/litentry/agentKeys/blob/main/docs/chain-setup.md)
- Orchestrator: [scripts/setup-heima.sh](https://github.com/litentry/agentKeys/blob/main/scripts/setup-heima.sh)
- Per-step helpers: [scripts/heima-*.sh](https://github.com/litentry/agentKeys/tree/main/scripts)
- Live contract addresses: [docs/spec/deployed-contracts.md](https://github.com/litentry/agentKeys/blob/main/docs/spec/deployed-contracts.md)
- Cloud setup FAQ: [cloud-setup-faq](./cloud-setup-faq.md)
- CI setup FAQ: [ci-setup-faq](./ci-setup-faq.md)
