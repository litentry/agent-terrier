Troubleshooting + edge cases for [`docs/ci-setup.md`](https://github.com/litentry/agentKeys/blob/main/docs/ci-setup.md) + [`.github/workflows/harness-ci.yml`](https://github.com/litentry/agentKeys/blob/main/.github/workflows/harness-ci.yml).

## Q. The `harness-e2e` job always shows "skipped" — what gives?

That's the designed behavior until `TEST_OIDC_AWS_ROLE_ARN` is set as a repo secret. The preflight job emits a `::warning::` reminder. Until the operator finishes the 7-step bring-up in `docs/ci-setup.md`, only `rust-checks` runs — and that's enough to catch most regressions (600+ tests).

## Q. `AssumeRoleWithWebIdentity` returns `InvalidIdentityToken: No OpenIDConnect provider found`

AWS hasn't found the test broker's OIDC provider. Three checks:

1. The OIDC provider ARN matches the broker's `BROKER_OIDC_ISSUER` byte-for-byte (including scheme and trailing slash).
2. The broker's `.well-known/openid-configuration` is reachable from the public internet (curl from a random box, not just the runner).
3. The IAM trust policy on the test role lists the OIDC provider ARN under `Principal.Federated`.

## Q. `harness-e2e` runs but stage-3 fails with `AccessDenied` on the cross-actor write

That's the test working — stage-3 step 5 / 8 / 9 are NEGATIVE tests that EXPECT `AccessDenied`. If they pass-as-success, the workflow exits 0. If they pass with `AccessDenied`, the harness script asserts that (the per-actor + per-data-class invariants from CLAUDE.md). A genuine failure is the script exiting non-zero, not the AWS API returning `AccessDenied`.

## Q. Concurrent runs collide on S3 writes

Per-run prefix isolation via `CI_S3_PREFIX=ci/run-${GITHUB_RUN_ID}` should prevent this. If you see it anyway:

- Confirm `CI_S3_PREFIX` is being honored by every write site in the harness (currently `harness/v2-stage3-demo.sh` honors it; verify if you've added other harness steps).
- Make sure `concurrency.cancel-in-progress: true` is set in the workflow (it is — but a previous-run-in-flight can briefly overlap).

## Q. Test contract addresses drifted from the secrets

Happens when the operator redeploys the test contracts (e.g. after a `.sol` source change) but forgets to update the `TEST_*_HEIMA` secrets. Symptoms: stage-1 step 8 (verify-contracts) fails with "no bytecode at $SCOPE_ADDR".

**Fix:** re-read addresses from `scripts/operator-workstation.env` post-redeploy, update the six `TEST_*_HEIMA` secrets via the GitHub UI. Use the GitHub CLI:

```bash
for addr in SCOPE_CONTRACT_ADDRESS_HEIMA SIDECAR_REGISTRY_ADDRESS_HEIMA K3_EPOCH_COUNTER_ADDRESS_HEIMA \
            CREDENTIAL_AUDIT_ADDRESS_HEIMA P256_VERIFIER_ADDRESS_HEIMA K11_VERIFIER_ADDRESS_HEIMA; do
  val=$(grep "^${addr}=" scripts/operator-workstation.env | cut -d= -f2)
  gh secret set "TEST_${addr}" --body "$val"
done
```

## Q. The test deployer wallet ran out of HEI

CI doesn't redeploy on every run (it uses pinned addresses from secrets). The deployer wallet is only spent when the operator manually re-runs `setup-heima.sh` for the test instance. If it does run out:

```bash
# Check balance
cast balance "$(cast wallet address $(cat ~/.agentkeys/heima-deployer-test.key))" \
  --rpc-url "$(agentkeys chain show heima | jq -r .rpc.http)"

# Top up from your personal wallet — small float (~1 HEI) is enough
```

## Q. Manual dispatch errors with `inputs.stage` unrecognized

`workflow_dispatch.inputs` requires the workflow to be on the default branch (or your fork's default). If the workflow file landed on a feature branch, `gh workflow run` may fail. Either land it on `main` first, or push the feature branch and re-target:

```bash
gh workflow run harness-ci.yml --ref my-branch --field stage=3
```

## Q. Can the workflow run on every PR (not just operator-dispatched)?

It already does — push + pull_request triggers are wired in `on:` at the top. The gate is `TEST_OIDC_AWS_ROLE_ARN`, not the trigger. Every PR's `rust-checks` job runs unconditionally; the `harness-e2e` job runs only if the secret is set.

## Q. The workflow won't trigger on a PR from a fork

GitHub doesn't pass secrets to fork PRs by default — that's a platform security feature. The `harness-e2e` job will preflight-skip on fork PRs even with the secret set. Reviewer needs to push the fork branch to the upstream repo or manually dispatch the workflow from the PR page.

## Q. `aws-actions/configure-aws-credentials` succeeds but `aws sts get-caller-identity` says `agentkeys-admin`

You forgot to update the role ARN secret after rotating to OIDC. The default credential chain falls through to whatever AWS profile is on the runner image. Set `TEST_OIDC_AWS_ROLE_ARN` to the GitHub Actions OIDC role ARN (not the admin user ARN), and the OIDC web identity will assume the right role.

## Q. Why is `--test-threads=1` on `cargo test`?

Per the existing `@claude` review workflow convention: broker integration tests mutate process-global `$HOME` + `$AWS_*` env, and the keyring tests serialize on a per-process accounts map. Concurrent threads see each other's mutations and flake. Single-threaded test execution is the conservative default; per-test isolation cleanup is a future improvement.

## Q. CI runs are slow — anything to tune?

- `Swatinem/rust-cache@v2` with `shared-key: harness-ci` is enabled — both jobs share a cache.
- `concurrency.cancel-in-progress: true` cancels stale runs on a re-push.
- Foundry toolchain is the slowest install; pin to `version: stable` for cache hits.
- The 60-minute timeout on `harness-e2e` is generous; typical run is 20–30 min.

If runs still feel slow, profile with `gh run view <run-id> --log-failed | head -50` to find the longest step.

## Q. Where do I read the harness logs after a failure?

Each harness script writes a temp dir under `/tmp/agentkeys-*`. The workflow uploads `/tmp/agentkeys-ci-ephemeral-*/` as the `ephemeral-stack-logs` artifact on failure (for the harness-e2e job). Download via `gh run download <run-id>`.

## Related

- Operator runbook: [docs/ci-setup.md](https://github.com/litentry/agentKeys/blob/main/docs/ci-setup.md)
- Workflow file: [.github/workflows/harness-ci.yml](https://github.com/litentry/agentKeys/blob/main/.github/workflows/harness-ci.yml)
- Cloud setup FAQ: [cloud-setup-faq](./cloud-setup-faq.md)
- Heima setup FAQ: [heima-setup-faq](./heima-setup-faq.md)
