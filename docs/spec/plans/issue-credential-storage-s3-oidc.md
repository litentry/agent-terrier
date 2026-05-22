# Replace mock-server `/credential/*` with S3-backed encrypted storage (OIDC-scoped, PrincipalTag-isolated)

_Draft body for a new GitHub issue on `litentry/agentKeys`. Filed via:_

```bash
gh issue create --repo litentry/agentKeys \
  --title "Replace mock-server /credential/* with S3-backed encrypted storage (OIDC-scoped, PrincipalTag-isolated)" \
  --label "stage-7+,architecture,credential-storage" \
  --body-file docs/spec/plans/issue-credential-storage-s3-oidc.md
```

---

## Context

[arch.md §9 #10](../../docs/arch.md#L608) flags the mock-server backend (`agentkeys-backend.service` on `127.0.0.1:8090` on the deployed broker host) as **legacy and pending deprecation**:

> Backend (mock-server) — Legacy `/session/*` + `/credential/*` + `/audit/*` (broker's Tier-2 reachability target; **will be deprecated as callers migrate to the new flow**)

[arch.md §11](../../docs/arch.md#L670) explicitly forbids exposing this backend publicly:

> The legacy backend at `:8090` is **never** publicly exposed; only the broker on the same host reaches it.

The "new flow" the deprecation comment references is **not yet defined** in arch.md. Today this manifests as a real operator-facing failure: `agentkeys provision openrouter` succeeds end-to-end at the scrape, mints a real `sk-or-v1-...` API key, and then fails at `backend.store_credential` because the CLI's `--backend http://localhost:8090` default points at a mock-server that isn't running on the operator's laptop (and *can't* be reached on the broker host per §11). The masked key shown in the error message is unrecoverable without manually copy-pasting from the scraper's stdout — fragile.

## Proposed replacement — S3 + OIDC + client-side encryption

Reuse the auth + isolation infrastructure that already enforces per-operator boundaries for the SES inbound-mail routing (issue #83) and the §5.1 OIDC workflow:

| Concern | Today (mock-server) | Proposed (S3 + OIDC) |
|---|---|---|
| **Where credentials sit** | SQLite on the operator workstation OR :8090 on broker host (loopback) | `s3://$BUCKET/bots/<wallet>/credentials/<service>.enc` |
| **Access control** | Process-local | OIDC-assumed `agentkeys-data-role` + bucket-policy PrincipalTag scoping (already in place — same path the SES Lambda routes into) |
| **Encryption at rest** | None (cleartext SQLite) | Client-side AES-256-GCM with a wallet-derived KEK (signed via dev_key_service `/dev/sign-message` or HKDF over a stable wallet-bound secret) — broker never sees the plaintext |
| **Cross-operator isolation** | None (single SQLite DB) | Bucket-policy + PrincipalTag (cloud-enforced — same federation-isolation rule as cloud-setup.md §4.5) |
| **Deployment** | Per-operator-laptop mock-server OR shared broker SQLite | Zero new deployable artifacts — uses the existing mail bucket + role |
| **Cloud-portability** | AWS-only | S3/COS-abstracted (Tencent CAM + COS slot in unchanged — per cloud-setup.md §2.2) |
| **Audit trail** | None | S3 CloudTrail + bucket-policy access log |
| **Lifecycle / rotation** | None | Bucket lifecycle: expire credentials after N days; operator re-provisions to rotate |

## Wire contract sketch

`agentkeys-core::CredentialBackend` trait gains an alternative impl:

```rust
pub struct S3CredentialBackend {
    bucket: String,
    region: String,
    // STS creds come from the daemon's existing aws_creds::AwsTempCreds —
    // the same temp creds the CLI already mints for `provision`
    sts_creds_provider: Arc<dyn TempCredsProvider>,
    kek_signer: Arc<dyn DevKeySigner>,
}

impl CredentialBackend for S3CredentialBackend {
    async fn store_credential(
        &self,
        session: &Session,
        agent: &WalletAddress,
        service: &ServiceName,
        plaintext: &[u8],
    ) -> Result<(), BackendError> {
        // 1. Derive per-(wallet,service) KEK via signer (deterministic,
        //    same on every read/write — survives session-JWT rotation).
        let kek = self.derive_kek(agent, service).await?;
        // 2. Encrypt + authenticate with AES-256-GCM.
        let ciphertext = aes_gcm_seal(&kek, plaintext)?;
        // 3. PUT to s3://$BUCKET/bots/<wallet>/credentials/<service>.enc
        //    using the assumed-role creds.
        let key = format!("bots/{}/credentials/{}.enc", agent.0.to_lowercase(), service.0);
        self.s3.put_object(&self.bucket, &key, ciphertext).await
    }
    // read/teardown analogous
}
```

The KEK derivation deliberately routes through `dev_key_service` so the master secret K3 anchors credential confidentiality the same way it anchors wallet derivation. Future TEE migration (arch.md #13) transparently inherits credential-KEK custody.

## Required IAM grants

Extend the existing bucket policy (already grants PrincipalTag-scoped read on `bots/<wallet>/*`) to also allow `s3:PutObject` + `s3:DeleteObject` on `bots/<wallet>/credentials/*` under the same PrincipalTag condition. Minimal delta — no new IAM principal, no new role, no broader scope.

## Migration plan

1. ✅ Land `S3CredentialBackend` alongside the existing `MockHttpClient` impl (both compile, both pass tests). — `crates/agentkeys-core/src/s3_backend.rs`, 9 unit tests covering KEK determinism, AAD-binding, envelope versioning.
2. ✅ Add a CLI flag `--credential-backend {http,s3}` (default still `http` for the transition window). — top-level flag on `agentkeys` + `AGENTKEYS_CREDENTIAL_BACKEND` env. `cmd_store` / `cmd_read` / `cmd_run` / `cmd_teardown` / `cmd_provision` now route through `ctx.credential_backend()`; every other backend method (sessions, audit, identity, scope, rendezvous, inbox) still hits `MockHttpClient`.
3. ✅ Update §5.3 of the demo doc + cloud-setup.md to document the new backend. — cloud-setup.md §4.4 grows an `AllowDaemonPutOwnCredentials` statement (`s3:PutObject` + `s3:DeleteObject` on `bots/<wallet>/credentials/*` under the same PrincipalTag). stage7-demo-and-verification.md §5.3 documents the env-var opt-in.
4. ⏳ Once the operator-runbook docs are migrated, flip the default to `s3`. — next PR; gated on operators running the bucket-policy update.
5. ⏳ After one release with `s3` default, remove the mock-server's `/credential/*` handlers + the `agentkeys-backend.service` systemd unit (component #10 in arch.md §9 ceases to exist for credentials, stays for sessions+audit).
6. ⏳ Update arch.md §11: remove the "never publicly exposed" rule for :8090 entirely (the legacy backend goes away — nothing left to expose). Blocked by sessions+audit also migrating off the mock-server (separate issues).

## Out of scope (separate issues)

- Replacing the broker's audit-log storage (also lives on the mock-server today).
- Replacing `/session/*` (session-store has its own roadmap, not credential-related).
- TEE-backed KEK custody (arch.md #13 — future, dependent on issue-#74 step 2).

## Cross-references

- Forced by [issue #83](https://github.com/litentry/agentKeys/issues/83) follow-up: the auto-provision pipeline now succeeds through key mint but fails at storage because the legacy backend isn't reachable.
- Reuses infra from [SES routing Lambda](../../infra/ses-routing-lambda/) (issue #83 follow-up).
- See [arch.md §9 #10](../../docs/arch.md#L608), [§11](../../docs/arch.md#L636), [cloud-setup.md §4.5](../../docs/cloud-setup.md).
