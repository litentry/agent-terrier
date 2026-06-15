//! `S3CredentialBackend` — issue #85.
//!
//! Replaces the legacy mock-server `/credential/*` backend with S3-backed
//! storage. Each credential is stored as a client-side-encrypted blob at
//! `s3://$BUCKET/bots/<wallet>/credentials/<service>.enc`. Access is gated
//! by the existing `agentkeys-data-role` + `agentkeys_user_wallet`
//! PrincipalTag isolation (cloud-setup.md §4.4) — exactly the same path the
//! SES routing Lambda (issue #83) writes inbound mail through, so no new
//! IAM principal or bucket is provisioned.
//!
//! ## What this backend implements
//!
//! - `store_credential` — derive per-(wallet, service) KEK via the signer's
//!   `/dev/sign-message`, AES-256-GCM-seal the plaintext, PUT to S3.
//! - `read_credential` — GET from S3, derive KEK, AES-256-GCM-open.
//! - `teardown_agent` — list + delete every object under
//!   `bots/<wallet>/credentials/`.
//! - `list_credentials` — list objects under the credentials prefix and
//!   return their service names.
//!
//! Every other `CredentialBackend` method is intentionally a `NotFound` /
//! `Internal` error — those endpoints (sessions, audit, rendezvous,
//! identity, scope, inbox) still live on the legacy mock-server. This
//! backend is **only** for the `/credential/*` slice that issue #85
//! deprecates. The CLI's `--credential-backend s3` flag only swaps the
//! credential-CRUD impl; everything else continues to route through
//! `MockHttpClient`.
//!
//! ## Encryption
//!
//! - KEK derivation is signer-anchored. The signer's `sign_eip191` is
//!   called with the message
//!   `"agentkeys.kek.v1:" || lower(wallet) || ":" || service` under the
//!   operator's `omni_account`. secp256k1 with RFC 6979 deterministic-k
//!   makes the signature deterministic across calls. SHA-256 of the
//!   65-byte signature is the 32-byte AES-256 KEK.
//! - AEAD: AES-256-GCM with a 96-bit random nonce. Wire layout:
//!   `1B version || 12B nonce || ciphertext || 16B tag`,
//!   `version = 0x01`. The wallet, service name, and KEK version are mixed
//!   into AAD so a swap between two operators' (wallet, service) blobs at
//!   the S3 layer fails decryption.
//!
//! ## What's NOT bound to this backend
//!
//! The S3 client uses `aws-config::defaults` which reads creds from the
//! standard `AWS_*` environment. The CLI's `cmd_provision` already mints
//! per-call temp creds via `agentkeys-provisioner::aws_creds` and injects
//! them into the scraper subprocess; the same env vars (set in the
//! agentkeys process) drive this backend's S3 client. Production callers
//! that need fresh creds per call should construct a new backend
//! per-provision (or pass a custom `credentials_provider`).

use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials as AwsCredentials;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use sha2::{Digest, Sha256};

use crate::actor_omni::actor_omni_hex;
use crate::backend::{BackendError, CredentialBackend};
use crate::signer_client::{SignerClient, SignerClientError};
use agentkeys_types::{
    AuthRequest, AuthRequestId, AuthRequestType, CanonicalBytes, EncryptedPairPayload,
    InboxAddress, OpenedAuthRequest, PairCode, PairPayload, PublicKey, RegistrationToken, Scope,
    SecretBytes, ServiceName, Session, SignedAuthDecision, WalletAddress,
};

/// AEAD wire-format version byte. v1 (wallet-keyed AAD) is the original
/// envelope shipped by PR #87. v2 (actor_omni-keyed AAD + `bots/<actor_omni>/`
/// path) is the stage 1 target — stable across K3 rotation per
/// docs/arch.md §14.4. The backend reads BOTH formats during
/// the migration window (see `read_credential`), but writes only v2 when
/// `WriteEnvelope::V2` is selected.
const ENVELOPE_VERSION_V1: u8 = 0x01;
const ENVELOPE_VERSION_V2: u8 = 0x02;
const KEK_DOMAIN_TAG: &str = "agentkeys.kek.v1";

/// Which envelope shape `store_credential` produces. Reads always accept
/// both shapes during the migration window per the stage 1 plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteEnvelope {
    /// Legacy v1 envelope shipped by PR #87 — `bots/<wallet>/` path,
    /// AAD = `agentkeys.cred.aad.v1|wallet|service`.
    V1,
    /// Stage 1 v2 envelope — `bots/<actor_omni_hex>/` path,
    /// AAD = `agentkeys.cred.aad.v2|actor_omni_hex|service`. Stable
    /// across K3 rotation (path keys off actor_omni, not master_wallet).
    V2,
}

/// S3-backed credential store. Encrypts client-side; the bucket and the
/// signer are independent trust roots (the bucket holds ciphertext only;
/// the signer holds KEK derivation).
pub struct S3CredentialBackend {
    s3: S3Client,
    bucket: String,
    signer: Arc<dyn SignerClient>,
    /// 64-lowercase-hex `omni_account` for KEK derivation. Same value the
    /// daemon uses with `dev_key_service::derive_address` to materialize
    /// the wallet — issue #74 step 2 will pull this from the session JWT
    /// automatically. Today the operator passes it via
    /// `AGENTKEYS_OMNI_ACCOUNT`.
    omni_account: String,
    /// Which envelope shape new writes produce. Reads always accept both
    /// v1 and v2 (`open` dispatches on the version byte). Default is `V1`
    /// for backwards compat during the stage 1 migration window — flip
    /// to `V2` per-operator via `with_write_envelope(V2)` once the
    /// migration runbook step 9 completes.
    write_envelope: WriteEnvelope,
}

impl S3CredentialBackend {
    /// Build a backend against the live AWS S3 service.
    ///
    /// `credentials` is the **canonical injection point** for the
    /// short-lived AWS creds the broker mints via OIDC + STS
    /// `AssumeRoleWithWebIdentity`. When `Some`, the S3 client uses
    /// those creds explicitly — independent of the process env, which
    /// matters because `cmd_provision` injects broker-minted creds into
    /// the *scraper subprocess* env, not the parent. When `None`, the
    /// S3 client falls back to the standard `aws_config::defaults`
    /// chain (process AWS_* env, shared config, IMDS, …) — fine for
    /// callers that already export AWS_* themselves.
    ///
    /// `region` overrides the SDK default lookup only when supplied;
    /// leaving it `None` lets `AWS_REGION` or shared config win.
    pub async fn new(
        bucket: impl Into<String>,
        region: Option<&str>,
        credentials: Option<AwsCredentials>,
        signer: Arc<dyn SignerClient>,
        omni_account: impl Into<String>,
    ) -> Self {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(r) = region {
            loader = loader.region(Region::new(r.to_string()));
        }
        if let Some(c) = credentials {
            loader = loader.credentials_provider(c);
        }
        let config = loader.load().await;
        let s3 = S3Client::new(&config);
        Self {
            s3,
            bucket: bucket.into(),
            signer,
            omni_account: omni_account.into(),
            write_envelope: WriteEnvelope::V1,
        }
    }

    /// Test seam: construct directly from a pre-built S3 client. Lets unit
    /// tests inject an SDK config rewired to a localstack or stub
    /// endpoint without touching env vars.
    pub fn from_client(
        s3: S3Client,
        bucket: impl Into<String>,
        signer: Arc<dyn SignerClient>,
        omni_account: impl Into<String>,
    ) -> Self {
        Self {
            s3,
            bucket: bucket.into(),
            signer,
            omni_account: omni_account.into(),
            write_envelope: WriteEnvelope::V1,
        }
    }

    /// Select which envelope shape new writes produce. v1 (default) is the
    /// legacy wallet-keyed path; v2 keys both AAD and S3 path off
    /// `actor_omni_hex`. Stage 1 ships v1 as default so existing #87
    /// deployments keep working unchanged; per-operator opt-in flips this
    /// to v2 once the bucket policy + OIDC dual-tag rollout completes
    /// (see `docs/plan/v2-issues/issue-v2-stage-1-foundation.md`
    /// migration step 9).
    pub fn with_write_envelope(mut self, envelope: WriteEnvelope) -> Self {
        self.write_envelope = envelope;
        self
    }

    /// v1 path — `bots/<lowercase-wallet>/credentials/<service>.enc` —
    /// the legacy PR #87 layout. The bucket-policy `agentkeys_user_wallet`
    /// PrincipalTag condition keys off this prefix.
    fn object_key_v1(wallet: &WalletAddress, service: &ServiceName) -> String {
        format!(
            "bots/{}/credentials/{}.enc",
            wallet.0.to_lowercase(),
            service.0
        )
    }

    /// v2 path — `bots/<actor_omni_hex>/credentials/<service>.enc` per
    /// docs/arch.md §14.5. Stable across K3 rotation,
    /// matched by the new `agentkeys_actor_omni` PrincipalTag rule.
    fn object_key_v2(wallet: &WalletAddress, service: &ServiceName) -> String {
        format!(
            "bots/{}/credentials/{}.enc",
            actor_omni_hex(wallet),
            service.0
        )
    }

    /// v1 `bots/<wallet>/credentials/` prefix used by list + teardown.
    fn credentials_prefix_v1(wallet: &WalletAddress) -> String {
        format!("bots/{}/credentials/", wallet.0.to_lowercase())
    }

    /// v2 `bots/<actor_omni_hex>/credentials/` prefix.
    fn credentials_prefix_v2(wallet: &WalletAddress) -> String {
        format!("bots/{}/credentials/", actor_omni_hex(wallet))
    }

    /// Derive the 32-byte AES-256 KEK for `(wallet, service)` by asking
    /// the signer to EIP-191-sign a deterministic domain-tagged message.
    /// secp256k1 RFC 6979 makes this signature deterministic across calls,
    /// so the same KEK comes back on every read.
    async fn derive_kek(
        &self,
        wallet: &WalletAddress,
        service: &ServiceName,
    ) -> Result<[u8; 32], BackendError> {
        let msg = format!(
            "{}:{}:{}",
            KEK_DOMAIN_TAG,
            wallet.0.to_lowercase(),
            service.0
        );
        let signed = self
            .signer
            .sign_eip191(&self.omni_account, msg.as_bytes())
            .await
            .map_err(map_signer_error)?;

        // signed.signature is "0x" + 130 hex chars (65 bytes: r || s || v).
        let sig_hex = signed.signature.trim_start_matches("0x");
        let sig_bytes = hex::decode(sig_hex).map_err(|e| {
            BackendError::Internal(format!("signer returned invalid hex signature: {e}"))
        })?;
        if sig_bytes.len() != 65 {
            return Err(BackendError::Internal(format!(
                "signer returned {}-byte signature, expected 65",
                sig_bytes.len()
            )));
        }

        let mut hasher = Sha256::new();
        hasher.update(b"agentkeys.kek-derive.v1");
        hasher.update(&sig_bytes);
        let out = hasher.finalize();
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&out);
        Ok(kek)
    }

    /// List service names under `prefix` (`.enc` objects only). Used by
    /// `list_credentials` to walk both v1 and v2 prefixes during the
    /// migration window.
    async fn list_under_prefix(&self, prefix: &str) -> Result<Vec<ServiceName>, BackendError> {
        let mut continuation: Option<String> = None;
        let mut names: Vec<ServiceName> = Vec::new();
        loop {
            let mut req = self
                .s3
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = &continuation {
                req = req.continuation_token(token);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| map_s3_error("ListObjectsV2", e))?;

            for obj in resp.contents() {
                if let Some(k) = obj.key() {
                    if let Some(rest) = k.strip_prefix(prefix) {
                        if let Some(svc) = rest.strip_suffix(".enc") {
                            if !svc.is_empty() && !svc.contains('/') {
                                names.push(ServiceName(svc.to_string()));
                            }
                        }
                    }
                }
            }
            if resp.is_truncated().unwrap_or(false) {
                continuation = resp.next_continuation_token().map(|s| s.to_string());
                if continuation.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(names)
    }

    /// Delete every object under `prefix`. Used by `teardown_agent` to
    /// wipe both v1 and v2 paths.
    async fn delete_under_prefix(&self, prefix: &str) -> Result<(), BackendError> {
        let mut continuation: Option<String> = None;
        loop {
            let mut req = self
                .s3
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = &continuation {
                req = req.continuation_token(token);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| map_s3_error("ListObjectsV2", e))?;

            for obj in resp.contents() {
                if let Some(k) = obj.key() {
                    self.s3
                        .delete_object()
                        .bucket(&self.bucket)
                        .key(k)
                        .send()
                        .await
                        .map_err(|e| map_s3_error("DeleteObject", e))?;
                }
            }
            if resp.is_truncated().unwrap_or(false) {
                continuation = resp.next_continuation_token().map(|s| s.to_string());
                if continuation.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    /// AEAD-seal `plaintext` under `kek` per the selected envelope
    /// version. v1 binds AAD to `(wallet, service)`; v2 binds AAD to
    /// `(actor_omni_hex, service)` so the blob stays decryptable even
    /// after K3 / master-wallet rotation.
    fn seal(
        envelope_version: u8,
        kek: &[u8; 32],
        wallet: &WalletAddress,
        service: &ServiceName,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, BackendError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = aad_for_version(envelope_version, wallet, service)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| BackendError::Internal(format!("aes-gcm seal: {e}")))?;

        let mut envelope = Vec::with_capacity(1 + 12 + ciphertext.len());
        envelope.push(envelope_version);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// AEAD-open the wire envelope produced by `seal`. Dispatches on the
    /// version byte: v1 envelopes verify against the wallet-keyed AAD,
    /// v2 envelopes verify against the actor_omni-keyed AAD. Operators
    /// can read pre-migration v1 blobs and post-migration v2 blobs
    /// through the exact same call site.
    fn open(
        kek: &[u8; 32],
        wallet: &WalletAddress,
        service: &ServiceName,
        envelope: &[u8],
    ) -> Result<SecretBytes, BackendError> {
        if envelope.len() < 1 + 12 + 16 {
            return Err(BackendError::Internal(format!(
                "envelope too short: {} bytes",
                envelope.len()
            )));
        }
        let version = envelope[0];
        if version != ENVELOPE_VERSION_V1 && version != ENVELOPE_VERSION_V2 {
            return Err(BackendError::Internal(format!(
                "unsupported envelope version 0x{:02x}",
                version
            )));
        }
        let nonce = Nonce::from_slice(&envelope[1..13]);
        let ciphertext = &envelope[13..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
        let aad = aad_for_version(version, wallet, service)?;
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| BackendError::Internal(format!("aes-gcm open: {e}")))?;
        Ok(SecretBytes::new(plaintext))
    }
}

/// Enforce `Session.scope` for a per-service credential operation. The
/// legacy HTTP backend sends the bearer JWT and lets the mock-server's
/// `/credential/*` handlers do this server-side; with the S3 backend
/// the client IS the trust boundary (AWS only knows about wallet, not
/// service), so we have to apply the same gate before we touch S3.
///
/// `write` distinguishes store/teardown from read so `read_only`
/// scopes can still call `read_credential`.
fn enforce_scope_for_service(
    session: &Session,
    service: &ServiceName,
    write: bool,
) -> Result<(), BackendError> {
    let Some(scope) = &session.scope else {
        return Ok(());
    };
    if !scope.services.iter().any(|s| s == service) {
        let allowed: Vec<&str> = scope.services.iter().map(|s| s.0.as_str()).collect();
        return Err(BackendError::PermissionDenied(format!(
            "service '{}' not in session scope (allowed: [{}])",
            service.0,
            allowed.join(", ")
        )));
    }
    if write && scope.read_only {
        return Err(BackendError::PermissionDenied(format!(
            "session is read_only; refusing to write credential for service '{}'",
            service.0
        )));
    }
    Ok(())
}

/// Enforce that a wallet-level destructive op (today only
/// `teardown_agent`) is invoked from the unscoped master session.
/// Scoped child sessions don't carry the "delete-all-credentials"
/// authority even if their scope.services covers what would be
/// deleted — that's a master decision.
fn enforce_master_session(session: &Session, op: &str) -> Result<(), BackendError> {
    if session.scope.is_some() {
        return Err(BackendError::PermissionDenied(format!(
            "'{op}' requires the unscoped master session (current session carries a scope)"
        )));
    }
    Ok(())
}

/// v1 AAD: `agentkeys.cred.aad.v1|<lowercase_wallet>|<service>`.
fn aad_for_v1(wallet: &WalletAddress, service: &ServiceName) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + wallet.0.len() + service.0.len());
    aad.extend_from_slice(b"agentkeys.cred.aad.v1|");
    aad.extend_from_slice(wallet.0.to_lowercase().as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(service.0.as_bytes());
    aad
}

/// v2 AAD: `agentkeys.cred.aad.v2|<actor_omni_hex>|<service>` per
/// docs/arch.md §14.4. Binds the blob to its stable
/// actor_omni-keyed location instead of the rotation-volatile wallet.
fn aad_for_v2(wallet: &WalletAddress, service: &ServiceName) -> Vec<u8> {
    let omni = actor_omni_hex(wallet);
    let mut aad = Vec::with_capacity(64 + omni.len() + service.0.len());
    aad.extend_from_slice(b"agentkeys.cred.aad.v2|");
    aad.extend_from_slice(omni.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(service.0.as_bytes());
    aad
}

/// Dispatch on the envelope version byte. Errors only on unknown
/// versions — callers should have already validated the byte before
/// reaching the cipher.
fn aad_for_version(
    version: u8,
    wallet: &WalletAddress,
    service: &ServiceName,
) -> Result<Vec<u8>, BackendError> {
    match version {
        ENVELOPE_VERSION_V1 => Ok(aad_for_v1(wallet, service)),
        ENVELOPE_VERSION_V2 => Ok(aad_for_v2(wallet, service)),
        other => Err(BackendError::Internal(format!(
            "unsupported envelope version 0x{:02x}",
            other
        ))),
    }
}

fn map_signer_error(err: SignerClientError) -> BackendError {
    match err {
        SignerClientError::Unauthorized(m) => BackendError::AuthFailed(format!("signer: {m}")),
        SignerClientError::SignerDisabled(m) => {
            BackendError::Internal(format!("signer disabled: {m}"))
        }
        SignerClientError::Transport(m) => BackendError::Transport(format!("signer: {m}")),
        other => BackendError::Internal(format!("signer: {other}")),
    }
}

fn map_s3_error<E: std::fmt::Display>(op: &str, e: E) -> BackendError {
    let s = e.to_string();
    if s.contains("NotFound") || s.contains("NoSuchKey") || s.contains("404") {
        BackendError::NotFound(format!("{op}: {s}"))
    } else if s.contains("AccessDenied") || s.contains("403") {
        BackendError::PermissionDenied(format!("{op}: {s}"))
    } else {
        BackendError::Transport(format!("{op}: {s}"))
    }
}

#[async_trait]
impl CredentialBackend for S3CredentialBackend {
    async fn store_credential(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
        service: &ServiceName,
        plaintext: &[u8],
    ) -> Result<(), BackendError> {
        enforce_scope_for_service(session, service, true)?;
        let kek = self.derive_kek(agent_id, service).await?;
        let (envelope_version, key) = match self.write_envelope {
            WriteEnvelope::V1 => (ENVELOPE_VERSION_V1, Self::object_key_v1(agent_id, service)),
            WriteEnvelope::V2 => (ENVELOPE_VERSION_V2, Self::object_key_v2(agent_id, service)),
        };
        let envelope = Self::seal(envelope_version, &kek, agent_id, service, plaintext)?;

        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(envelope))
            .content_type("application/octet-stream")
            .send()
            .await
            .map_err(|e| map_s3_error("PutObject", e))?;
        Ok(())
    }

    async fn read_credential(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
        service: &ServiceName,
    ) -> Result<SecretBytes, BackendError> {
        enforce_scope_for_service(session, service, false)?;
        // Dual-path read per issue-v2-stage-1-foundation.md migration step
        // 10: try v2 (actor_omni-keyed) path first, fall back to v1
        // (wallet-keyed). Lets operators read either pre-migration v1
        // blobs or post-migration v2 blobs without an opt-in flag flip.
        let key_v2 = Self::object_key_v2(agent_id, service);
        let body = match self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&key_v2)
            .send()
            .await
        {
            Ok(resp) => resp
                .body
                .collect()
                .await
                .map_err(|e| BackendError::Transport(format!("GetObject body collect: {e}")))?
                .into_bytes()
                .to_vec(),
            Err(e) => {
                // Only fall back on NotFound — propagate every other
                // error (AccessDenied, throttling, network) so the
                // operator sees the real failure instead of a silently
                // swapped path.
                let mapped = map_s3_error("GetObject", e);
                if !matches!(mapped, BackendError::NotFound(_)) {
                    return Err(mapped);
                }
                let key_v1 = Self::object_key_v1(agent_id, service);
                let resp = self
                    .s3
                    .get_object()
                    .bucket(&self.bucket)
                    .key(&key_v1)
                    .send()
                    .await
                    .map_err(|e| map_s3_error("GetObject", e))?;
                resp.body
                    .collect()
                    .await
                    .map_err(|e| BackendError::Transport(format!("GetObject body collect: {e}")))?
                    .into_bytes()
                    .to_vec()
            }
        };
        let kek = self.derive_kek(agent_id, service).await?;
        Self::open(&kek, agent_id, service, &body)
    }

    async fn teardown_agent(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<(), BackendError> {
        enforce_master_session(session, "teardown_agent")?;
        // Wipe BOTH the v1 wallet-keyed prefix AND the v2 actor_omni-keyed
        // prefix so a mid-migration teardown doesn't leave orphan blobs at
        // the un-deleted path.
        for prefix in [
            Self::credentials_prefix_v2(agent_id),
            Self::credentials_prefix_v1(agent_id),
        ] {
            self.delete_under_prefix(&prefix).await?;
        }
        Ok(())
    }

    async fn list_credentials(
        &self,
        session: &Session,
        agent_id: &WalletAddress,
    ) -> Result<Vec<ServiceName>, BackendError> {
        // Union of v1 + v2 names — dedupe so a credential that's been
        // lazy-migrated (exists at both paths) appears once. v2 wins when
        // both paths carry the same service.
        let mut names: Vec<ServiceName> = Vec::new();
        for prefix in [
            Self::credentials_prefix_v2(agent_id),
            Self::credentials_prefix_v1(agent_id),
        ] {
            let mut entries = self.list_under_prefix(&prefix).await?;
            for entry in entries.drain(..) {
                if !names.contains(&entry) {
                    names.push(entry);
                }
            }
        }

        // Scoped child sessions must not see service names outside their
        // scope — the bucket-policy PrincipalTag only knows the prefix,
        // so client-side filtering is the trust boundary. Match the
        // mock-server's `/credential/list` behavior.
        if let Some(scope) = &session.scope {
            names.retain(|n| scope.services.iter().any(|s| s == n));
        }

        Ok(names)
    }

    // -- Methods this backend deliberately does not implement -----------
    //
    // Sessions, audit, rendezvous, identity, scope, inbox, and auth
    // requests still live on the legacy backend (or the broker). Issue
    // #85's migration plan only swaps credentials. The CLI's
    // `--credential-backend s3` flag only routes credential-CRUD here;
    // every other call goes through the existing `MockHttpClient`.

    async fn create_session(
        &self,
        _auth_token: agentkeys_types::AuthToken,
    ) -> Result<(Session, WalletAddress), BackendError> {
        Err(unsupported("create_session"))
    }

    async fn create_child_session(
        &self,
        _parent: &Session,
        _scope: Scope,
    ) -> Result<(Session, WalletAddress), BackendError> {
        Err(unsupported("create_child_session"))
    }

    async fn revoke_session(
        &self,
        _session: &Session,
        _target: &Session,
    ) -> Result<(), BackendError> {
        Err(unsupported("revoke_session"))
    }

    async fn revoke_by_wallet(
        &self,
        _session: &Session,
        _target_wallet: &WalletAddress,
    ) -> Result<(), BackendError> {
        Err(unsupported("revoke_by_wallet"))
    }

    async fn shielding_key(&self) -> Result<PublicKey, BackendError> {
        Err(unsupported("shielding_key"))
    }

    async fn register_rendezvous(
        &self,
        _daemon_pubkey: &PublicKey,
        _pair_code: &PairCode,
    ) -> Result<RegistrationToken, BackendError> {
        Err(unsupported("register_rendezvous"))
    }

    async fn poll_rendezvous(
        &self,
        _token: &RegistrationToken,
    ) -> Result<Option<PairPayload>, BackendError> {
        Err(unsupported("poll_rendezvous"))
    }

    async fn deliver_rendezvous(
        &self,
        _session: &Session,
        _pair_code: &PairCode,
        _payload: &EncryptedPairPayload,
    ) -> Result<(), BackendError> {
        Err(unsupported("deliver_rendezvous"))
    }

    async fn open_auth_request(
        &self,
        _child_pubkey: &PublicKey,
        _request_type: AuthRequestType,
        _request_details: &CanonicalBytes,
        _parent_wallet: Option<&WalletAddress>,
    ) -> Result<OpenedAuthRequest, BackendError> {
        Err(unsupported("open_auth_request"))
    }

    async fn fetch_auth_request(
        &self,
        _session: &Session,
        _pair_code: &PairCode,
    ) -> Result<AuthRequest, BackendError> {
        Err(unsupported("fetch_auth_request"))
    }

    async fn approve_auth_request(
        &self,
        _session: &Session,
        _request_id: &AuthRequestId,
    ) -> Result<(), BackendError> {
        Err(unsupported("approve_auth_request"))
    }

    async fn await_auth_decision(
        &self,
        _request_id: &AuthRequestId,
    ) -> Result<SignedAuthDecision, BackendError> {
        Err(unsupported("await_auth_decision"))
    }

    async fn recover_session(
        &self,
        _identity: &agentkeys_types::AgentIdentity,
        _method: &agentkeys_types::RecoveryMethod,
    ) -> Result<(Session, WalletAddress), BackendError> {
        Err(unsupported("recover_session"))
    }

    async fn get_scope(
        &self,
        _session: &Session,
        _target_wallet: &WalletAddress,
    ) -> Result<Option<Scope>, BackendError> {
        Err(unsupported("get_scope"))
    }

    async fn update_scope(
        &self,
        _session: &Session,
        _target_wallet: &WalletAddress,
        _new_scope: &Scope,
    ) -> Result<(), BackendError> {
        Err(unsupported("update_scope"))
    }

    async fn provision_inbox(
        &self,
        _session: &Session,
        _agent_id: &WalletAddress,
    ) -> Result<InboxAddress, BackendError> {
        Err(unsupported("provision_inbox"))
    }

    async fn list_inboxes(
        &self,
        _session: &Session,
        _agent_id: &WalletAddress,
    ) -> Result<Vec<InboxAddress>, BackendError> {
        Err(unsupported("list_inboxes"))
    }
}

fn unsupported(op: &str) -> BackendError {
    BackendError::Internal(format!(
        "S3CredentialBackend only handles credential CRUD; '{op}' must route through the http (broker / mock-server) backend"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clear_signing::TypedData;
    use crate::signer_client::{
        DerivedAddress, SignedMessage, SignedTypedData, SignerClient, SignerClientError,
    };
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// In-memory signer that produces a deterministic 65-byte hex
    /// "signature" by SHA-256-hashing the input and zero-padding. Real
    /// signers use RFC 6979 secp256k1, but for unit-testing the AES-GCM
    /// envelope and KEK-derivation flow we only need determinism + the
    /// 65-byte length contract.
    struct FakeSigner {
        omni_seen: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl SignerClient for FakeSigner {
        async fn derive_address(&self, _omni: &str) -> Result<DerivedAddress, SignerClientError> {
            Ok(DerivedAddress {
                address: "0x0000000000000000000000000000000000000000".into(),
                key_version: 1,
            })
        }

        async fn sign_eip191(
            &self,
            omni: &str,
            msg: &[u8],
        ) -> Result<SignedMessage, SignerClientError> {
            self.omni_seen.lock().unwrap().push(omni.to_string());
            let mut hasher = Sha256::new();
            hasher.update(omni.as_bytes());
            hasher.update(b"|");
            hasher.update(msg);
            let digest = hasher.finalize();
            let mut sig = Vec::with_capacity(65);
            sig.extend_from_slice(&digest);
            sig.extend_from_slice(&digest);
            sig.push(0u8);
            Ok(SignedMessage {
                signature: format!("0x{}", hex::encode(sig)),
                address: "0x0000000000000000000000000000000000000000".into(),
                key_version: 1,
            })
        }

        async fn sign_eip712(
            &self,
            _omni: &str,
            _td: &TypedData,
        ) -> Result<SignedTypedData, SignerClientError> {
            // S3CredentialBackend only needs the EIP-191 KEK-derivation
            // path; this fake never sees a typed-data sign call.
            Err(SignerClientError::Internal(
                "FakeSigner does not implement sign_eip712".into(),
            ))
        }
    }

    fn fake_signer() -> Arc<dyn SignerClient> {
        Arc::new(FakeSigner {
            omni_seen: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn object_key_v1_uses_lowercase_wallet_and_credentials_prefix() {
        let key = S3CredentialBackend::object_key_v1(
            &WalletAddress("0xABCDEF1234567890ABCDEF1234567890ABCDEF12".into()),
            &ServiceName("openrouter".into()),
        );
        assert_eq!(
            key,
            "bots/0xabcdef1234567890abcdef1234567890abcdef12/credentials/openrouter.enc"
        );
    }

    #[test]
    fn object_key_v2_uses_actor_omni_hex_prefix() {
        use crate::actor_omni::actor_omni_hex;
        let wallet = WalletAddress("0xabc".into());
        let key = S3CredentialBackend::object_key_v2(&wallet, &ServiceName("openrouter".into()));
        let expected_omni = actor_omni_hex(&wallet);
        assert_eq!(
            key,
            format!("bots/{}/credentials/openrouter.enc", expected_omni)
        );
        // v2 path never contains the wallet hex — the whole point of the
        // migration is to stop leaking the rotation-volatile wallet into
        // S3 paths.
        assert!(!key.contains("0xabc"));
    }

    #[test]
    fn credentials_prefix_v1_matches_object_key_v1_root() {
        let wallet = WalletAddress("0xABC".into());
        let prefix = S3CredentialBackend::credentials_prefix_v1(&wallet);
        let key = S3CredentialBackend::object_key_v1(&wallet, &ServiceName("svc".into()));
        assert!(key.starts_with(&prefix));
        assert_eq!(prefix, "bots/0xabc/credentials/");
    }

    #[test]
    fn credentials_prefix_v2_matches_object_key_v2_root() {
        let wallet = WalletAddress("0xABC".into());
        let prefix = S3CredentialBackend::credentials_prefix_v2(&wallet);
        let key = S3CredentialBackend::object_key_v2(&wallet, &ServiceName("svc".into()));
        assert!(key.starts_with(&prefix));
        assert!(prefix.ends_with("/credentials/"));
        assert!(!prefix.contains("0xabc"));
    }

    /// Build a `S3CredentialBackend` against an empty config — the
    /// helper tests (`derive_kek`, `enforce_scope_for_service`) don't
    /// reach S3, so the client doesn't need to be functional.
    async fn test_backend(signer: Arc<dyn SignerClient>) -> S3CredentialBackend {
        S3CredentialBackend {
            s3: S3Client::new(
                &aws_config::defaults(BehaviorVersion::latest())
                    .region(Region::new("us-east-1"))
                    .load()
                    .await,
            ),
            bucket: "test-bucket".into(),
            signer,
            omni_account: "deadbeef".repeat(8),
            write_envelope: WriteEnvelope::V1,
        }
    }

    fn scoped_session(services: Vec<&str>, read_only: bool) -> Session {
        Session {
            token: "tok".into(),
            wallet: WalletAddress("0xabc".into()),
            scope: Some(Scope {
                services: services
                    .into_iter()
                    .map(|s| ServiceName(s.into()))
                    .collect(),
                read_only,
            }),
            created_at: 0,
            ttl_seconds: 3600,
        }
    }

    fn master_session() -> Session {
        Session {
            token: "tok".into(),
            wallet: WalletAddress("0xabc".into()),
            scope: None,
            created_at: 0,
            ttl_seconds: 3600,
        }
    }

    #[tokio::test]
    async fn derive_kek_is_deterministic_and_per_service() {
        let signer = fake_signer();
        let backend = test_backend(signer).await;
        let wallet = WalletAddress("0xabc".into());
        let svc_a = ServiceName("openrouter".into());
        let svc_b = ServiceName("anthropic".into());

        let kek_a1 = backend.derive_kek(&wallet, &svc_a).await.unwrap();
        let kek_a2 = backend.derive_kek(&wallet, &svc_a).await.unwrap();
        let kek_b = backend.derive_kek(&wallet, &svc_b).await.unwrap();

        assert_eq!(kek_a1, kek_a2, "same (wallet, service) → same KEK");
        assert_ne!(
            kek_a1, kek_b,
            "different services must derive distinct KEKs"
        );
    }

    // ---- Scope enforcement (codex adversarial review finding #1) ----

    #[test]
    fn enforce_scope_allows_master_session() {
        let session = master_session();
        let svc = ServiceName("openrouter".into());
        assert!(enforce_scope_for_service(&session, &svc, false).is_ok());
        assert!(enforce_scope_for_service(&session, &svc, true).is_ok());
        assert!(enforce_master_session(&session, "teardown_agent").is_ok());
    }

    #[test]
    fn enforce_scope_blocks_service_not_in_list() {
        let session = scoped_session(vec!["openrouter"], false);
        let svc = ServiceName("anthropic".into());
        let err = enforce_scope_for_service(&session, &svc, false).unwrap_err();
        match err {
            BackendError::PermissionDenied(m) => {
                assert!(m.contains("anthropic"), "msg = {m}");
                assert!(m.contains("openrouter"), "msg = {m}");
            }
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    #[test]
    fn enforce_scope_blocks_write_when_read_only() {
        let session = scoped_session(vec!["openrouter"], true);
        let svc = ServiceName("openrouter".into());
        // Read is allowed even on read_only scopes.
        assert!(enforce_scope_for_service(&session, &svc, false).is_ok());
        // Write is rejected.
        let err = enforce_scope_for_service(&session, &svc, true).unwrap_err();
        match err {
            BackendError::PermissionDenied(m) => assert!(m.contains("read_only"), "msg = {m}"),
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    #[test]
    fn enforce_master_session_blocks_scoped_session() {
        let session = scoped_session(vec!["openrouter"], false);
        let err = enforce_master_session(&session, "teardown_agent").unwrap_err();
        match err {
            BackendError::PermissionDenied(m) => assert!(
                m.contains("teardown_agent") && m.contains("master"),
                "msg = {m}"
            ),
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_credential_blocks_out_of_scope_before_s3_call() {
        let backend = test_backend(fake_signer()).await;
        let session = scoped_session(vec!["openrouter"], false);
        let err = backend
            .store_credential(
                &session,
                &WalletAddress("0xabc".into()),
                &ServiceName("anthropic".into()),
                b"sk-ant-x",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn read_credential_allows_in_scope_read_only() {
        // Read-only sessions can still derive the KEK and reach S3
        // (we'd fail on the GetObject call here, but scope enforcement
        // must NOT short-circuit). Use a service that's in scope; the
        // KEK derivation runs against the fake signer.
        let backend = test_backend(fake_signer()).await;
        let session = scoped_session(vec!["openrouter"], true);
        // We can't easily reach S3 in unit tests, so verify the scope
        // gate alone returns Ok(()) — anything past that is the SDK's
        // problem.
        assert!(
            enforce_scope_for_service(&session, &ServiceName("openrouter".into()), false).is_ok()
        );
        // Sanity: still rejects out-of-scope reads.
        let err = backend
            .read_credential(
                &session,
                &WalletAddress("0xabc".into()),
                &ServiceName("anthropic".into()),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn teardown_agent_rejects_scoped_session() {
        let backend = test_backend(fake_signer()).await;
        let session = scoped_session(vec!["openrouter"], false);
        let err = backend
            .teardown_agent(&session, &WalletAddress("0xabc".into()))
            .await
            .unwrap_err();
        match err {
            BackendError::PermissionDenied(m) => assert!(m.contains("teardown_agent")),
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    #[test]
    fn seal_open_v1_roundtrips_with_aad_binding() {
        let kek = [7u8; 32];
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let plaintext = b"sk-or-v1-secret";

        let envelope =
            S3CredentialBackend::seal(ENVELOPE_VERSION_V1, &kek, &wallet, &svc, plaintext).unwrap();
        assert_eq!(envelope[0], ENVELOPE_VERSION_V1);
        assert!(envelope.len() > 1 + 12 + 16);
        let opened = S3CredentialBackend::open(&kek, &wallet, &svc, &envelope).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn seal_open_v2_roundtrips_with_actor_omni_aad() {
        let kek = [7u8; 32];
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let plaintext = b"sk-or-v2-secret";

        let envelope =
            S3CredentialBackend::seal(ENVELOPE_VERSION_V2, &kek, &wallet, &svc, plaintext).unwrap();
        assert_eq!(envelope[0], ENVELOPE_VERSION_V2);
        let opened = S3CredentialBackend::open(&kek, &wallet, &svc, &envelope).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn v1_envelope_does_not_decrypt_with_v2_aad_and_vice_versa() {
        let kek = [7u8; 32];
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        // v1 ciphertext re-tagged with v2 version byte must fail open
        // (AAD changes from wallet-keyed to actor_omni-keyed).
        let mut v1 =
            S3CredentialBackend::seal(ENVELOPE_VERSION_V1, &kek, &wallet, &svc, b"x").unwrap();
        v1[0] = ENVELOPE_VERSION_V2;
        let err = S3CredentialBackend::open(&kek, &wallet, &svc, &v1).unwrap_err();
        assert!(matches!(err, BackendError::Internal(_)));
        // Sanity: a v2-shaped envelope decrypted against itself works.
        let v2 = S3CredentialBackend::seal(ENVELOPE_VERSION_V2, &kek, &wallet, &svc, b"x").unwrap();
        assert_eq!(
            S3CredentialBackend::open(&kek, &wallet, &svc, &v2)
                .unwrap()
                .as_slice(),
            b"x"
        );
    }

    #[test]
    fn open_rejects_wrong_aad_wallet() {
        let kek = [7u8; 32];
        let wallet = WalletAddress("0xabc".into());
        let other_wallet = WalletAddress("0xdef".into());
        let svc = ServiceName("openrouter".into());
        let envelope =
            S3CredentialBackend::seal(ENVELOPE_VERSION_V1, &kek, &wallet, &svc, b"sk-or-v1-secret")
                .unwrap();
        let err = S3CredentialBackend::open(&kek, &other_wallet, &svc, &envelope).unwrap_err();
        match err {
            BackendError::Internal(m) => assert!(m.contains("aes-gcm")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_wrong_aad_service() {
        let kek = [7u8; 32];
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let other_svc = ServiceName("anthropic".into());
        let envelope =
            S3CredentialBackend::seal(ENVELOPE_VERSION_V1, &kek, &wallet, &svc, b"x").unwrap();
        let err = S3CredentialBackend::open(&kek, &wallet, &other_svc, &envelope).unwrap_err();
        assert!(matches!(err, BackendError::Internal(_)));
    }

    #[test]
    fn open_rejects_envelope_version_drift() {
        let kek = [7u8; 32];
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let mut envelope =
            S3CredentialBackend::seal(ENVELOPE_VERSION_V1, &kek, &wallet, &svc, b"x").unwrap();
        envelope[0] = 0xFF;
        let err = S3CredentialBackend::open(&kek, &wallet, &svc, &envelope).unwrap_err();
        match err {
            BackendError::Internal(m) => assert!(m.contains("envelope version")),
            other => panic!("expected version error, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_truncated_envelope() {
        let kek = [7u8; 32];
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let err =
            S3CredentialBackend::open(&kek, &wallet, &svc, &[ENVELOPE_VERSION_V1]).unwrap_err();
        match err {
            BackendError::Internal(m) => assert!(m.contains("envelope too short")),
            other => panic!("expected truncation error, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_helper_names_the_operation() {
        let err = unsupported("recover_session");
        let s = err.to_string();
        assert!(s.contains("recover_session"), "msg = {s}");
    }

    // ---- v2 migration coverage (issue-v2-stage-1-foundation) -------------

    #[test]
    fn v1_and_v2_paths_diverge_for_same_wallet() {
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let v1 = S3CredentialBackend::object_key_v1(&wallet, &svc);
        let v2 = S3CredentialBackend::object_key_v2(&wallet, &svc);
        assert_ne!(v1, v2, "v1 and v2 paths must not collide");
        assert!(v1.contains("0xabc"), "v1 carries wallet hex: {v1}");
        assert!(!v2.contains("0xabc"), "v2 must not leak wallet hex: {v2}");
    }

    #[test]
    fn v1_and_v2_aad_diverge_for_same_wallet() {
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let aad_v1 = aad_for_v1(&wallet, &svc);
        let aad_v2 = aad_for_v2(&wallet, &svc);
        assert_ne!(aad_v1, aad_v2);
        // v1 AAD domain tag must be present in v1, absent in v2 (and vice
        // versa). Operators reading raw blobs from S3 can tell the
        // version from the first byte; this guards the in-memory AAD.
        assert!(aad_v1.windows(2).any(|w| w == b"v1"));
        assert!(aad_v2.windows(2).any(|w| w == b"v2"));
    }

    #[test]
    fn write_envelope_v2_seals_into_v2_envelope() {
        let kek = [7u8; 32];
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let env =
            S3CredentialBackend::seal(ENVELOPE_VERSION_V2, &kek, &wallet, &svc, b"x").unwrap();
        assert_eq!(env[0], ENVELOPE_VERSION_V2);
        // Round-trip via the public open() — dispatches on version byte.
        let opened = S3CredentialBackend::open(&kek, &wallet, &svc, &env).unwrap();
        assert_eq!(opened.as_slice(), b"x");
    }

    #[test]
    fn aad_version_dispatch_rejects_unknown_version() {
        let wallet = WalletAddress("0xabc".into());
        let svc = ServiceName("openrouter".into());
        let err = aad_for_version(0x55, &wallet, &svc).unwrap_err();
        match err {
            BackendError::Internal(m) => assert!(m.contains("0x55"), "msg = {m}"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn with_write_envelope_overrides_default() {
        let backend = test_backend(fake_signer()).await;
        assert_eq!(backend.write_envelope, WriteEnvelope::V1);
        let upgraded = backend.with_write_envelope(WriteEnvelope::V2);
        assert_eq!(upgraded.write_envelope, WriteEnvelope::V2);
    }
}
