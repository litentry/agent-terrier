//! `POST /v1/mint-aws-creds` — credential mint endpoint.
//!
//! Stage 7 issue#64 US-011 upgrades this handler to accept the NEW v0
//! shape (plan §3.5.2):
//!
//! - Authorization header carries a session JWT (signed by the broker's
//!   session keypair, minted by `/v1/auth/wallet/verify` or
//!   `/v1/auth/exchange`).
//! - Request body declares `{request_id, issued_at, intent, auth}` where
//!   `auth.signature` is an EIP-191 signature by the daemon's wallet
//!   over the canonical hash of the body (excluding `auth.signature`).
//! - Audit row is written via every configured `AuditAnchor` BEFORE
//!   credentials are released. Per plan §2 (load-bearing invariant):
//!   no creds out unless durably anchored everywhere.
//!
//! The handler also keeps the LEGACY path working so the existing
//! daemon/CLI binaries (which consume the bearer-validated /session/validate
//! flow) continue to function during the cutover. Discrimination is
//! purely on token shape: a 3-segment JWT-looking bearer goes through
//! the new path; anything else goes through the legacy path.
//!
//! The legacy path is REMOVED in v1.0 along with `/v1/auth/exchange`
//! per plan §3.5.7. Codex P0 #14 (permanent dual-accept) is mitigated
//! by this transitional split being a documented v0→v1 cutover, not a
//! forever-feature.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::audit::{MintOutcome, MintRecord};
use crate::auth::extract_bearer_token;
use crate::error::{BrokerError, BrokerResult};
use crate::jwt::verify::verify_session_jwt;
use crate::plugins::audit::{AnchorReceipt, AuditRecord};
use crate::state::SharedState;

/// Successful response — same shape under both legacy and new paths so a
/// daemon switching between them needs no JSON-decoding changes.
#[derive(Serialize, Debug, Clone)]
pub struct MintResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: i64,
    pub wallet: String,
    /// New-path only — the audit record's ULID. Legacy path leaves this
    /// `None` so existing clients ignore it; new clients can correlate
    /// the response with the on-anchor record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_record_id: Option<String>,
    /// New-path only — list of anchor names that confirmed durability.
    /// Legacy clients ignore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchored: Option<Vec<String>>,
}

/// New-path body shape (plan §3.5.2).
#[derive(Deserialize, Debug, Clone)]
pub struct MintBodyV2 {
    pub request_id: String,
    pub issued_at: String,
    pub intent: MintIntent,
    pub auth: MintAuth,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
pub struct MintIntent {
    pub agent_id: String,
    pub service: String,
    #[serde(default)]
    pub scope_path: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MintAuth {
    pub address: String,
    pub signature: String,
}

#[tracing::instrument(skip_all, fields(wallet = tracing::field::Empty, outcome = tracing::field::Empty))]
pub async fn mint_aws_creds(
    State(state): State<SharedState>,
    headers: HeaderMap,
    raw_body: axum::body::Bytes,
) -> BrokerResult<Json<MintResponse>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;

    // Single path: callers send a session JWT. Pre-Stage-7 backend-validated
    // bearers and the dispatch heuristic were removed in the OIDC-only
    // migration (issue #71).
    mint_v2(&state, token, &raw_body).await
}

// ---------------------------------------------------------------------------
// New v2 path — session JWT + per-call daemon signature + AuditAnchor write
// ---------------------------------------------------------------------------

async fn mint_v2(
    state: &SharedState,
    token: &str,
    raw_body: &axum::body::Bytes,
) -> BrokerResult<Json<MintResponse>> {
    // 1. Verify session JWT against the broker's session keypair.
    let claims = verify_session_jwt(&state.session_keypair, &state.config.oidc_issuer, token)
        .map_err(|e| BrokerError::Unauthorized(format!("session jwt: {}", e)))?;
    tracing::Span::current().record("wallet", claims.agentkeys.wallet_address.as_str());

    // 2. Parse the v2 body. Empty body or wrong shape → 400.
    if raw_body.is_empty() {
        return Err(BrokerError::BadRequest(
            "v2 mint requires a JSON body — see plan §3.5.2 wire format".into(),
        ));
    }
    let body: MintBodyV2 = serde_json::from_slice(raw_body)
        .map_err(|e| BrokerError::BadRequest(format!("malformed v2 body: {}", e)))?;

    // 3. Per-call signature verification. The body without `auth.signature`
    //    must canonicalize, hash, and verify against `auth.address`.
    let canonical = canonical_signing_input(raw_body, &body)?;
    let recovered = ecrecover_eip191(&canonical, &body.auth.signature)
        .map_err(|e| BrokerError::Unauthorized(format!("per-call sig: {}", e)))?;
    if !addresses_match(&recovered, &body.auth.address) {
        return Err(BrokerError::Unauthorized(format!(
            "per-call signature recovers to {} not {}",
            recovered, body.auth.address
        )));
    }

    // 4. Wallet-binding: auth.address MUST match the wallet bound in the
    //    session JWT. Closes the "valid sig for wallet A but JWT claims
    //    wallet B" cross-binding hole.
    if !addresses_match(&body.auth.address, &claims.agentkeys.wallet_address) {
        return Err(BrokerError::Unauthorized(format!(
            "auth.address {} does not match wallet bound in session JWT ({})",
            body.auth.address, claims.agentkeys.wallet_address
        )));
    }

    // 4b. Phase B (US-027) — grant resolution. The broker consults the
    //     grant store atomically (ONE SQL UPDATE … RETURNING) for an
    //     active grant matching (master_omni_account, daemon_address,
    //     service). Failure modes:
    //       - NoGrant: legacy implicit-grant fallback (Phase 0 mints
    //         continue to work). Phase E US-039 will flip this default
    //         to fail-closed once all daemons are grant-aware.
    //       - Revoked / Expired / Exhausted: HTTP 403, no STS call.
    //     A successful Consumed result both increments used_count + 1
    //     atomically AND returns the grant_id + audit_proof for the
    //     audit row.
    let now_for_grant = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let resolved_grant_id = match state.grant_store.try_consume(
        &claims.agentkeys.omni_account,
        &body.auth.address.to_lowercase(),
        &body.intent.service,
        now_for_grant,
    ) {
        Ok(crate::storage::GrantConsumeOutcome::Consumed { grant_id, .. }) => grant_id,
        Ok(crate::storage::GrantConsumeOutcome::NoGrant) => {
            // Phase 0 implicit-grant fallback. Logged but not rejected.
            tracing::debug!(
                "mint_v2: no explicit grant for ({}, {}, {}) — Phase 0 implicit-grant path",
                claims.agentkeys.omni_account,
                body.auth.address,
                body.intent.service
            );
            String::new()
        }
        Ok(crate::storage::GrantConsumeOutcome::Revoked) => {
            // Plan §3.5.5: grant failures map to 403 (caller authenticated
            // but lacks permission). Codex Phase A.2 round-3 Vector 4 P2.
            return Err(BrokerError::Forbidden(
                "grant has been revoked".into(),
            ));
        }
        Ok(crate::storage::GrantConsumeOutcome::Expired) => {
            return Err(BrokerError::Forbidden(
                "grant is expired".into(),
            ));
        }
        Ok(crate::storage::GrantConsumeOutcome::Exhausted) => {
            return Err(BrokerError::Forbidden(
                "grant exhausted (used_count >= max_uses)".into(),
            ));
        }
        Err(e) => {
            return Err(BrokerError::Internal(format!(
                "grant_store.try_consume: {}",
                e
            )));
        }
    };

    // 5. Build the AuditRecord. record_hash is `SHA256(canonical_signing_input)`
    //    so a row mismatch is detectable by re-running the canonicalization.
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let record_hash = hex::encode(hasher.finalize());
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let record_id = format!("aud_{}_{}", now_secs, &record_hash[..16]);

    let session_name = build_session_name(&body.auth.address);

    // 6. Audit-anchor write happens BEFORE the STS call's response is
    //    constructed. Per plan §2.e the broker may speculatively call
    //    STS in parallel with the audit write to keep p50 latency low —
    //    but credentials must NOT be returned unless the audit anchor
    //    write succeeded. Phase 0 is single-anchor (sqlite) so we keep
    //    things simple: STS first, then anchor, then return creds. If
    //    anchor fails we still record the failure on the legacy log
    //    and return 500 without creds.
    //
    // Mint a per-call user-scoped OIDC JWT here (same shape as
    // /v1/mint-oidc-jwt) and pass it to AssumeRoleWithWebIdentity. The
    // `https://aws.amazon.com/tags` claim drives PrincipalTag isolation.
    let (oidc_claims, _now_oidc, _exp_oidc) = crate::handlers::oidc::build_oidc_jwt_claims(
        &state.config.oidc_issuer,
        &body.auth.address,
        state.config.oidc_jwt_ttl_seconds,
    );
    let internal_oidc_jwt = match state.oidc.sign_jwt(&oidc_claims) {
        Ok(j) => j,
        Err(e) => {
            record_legacy_outcome(
                state,
                token,
                &body.auth.address,
                &session_name,
                MintOutcome::StsError,
                Some(&format!("internal_oidc_jwt: {}", e)),
            );
            tracing::Span::current().record("outcome", "internal_oidc_jwt_failed");
            return Err(BrokerError::Internal(format!(
                "sign internal oidc jwt: {}",
                e
            )));
        }
    };
    let creds_result = state
        .sts
        .assume_role_with_web_identity(
            &state.config.data_role_arn,
            &session_name,
            &internal_oidc_jwt,
            state.config.session_duration_seconds,
        )
        .await;

    let creds = match creds_result {
        Ok(c) => c,
        Err(e) => {
            // Best-effort failure record on legacy log.
            record_legacy_outcome(
                state,
                token,
                &body.auth.address,
                &session_name,
                MintOutcome::StsError,
                Some(&e.to_string()),
            );
            tracing::Span::current().record("outcome", "sts_error");
            return Err(e);
        }
    };

    let audit_record = AuditRecord {
        id: record_id.clone(),
        minted_at: now_secs,
        record_hash,
        omni_account: claims.agentkeys.omni_account.clone(),
        wallet: body.auth.address.to_lowercase(),
        agent_id: body.intent.agent_id.clone(),
        service: body.intent.service.clone(),
        // Phase B (US-027): grant_id from resolved grant; empty when
        // legacy implicit-grant fallback fired.
        grant_id: resolved_grant_id.clone(),
        outcome: "ok".into(),
        outcome_detail: None,
    };

    // Anchor through every configured audit anchor. The audit_policy
    // selects how partial failures are handled — Phase 0 is single-
    // anchor (sqlite), so any error fails the response.
    let anchored: Vec<String> = match anchor_to_all(state, &audit_record).await {
        Ok(receipts) => receipts.into_iter().map(|r| r.anchor).collect(),
        Err(e) => {
            // The load-bearing invariant: audit failure means NO creds
            // returned. We still record best-effort on the legacy log
            // for monitoring continuity.
            record_legacy_outcome(
                state,
                token,
                &body.auth.address,
                &session_name,
                MintOutcome::BackendError,
                Some(&format!("audit_anchor: {}", e)),
            );
            tracing::Span::current().record("outcome", "audit_failed");
            return Err(BrokerError::AuditError(format!(
                "audit anchor write failed; refusing to release credentials: {}",
                e
            )));
        }
    };

    // 7. Mirror the success record on the legacy log so existing audit
    //    queries continue to function during the dual-write transition.
    if let Err(e) = state.audit.record_mint(
        MintRecord {
            requester_token: token,
            requester_wallet: &body.auth.address,
            requested_role: &state.config.data_role_arn,
            session_duration_seconds: state.config.session_duration_seconds,
            sts_session_name: &session_name,
            outcome: MintOutcome::Ok,
        },
        Some(&format!("v2 mint anchored to: {}", anchored.join(","))),
    ) {
        tracing::warn!(error = %e, "legacy audit mirror failed (non-fatal — v2 anchor row exists)");
    }

    tracing::Span::current().record("outcome", "ok");
    Ok(Json(MintResponse {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration_unix,
        wallet: body.auth.address,
        audit_record_id: Some(record_id),
        anchored: Some(anchored),
    }))
}

/// Anchor `record` to every configured AuditAnchor. Phase 0 is single-
/// anchor; Phase C extends this with multi-anchor + circuit breaker per
/// `BROKER_AUDIT_POLICY`.
async fn anchor_to_all(
    state: &SharedState,
    record: &AuditRecord,
) -> Result<Vec<AnchorReceipt>, crate::plugins::audit::AuditError> {
    let mut receipts = Vec::new();
    for anchor in &state.registry.audit {
        let receipt = anchor.anchor(record).await?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

/// Canonical signing input: the request body bytes with `auth.signature`
/// replaced by the empty string. We re-serialize via `serde_json` with
/// sorted keys so two semantically-equivalent JSON encodings produce the
/// same hash. This is the v0 form; Phase B+ may switch to deterministic
/// CBOR via `agentkeys-core::auth_request`.
fn canonical_signing_input(raw_body: &[u8], parsed: &MintBodyV2) -> Result<Vec<u8>, BrokerError> {
    // Reconstruct the body with auth.signature stripped, then sort keys.
    let mut value: Value = serde_json::from_slice(raw_body)
        .map_err(|e| BrokerError::BadRequest(format!("body re-parse: {}", e)))?;
    if let Some(auth) = value.get_mut("auth").and_then(Value::as_object_mut) {
        auth.remove("signature");
    }
    let _ = parsed; // already validated upstream; suppress unused warning.
    let canonical_string = canonicalize_json(&value);
    Ok(canonical_string.into_bytes())
}

/// Stable canonical JSON: sort object keys recursively, no extra whitespace.
fn canonicalize_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()),
                        canonicalize_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonicalize_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".into()),
    }
}

/// EIP-191 ecrecover identical to `plugins::auth::wallet_sig::ecrecover_address`
/// but operating on raw bytes (the canonical signing input). Returns the
/// 0x-prefixed lowercase 20-byte address.
fn ecrecover_eip191(message: &[u8], signature_hex: &str) -> Result<String, BrokerError> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::Keccak256;

    let sig_hex = signature_hex.trim_start_matches("0x");
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| BrokerError::BadRequest(format!("signature is not hex: {}", e)))?;
    if sig_bytes.len() != 65 {
        return Err(BrokerError::BadRequest(format!(
            "signature must be 65 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let v_byte = sig_bytes[64];
    let recovery_id_byte = match v_byte {
        0 | 1 => v_byte,
        27 | 28 => v_byte - 27,
        other => {
            return Err(BrokerError::BadRequest(format!(
                "unsupported v byte: {}",
                other
            )));
        }
    };
    let recovery_id = RecoveryId::try_from(recovery_id_byte)
        .map_err(|e| BrokerError::BadRequest(format!("bad recovery id: {}", e)))?;
    let signature = Signature::from_slice(&sig_bytes[..64])
        .map_err(|e| BrokerError::BadRequest(format!("bad sig bytes: {}", e)))?;

    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    let digest = hasher.finalize();

    let verifying_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|e| BrokerError::Unauthorized(format!("recover failed: {}", e)))?;

    let encoded_point = verifying_key.to_encoded_point(false);
    let pubkey_bytes = encoded_point.as_bytes();
    if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
        return Err(BrokerError::Internal(
            "recovered key is not 65-byte uncompressed point".into(),
        ));
    }
    let mut addr_hasher = Keccak256::new();
    addr_hasher.update(&pubkey_bytes[1..]);
    let pubkey_hash = addr_hasher.finalize();
    Ok(format!("0x{}", hex::encode(&pubkey_hash[12..])))
}

fn addresses_match(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

// `mint_legacy` (pre-issue-#71 backend-validated-bearer path) was removed
// in the OIDC-only migration. The provisioner / MCP / daemon now use
// `/v1/mint-oidc-jwt` + client-side `AssumeRoleWithWebIdentity` directly.

fn record_legacy_outcome(
    state: &SharedState,
    token: &str,
    wallet: &str,
    session_name: &str,
    outcome: MintOutcome,
    detail: Option<&str>,
) {
    if let Err(audit_err) = state.audit.record_mint(
        MintRecord {
            requester_token: token,
            requester_wallet: wallet,
            requested_role: &state.config.data_role_arn,
            session_duration_seconds: state.config.session_duration_seconds,
            sts_session_name: session_name,
            outcome,
        },
        detail,
    ) {
        tracing::error!(
            error = %audit_err,
            wallet = %wallet,
            outcome = ?outcome,
            "audit insert failed on failure path — anomaly detection is now blind"
        );
    }
}

fn build_session_name(wallet: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let micros = now.subsec_micros();
    let safe_wallet: String = wallet
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_'))
        .take(40)
        .collect();
    let mut name = format!("agentkeys-{}-{}-{:06}", safe_wallet, secs, micros);
    if name.len() > 64 {
        name.truncate(64);
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_name_under_64_chars() {
        let n = build_session_name("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(n.len() <= 64, "session name {} exceeds 64 chars", n);
        assert!(n.starts_with("agentkeys-"));
    }

    #[test]
    fn session_name_strips_unsafe_chars() {
        let n = build_session_name("0xABC/123 weird");
        assert!(!n.contains('/'));
        assert!(!n.contains(' '));
    }

    #[test]
    fn session_name_handles_empty_wallet() {
        let n = build_session_name("");
        assert!(n.starts_with("agentkeys--"));
    }

    #[test]
    fn session_name_includes_microsecond_suffix() {
        let a = build_session_name("0xabc");
        let b = build_session_name("0xabc");
        assert!(a.matches('-').count() >= 3, "expected at least 3 dashes, got {}", a);
        assert!(b.matches('-').count() >= 3);
    }

    // `looks_like_session_jwt` heuristic and its tests were removed in the
    // OIDC-only migration — `mint_aws_creds` now always routes through
    // `mint_v2` (session JWT path).

    #[test]
    fn canonicalize_json_sorts_object_keys() {
        let v: Value = serde_json::json!({
            "z": 1,
            "a": { "y": 2, "b": 3 },
            "m": [4, 5]
        });
        let s = canonicalize_json(&v);
        // "a" must precede "m" must precede "z"; nested "b" must precede "y".
        assert!(s.find("\"a\"").unwrap() < s.find("\"m\"").unwrap());
        assert!(s.find("\"m\"").unwrap() < s.find("\"z\"").unwrap());
        assert!(s.find("\"b\"").unwrap() < s.find("\"y\"").unwrap());
    }

    #[test]
    fn canonical_signing_input_strips_auth_signature() {
        let body = serde_json::to_vec(&serde_json::json!({
            "request_id": "mnt_1",
            "issued_at": "2026-05-05T14:00:00Z",
            "intent": { "agent_id": "0xabc", "service": "s3", "scope_path": "bots/" },
            "auth": { "address": "0xabc", "signature": "0xdeadbeef" }
        }))
        .unwrap();
        let parsed: MintBodyV2 = serde_json::from_slice(&body).unwrap();
        let canon = canonical_signing_input(&body, &parsed).unwrap();
        let s = String::from_utf8(canon).unwrap();
        assert!(s.contains("\"address\":\"0xabc\""));
        assert!(!s.contains("signature"));
    }

    #[test]
    fn addresses_match_is_case_insensitive() {
        assert!(addresses_match(
            "0xABCDef0123456789abcdef0123456789ABCDef00",
            "0xabcdef0123456789abcdef0123456789abcdef00"
        ));
        assert!(!addresses_match("0xabc", "0xdef"));
    }

    #[test]
    fn ecrecover_eip191_round_trip() {
        use k256::ecdsa::SigningKey;
        use sha3::Keccak256;
        let key = SigningKey::random(&mut crate::oidc::rand_compat::OsRngWrapper);
        let vkey = key.verifying_key();
        let pt = vkey.to_encoded_point(false);
        let mut h = Keccak256::new();
        h.update(&pt.as_bytes()[1..]);
        let pub_hash = h.finalize();
        let expected_addr = format!("0x{}", hex::encode(&pub_hash[12..]));

        let message = b"canonical body bytes";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut h2 = Keccak256::new();
        h2.update(prefix.as_bytes());
        h2.update(message);
        let digest = h2.finalize();

        let (sig, rid) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes.push(rid.to_byte());
        let sig_hex = format!("0x{}", hex::encode(&sig_bytes));

        let recovered = ecrecover_eip191(message, &sig_hex).unwrap();
        assert_eq!(recovered.to_lowercase(), expected_addr.to_lowercase());
    }
}
