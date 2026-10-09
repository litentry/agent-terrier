//! `POST /v1/auth/passkey/verify` — verify the re-auth assertion against the
//! CHAIN and mint the session JWT (issue #242).
//!
//! Verification is pure `eth_call`s against the SAME contracts `handleOps`
//! uses — zero broker-side WebAuthn/P-256 crypto, so the verb can never drift
//! from what the chain itself accepts:
//!
//!   1. `operatorMasterWallet(omni)` → the challenge-bound P256Account, RE-read at
//!      verify time (a reset-master between start and verify fails closed);
//!   2. `account.signers(credential_id_hash(rawId))`, or the original synthetic
//!      signer when that row is absent, plus `signerGeneration()` →
//!      the live signer's `(pubX, pubY, rpIdHash)` — generation-checked, so a
//!      social-recovery rotation (#164 E5) instantly invalidates old passkeys
//!      here exactly as it does on chain;
//!   3. `K11Verifier.verifyAssertion(challenge, rpIdHash, authData,
//!      clientDataJSON, loc, r, s, pubX, pubY)` — the deployed on-chain
//!      verifier (UP+UV flags, challenge-in-clientDataJSON compare, P-256
//!      signature) as a view call.
//!
//! Body: `{ "challenge": "0x<64 hex>", "assertion": { authenticator_data,
//! client_data_json, signature, credential_id } }` (the assertion exactly as
//! `apps/parent-control/lib/webauthn.ts::getAssertionOverHash` emits it).
//!
//! On success the response mirrors the other auth verbs:
//! `{ status: "verified", session_jwt, session_jwt_kid, expires_at,
//!    omni_account, account }` with `agentkeys.omni_account` = the
//! chain-verified omni, `identity_type` = `"passkey"`, `identity_value` = the
//! master account address. The JWT is scoped to that omni and nothing else.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::accept_assertion::BrowserAssertion;
use crate::error::BrokerError;
use crate::handlers::accept::{call_operator_master_wallet, load_chain_read_config};
use crate::handlers::auth::passkey_start::{now_unix_i64, parse_omni_0x64, PASSKEY_NONCE_PREFIX};
use crate::jwt::issue::mint_session_jwt;
use crate::state::SharedState;
use crate::storage::ConsumeOutcome;

#[derive(Debug, Deserialize)]
pub struct PasskeyVerifyRequest {
    pub challenge: String,
    pub assertion: BrowserAssertion,
}

fn parse_challenge_binding(binding: &str) -> Result<(String, [u8; 20]), BrokerError> {
    let (omni, account) = binding.split_once(':').ok_or_else(|| {
        BrokerError::Unauthorized(
            "challenge predates account binding; restart passkey sign-in".into(),
        )
    })?;
    let account = crate::handlers::accept::addr20(account, "challenge account")
        .map_err(BrokerError::Unauthorized)?;
    Ok((parse_omni_0x64(omni)?, account))
}

pub async fn passkey_verify(
    State(state): State<SharedState>,
    Json(body): Json<PasskeyVerifyRequest>,
) -> Result<impl IntoResponse, BrokerError> {
    // 1. Single-use challenge consume (TTL + replay protection + omni binding).
    let challenge_hex = body.challenge.trim().to_lowercase();
    let challenge_bytes = hex::decode(challenge_hex.trim_start_matches("0x"))
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or_else(|| BrokerError::BadRequest("challenge must be 0x + 64 hex".into()))?;
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&challenge_bytes);

    let omni = match state
        .nonce_store
        .consume(&challenge_hex, now_unix_i64())
        .map_err(|e| BrokerError::Internal(format!("consume passkey challenge: {e:?}")))?
    {
        ConsumeOutcome::Consumed { address, .. } => address
            .strip_prefix(PASSKEY_NONCE_PREFIX)
            .map(str::to_string)
            .ok_or_else(|| {
                BrokerError::Unauthorized("challenge was not issued for passkey re-auth".into())
            })?,
        ConsumeOutcome::Expired => {
            return Err(BrokerError::Unauthorized(
                "challenge expired — restart the passkey sign-in".into(),
            ));
        }
        ConsumeOutcome::NotFoundOrConsumed => {
            return Err(BrokerError::Unauthorized(
                "unknown or already-used challenge".into(),
            ));
        }
    };
    let (omni, challenge_account) = parse_challenge_binding(&omni)?;
    state
        .config
        .login_access
        .require_omni(&state, &omni)
        .await?;
    let mut omni32 = [0u8; 32];
    omni32.copy_from_slice(
        &hex::decode(omni.trim_start_matches("0x"))
            .map_err(|e| BrokerError::Internal(format!("stored omni hex: {e}")))?,
    );

    // 2. Chain reads — re-resolve the master account at verify time.
    let (rpc_url, registry) = load_chain_read_config().map_err(BrokerError::BackendUnreachable)?;
    let account = call_operator_master_wallet(&state.http, &rpc_url, &registry, &omni)
        .await
        .map_err(BrokerError::BackendUnreachable)?;
    if account == [0u8; 20] || account != challenge_account {
        return Err(BrokerError::Unauthorized(
            "master account changed or was unbound since the challenge was issued".into(),
        ));
    }
    crate::account_signer::resolve_assertion_signer(
        &state.http,
        &rpc_url,
        &account,
        &omni32,
        &challenge,
        &body.assertion,
    )
    .await?;

    // 4. Mint the session JWT for the chain-verified omni — with the omni claim
    //    in the BARE lowercase 64-hex form, byte-identical to the email-flow J1s.
    //    `/v1/mint-oidc-jwt` copies `agentkeys.omni_account` into the AWS
    //    principal tag, and the bucket policies interpolate it into the bare
    //    `bots/<omni>/` S3 prefixes — a `0x`-prefixed claim tags the STS session
    //    with a `bots/0x<omni>/` prefix that matches nothing, so every
    //    config/memory read AccessDenied'd after a passkey re-login (real
    //    2026-06-10 incident).
    let omni_bare = omni.trim_start_matches("0x").to_string();
    let account_hex = format!("0x{}", hex::encode(account));
    let ttl_seconds = std::env::var(crate::env::BROKER_SESSION_JWT_TTL_SECONDS)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(18_000);
    let token = mint_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &omni_bare,
        "", // the managed wallet is daemon-local state; the broker asserts only the omni
        "passkey",
        &account_hex,
        ttl_seconds,
    )
    .map_err(|e| BrokerError::Internal(format!("mint session jwt: {e}")))?;
    let expires_at = now_unix_i64() + ttl_seconds as i64;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status":          "verified",
            "session_jwt":     token,
            "session_jwt_kid": state.session_keypair.kid,
            "expires_at":      expires_at,
            "omni_account":    omni_bare,
            "account":         account_hex,
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept_assertion::{decode_assertion_parts, AssertionParts};
    use crate::account_signer::{
        decode_hex_result, decode_signer_row, encode_verify_assertion_call, word_at,
    };
    use crate::handlers::accept::selector;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};

    #[test]
    fn challenge_binding_requires_both_operator_and_original_account() {
        let omni = format!("0x{}", "11".repeat(32));
        let account = format!("0x{}", "22".repeat(20));
        assert_eq!(
            parse_challenge_binding(&format!("{omni}:{account}")).unwrap(),
            (omni.clone(), [0x22; 20])
        );
        assert!(parse_challenge_binding(&omni).is_err());
        assert!(parse_challenge_binding(&format!("{omni}:0x1234")).is_err());
    }

    fn sample_parts() -> AssertionParts {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let sig: Signature = sk.sign(b"m");
        let cdj = br#"{"type":"webauthn.get","challenge":"QUJD"}"#.to_vec();
        let loc = std::str::from_utf8(&cdj)
            .unwrap()
            .find("\"challenge\":\"")
            .unwrap()
            + "\"challenge\":\"".len();
        let rs = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&rs[0..32]);
        s.copy_from_slice(&rs[32..64]);
        AssertionParts {
            authenticator_data: vec![0xAA; 37],
            client_data_json: cdj,
            challenge_location: loc,
            r,
            s,
        }
    }

    #[test]
    fn verify_assertion_calldata_layout_is_canonical() {
        let parts = sample_parts();
        let challenge = [0x11u8; 32];
        let rp = [0x22u8; 32];
        let px = [0x33u8; 32];
        let py = [0x44u8; 32];
        let call = encode_verify_assertion_call(&challenge, &rp, &parts, &px, &py);
        let bytes = hex::decode(call.trim_start_matches("0x")).unwrap();
        let (sel, args) = bytes.split_at(4);
        assert_eq!(
            hex::encode(sel),
            selector("verifyAssertion(bytes32,bytes32,bytes,bytes,uint256,uint256,uint256,uint256,uint256)")
        );
        // Head words: challenge | rpIdHash | offAuth | offCdj | loc | r | s | pubX | pubY.
        assert_eq!(&args[0..32], &challenge);
        assert_eq!(&args[32..64], &rp);
        let w = |i: usize| u64::from_be_bytes(args[i * 32 + 24..i * 32 + 32].try_into().unwrap());
        let off_auth = w(2) as usize;
        let off_cdj = w(3) as usize;
        assert_eq!(off_auth, 9 * 32);
        assert_eq!(w(4) as usize, parts.challenge_location);
        assert_eq!(&args[5 * 32..6 * 32], &parts.r);
        assert_eq!(&args[6 * 32..7 * 32], &parts.s);
        assert_eq!(&args[7 * 32..8 * 32], &px);
        assert_eq!(&args[8 * 32..9 * 32], &py);
        // Tail: authData at its offset (len word + data), then clientDataJSON.
        let auth_len = w(off_auth / 32) as usize;
        assert_eq!(auth_len, parts.authenticator_data.len());
        assert_eq!(
            &args[off_auth + 32..off_auth + 32 + auth_len],
            parts.authenticator_data.as_slice()
        );
        let cdj_len_word =
            u64::from_be_bytes(args[off_cdj + 24..off_cdj + 32].try_into().unwrap()) as usize;
        assert_eq!(cdj_len_word, parts.client_data_json.len());
        assert_eq!(
            &args[off_cdj + 32..off_cdj + 32 + cdj_len_word],
            parts.client_data_json.as_slice()
        );
        // Both blobs 32-padded → total length word-aligned.
        assert_eq!(args.len() % 32, 0);
    }

    #[test]
    fn decode_assertion_parts_roundtrips_browser_b64u() {
        let parts = sample_parts();
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let sig: Signature = sk.sign(b"any");
        let a = BrowserAssertion {
            authenticator_data: URL_SAFE_NO_PAD.encode(&parts.authenticator_data),
            client_data_json: URL_SAFE_NO_PAD.encode(&parts.client_data_json),
            signature: URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()),
            credential_id: URL_SAFE_NO_PAD.encode(b"cred"),
        };
        let decoded = decode_assertion_parts(&a).unwrap();
        assert_eq!(decoded.authenticator_data, parts.authenticator_data);
        assert_eq!(decoded.client_data_json, parts.client_data_json);
        assert_eq!(decoded.challenge_location, parts.challenge_location);
        assert_eq!(&decoded.r, &sig.to_bytes()[0..32]);
    }

    #[test]
    fn word_decode_helpers_reject_short_returns() {
        assert!(word_at(&[0u8; 31], 0).is_err());
        assert!(word_at(&[0u8; 64], 2).is_err());
        assert_eq!(word_at(&[0u8; 64], 1).unwrap(), [0u8; 32]);
        assert!(decode_hex_result("0xzz").is_err());
    }

    /// Pins BOTH deployed `Signer` layouts (the legacy one is live on Heima
    /// prod — accounts from the pre-final #164 factory; real 2026-06-10
    /// incident: the strict 5-word decode 502'd every legacy re-login).
    #[test]
    fn decode_signer_row_handles_current_and_legacy_layouts() {
        let word = |b: u8| [b; 32];
        // Current 5-word layout: generation present.
        let mut current = Vec::new();
        for w in [word(0x11), word(0x22), word(0x33)] {
            current.extend_from_slice(&w);
        }
        let mut active = [0u8; 32];
        active[31] = 1;
        current.extend_from_slice(&active);
        let mut generation = [0u8; 32];
        generation[31] = 7;
        current.extend_from_slice(&generation);
        let row = decode_signer_row(&current).unwrap();
        assert!(row.active);
        assert_eq!(row.generation, Some(7));
        assert_eq!(row.pub_x, word(0x11));
        assert_eq!(row.rp_id_hash, word(0x33));

        // Legacy 4-word layout (no generation field on chain).
        let legacy = &current[..128];
        let row = decode_signer_row(legacy).unwrap();
        assert!(row.active);
        assert_eq!(row.generation, None);
        assert_eq!(row.pub_y, word(0x22));

        // Inactive signer decodes (the caller rejects on `active`).
        let mut inactive = current.clone();
        inactive[3 * 32 + 31] = 0;
        assert!(!decode_signer_row(&inactive).unwrap().active);

        // Anything else is a hard error naming both expected shapes.
        let err = decode_signer_row(&current[..96]).unwrap_err();
        assert!(err.contains("96 bytes") && err.contains("160") && err.contains("128"));
    }

    #[test]
    fn passkey_challenge_store_is_single_use_and_flow_bound() {
        use crate::storage::AuthNonceStore;
        let store = AuthNonceStore::open_in_memory().unwrap();
        let omni = format!("0x{}", "ab".repeat(32));
        store
            .issue(
                "0xchallenge1",
                &format!("{PASSKEY_NONCE_PREFIX}{omni}"),
                100,
                100 + super::super::passkey_start::PASSKEY_CHALLENGE_TTL_SECS,
            )
            .unwrap();
        // First consume succeeds and carries the flow-bound omni.
        match store.consume("0xchallenge1", 110).unwrap() {
            ConsumeOutcome::Consumed { address, .. } => {
                assert_eq!(address, format!("{PASSKEY_NONCE_PREFIX}{omni}"));
                assert_eq!(
                    address.strip_prefix(PASSKEY_NONCE_PREFIX).unwrap(),
                    omni.as_str()
                );
            }
            other => panic!("expected Consumed, got {other:?}"),
        }
        // Second consume: single-use.
        assert_eq!(
            store.consume("0xchallenge1", 111).unwrap(),
            ConsumeOutcome::NotFoundOrConsumed
        );
        // A SIWE-shaped row (no prefix) is rejected by the prefix check.
        store.issue("0xsiwe", "0xdeadbeef", 100, 999).unwrap();
        match store.consume("0xsiwe", 110).unwrap() {
            ConsumeOutcome::Consumed { address, .. } => {
                assert!(address.strip_prefix(PASSKEY_NONCE_PREFIX).is_none());
            }
            other => panic!("expected Consumed, got {other:?}"),
        }
        // Expiry honors the TTL.
        store
            .issue(
                "0xchallenge2",
                &format!("{PASSKEY_NONCE_PREFIX}{omni}"),
                100,
                160,
            )
            .unwrap();
        assert_eq!(
            store.consume("0xchallenge2", 200).unwrap(),
            ConsumeOutcome::Expired
        );
    }
}
