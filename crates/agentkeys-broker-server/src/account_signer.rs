use crate::accept_assertion::{decode_assertion_parts, AssertionParts, BrowserAssertion};
use crate::error::BrokerError;
use crate::handlers::accept::{eth_call, selector};
use base64::Engine;

/// One live signer row from `P256Account.signers(credIdHash)` +
/// `signerGeneration()` — everything `verifyAssertion` needs.
pub(crate) struct LiveSigner {
    pub(crate) credential_hash: [u8; 32],
    pub(crate) pub_x: [u8; 32],
    pub(crate) pub_y: [u8; 32],
    pub(crate) rp_id_hash: [u8; 32],
}

/// Decoded `signers(bytes32)` return. The deployed fleet has TWO layouts
/// (verified live on Heima prod, 2026-06-10): the current 5-word struct
/// `(pubX, pubY, rpIdHash, active, generation)` and the legacy pre-recovery
/// 4-word struct without `generation` — the live factory was deployed from a
/// pre-final #164 revision and never redeployed (VERSION stayed 0.3, so the
/// by-VERSION idempotency skipped it). Legacy accounts also have NO
/// `signerGeneration()` selector (the call reverts), so `generation: None`
/// means the caller must skip that cross-check entirely — `active` is the
/// whole liveness story on those accounts.
#[derive(Debug)]
pub(crate) struct SignerRow {
    pub(crate) pub_x: [u8; 32],
    pub(crate) pub_y: [u8; 32],
    pub(crate) rp_id_hash: [u8; 32],
    pub(crate) active: bool,
    pub(crate) generation: Option<u64>,
}

pub(crate) fn decode_signer_row(raw: &[u8]) -> Result<SignerRow, String> {
    let generation = match raw.len() {
        160 => Some(abi_u64(raw, 4)?),
        128 => None,
        n => {
            return Err(format!(
                "signers() returned {n} bytes — expected 160 (current 5-field Signer) or 128 \
                 (legacy pre-recovery 4-field Signer)"
            ))
        }
    };
    Ok(SignerRow {
        pub_x: word_at(raw, 0)?,
        pub_y: word_at(raw, 1)?,
        rp_id_hash: word_at(raw, 2)?,
        active: match abi_u64(raw, 3)? {
            0 => false,
            1 => true,
            _ => return Err("invalid ABI signer active flag".into()),
        },
        generation,
    })
}

pub(crate) fn word_at(raw: &[u8], i: usize) -> Result<[u8; 32], String> {
    let start = i.checked_mul(32).ok_or("ABI index overflow")?;
    let end = start.checked_add(32).ok_or("ABI index overflow")?;
    if raw.len() < end {
        return Err(format!(
            "short ABI return: need word {i} ({end} bytes), got {}",
            raw.len()
        ));
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&raw[start..end]);
    Ok(w)
}

fn abi_u64(raw: &[u8], index: usize) -> Result<u64, String> {
    let word = word_at(raw, index)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err("ABI uint64 overflow".into());
    }
    Ok(u64::from_be_bytes(
        word[24..].try_into().map_err(|_| "invalid ABI uint64")?,
    ))
}

pub(crate) fn decode_hex_result(raw: &str) -> Result<Vec<u8>, String> {
    hex::decode(raw.trim_start_matches("0x")).map_err(|e| format!("eth_call result hex: {e}"))
}

/// ABI-encode the `verifyAssertion(bytes32,bytes32,bytes,bytes,uint256,
/// uint256,uint256,uint256,uint256)` calldata. Head = 9 words; the two `bytes`
/// params are offset-referenced into the tail (each: length word + 32-padded
/// data) — the standard dynamic-type layout.
pub(crate) fn encode_verify_assertion_call(
    challenge: &[u8; 32],
    rp_id_hash: &[u8; 32],
    parts: &AssertionParts,
    pub_x: &[u8; 32],
    pub_y: &[u8; 32],
) -> String {
    const HEAD_WORDS: usize = 9;
    let pad32 = |len: usize| len.div_ceil(32) * 32;
    let word_usize = |n: usize| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&(n as u64).to_be_bytes());
        w
    };

    let auth = &parts.authenticator_data;
    let cdj = &parts.client_data_json;
    let off_auth = HEAD_WORDS * 32;
    let off_cdj = off_auth + 32 + pad32(auth.len());

    let mut data: Vec<u8> = Vec::with_capacity(off_cdj + 32 + pad32(cdj.len()));
    data.extend_from_slice(challenge);
    data.extend_from_slice(rp_id_hash);
    data.extend_from_slice(&word_usize(off_auth));
    data.extend_from_slice(&word_usize(off_cdj));
    data.extend_from_slice(&word_usize(parts.challenge_location));
    data.extend_from_slice(&parts.r);
    data.extend_from_slice(&parts.s);
    data.extend_from_slice(pub_x);
    data.extend_from_slice(pub_y);
    for blob in [auth.as_slice(), cdj.as_slice()] {
        data.extend_from_slice(&word_usize(blob.len()));
        data.extend_from_slice(blob);
        data.resize(data.len() + (pad32(blob.len()) - blob.len()), 0);
    }

    format!(
        "0x{}{}",
        selector(
            "verifyAssertion(bytes32,bytes32,bytes,bytes,uint256,uint256,uint256,uint256,uint256)"
        ),
        hex::encode(data)
    )
}

/// Read the LIVE signer for `cred_id_hash` from the account: `signers(bytes32)`
/// decoded layout-tolerantly ([`decode_signer_row`]), cross-checked against
/// `signerGeneration()` when the account HAS generations (current layout only —
/// the legacy 4-field accounts have neither the field nor the selector). `Err`
/// carries the precise rejection.
pub(crate) async fn read_live_signer(
    http: &reqwest::Client,
    rpc: &str,
    account: &[u8; 20],
    cred_id_hash: &[u8; 32],
) -> Result<Option<LiveSigner>, BrokerError> {
    let data = format!(
        "0x{}{}",
        selector("signers(bytes32)"),
        hex::encode(cred_id_hash)
    );
    let raw = decode_hex_result(
        &eth_call(http, rpc, account, &data)
            .await
            .map_err(BrokerError::BackendUnreachable)?,
    )
    .map_err(BrokerError::BackendUnreachable)?;
    let row = decode_signer_row(&raw).map_err(BrokerError::BackendUnreachable)?;

    if !row.active {
        if row.pub_x == [0; 32] && row.pub_y == [0; 32] && row.rp_id_hash == [0; 32] {
            return Ok(None);
        }
        return Err(BrokerError::Unauthorized(
            "master passkey is not an active signer".into(),
        ));
    }
    if let Some(generation) = row.generation {
        let gen_raw = decode_hex_result(
            &eth_call(
                http,
                rpc,
                account,
                &format!("0x{}", selector("signerGeneration()")),
            )
            .await
            .map_err(BrokerError::BackendUnreachable)?,
        )
        .map_err(BrokerError::BackendUnreachable)?;
        let current_gen = abi_u64(&gen_raw, 0).map_err(BrokerError::BackendUnreachable)?;
        if generation != current_gen {
            return Err(BrokerError::Unauthorized(format!(
                "master passkey is from signer generation {generation}, account is at \
                 {current_gen} (rotated via recovery) — use a current account signer"
            )));
        }
    }
    Ok(Some(LiveSigner {
        credential_hash: *cred_id_hash,
        pub_x: row.pub_x,
        pub_y: row.pub_y,
        rp_id_hash: row.rp_id_hash,
    }))
}

fn validate_assertion_context(
    parts: &AssertionParts,
    challenge: &[u8; 32],
    rp_id_hash: &[u8; 32],
) -> Result<(), BrokerError> {
    let data: serde_json::Value = serde_json::from_slice(&parts.client_data_json)
        .map_err(|_| BrokerError::Unauthorized("malformed assertion client data".into()))?;
    if parts.authenticator_data.len() < 37
        || parts.authenticator_data[..32] != *rp_id_hash
        || parts.authenticator_data[32] & 5 != 5
        || data.get("type").and_then(|value| value.as_str()) != Some("webauthn.get")
        || data.get("challenge").and_then(|value| value.as_str())
            != Some(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge))
        || data.get("crossOrigin").and_then(|value| value.as_bool()) == Some(true)
    {
        return Err(BrokerError::Unauthorized(
            "assertion has wrong RP, challenge, user verification, or context".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn verify_assertion(
    http: &reqwest::Client,
    rpc: &str,
    verifier_owner: &[u8; 20],
    challenge: &[u8; 32],
    signer: &LiveSigner,
    assertion: &BrowserAssertion,
) -> Result<(), BrokerError> {
    let parts = decode_assertion_parts(assertion).map_err(BrokerError::BadRequest)?;
    validate_assertion_context(&parts, challenge, &signer.rp_id_hash)?;
    let verifier = decode_hex_result(
        &eth_call(
            http,
            rpc,
            verifier_owner,
            &format!("0x{}", selector("k11Verifier()")),
        )
        .await
        .map_err(BrokerError::BackendUnreachable)?,
    )
    .map_err(BrokerError::BackendUnreachable)?;
    let address: [u8; 20] = word_at(&verifier, 0).map_err(BrokerError::BackendUnreachable)?[12..]
        .try_into()
        .unwrap();
    let calldata = encode_verify_assertion_call(
        challenge,
        &signer.rp_id_hash,
        &parts,
        &signer.pub_x,
        &signer.pub_y,
    );
    let result = eth_call(http, rpc, &address, &calldata)
        .await
        .map_err(BrokerError::BackendUnreachable)?;
    let verified = decode_hex_result(&result).map_err(BrokerError::BackendUnreachable)?;
    let word = word_at(&verified, 0).map_err(BrokerError::BackendUnreachable)?;
    if word[..31] != [0; 31] || word[31] != 1 {
        return Err(BrokerError::Unauthorized(
            "assertion rejected by the on-chain K11 verifier".into(),
        ));
    }
    Ok(())
}

pub(crate) fn credential_hash(credential_id: &str) -> Result<[u8; 32], BrokerError> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(credential_id)
        .map_err(|e| BrokerError::BadRequest(format!("credential_id base64url: {e}")))?;
    if raw.is_empty() || raw.len() > 1024 {
        return Err(BrokerError::BadRequest(
            "credential_id must contain 1 to 1024 bytes".into(),
        ));
    }
    Ok(agentkeys_core::erc4337::credential_id_hash(&raw))
}

pub(crate) async fn resolve_assertion_signer(
    http: &reqwest::Client,
    rpc: &str,
    account: &[u8; 20],
    operator_omni: &[u8; 32],
    challenge: &[u8; 32],
    assertion: &BrowserAssertion,
) -> Result<[u8; 32], BrokerError> {
    let credential_hash = credential_hash(&assertion.credential_id)?;
    let signer = match read_live_signer(http, rpc, account, &credential_hash).await? {
        Some(signer) => signer,
        None => read_live_signer(
            http,
            rpc,
            account,
            &agentkeys_core::erc4337::master_cred_id_hash(operator_omni),
        )
        .await?
        .ok_or_else(|| {
            BrokerError::Unauthorized("no active master signer for this account".into())
        })?,
    };
    verify_assertion(http, rpc, account, challenge, &signer, assertion).await?;
    Ok(signer.credential_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::post, Json, Router};
    use p256::ecdsa::{
        signature::{Signer as _, Verifier as _},
        Signature, SigningKey, VerifyingKey,
    };
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Fixture {
        credential_hash: [u8; 32],
        legacy_hash: [u8; 32],
        public_key: VerifyingKey,
        active: bool,
        generation: u64,
        current_generation: u64,
        missing: bool,
        rpc_failure: bool,
        legacy_layout: bool,
        calls: Arc<Mutex<Vec<String>>>,
    }
    fn encode_word(number: u64) -> [u8; 32] {
        let mut word = [0; 32];
        word[24..].copy_from_slice(&number.to_be_bytes());
        word
    }
    fn row(fixture: &Fixture) -> Vec<u8> {
        let point = fixture.public_key.to_encoded_point(false);
        let mut encoded = [
            point.x().unwrap().as_slice(),
            point.y().unwrap().as_slice(),
            Sha256::digest(b"localhost").as_slice(),
            &encode_word(u64::from(fixture.active)),
        ]
        .concat();
        if !fixture.legacy_layout {
            encoded.extend_from_slice(&encode_word(fixture.generation));
        }
        encoded
    }
    async fn rpc(
        State(fixture): State<Fixture>,
        Json(request): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let target = request["params"][0]["to"].as_str().unwrap();
        let calldata = request["params"][0]["data"].as_str().unwrap().to_string();
        fixture.calls.lock().unwrap().push(calldata.clone());
        let bytes = hex::decode(calldata.trim_start_matches("0x")).unwrap();
        let selector_hex = hex::encode(&bytes[..4]);
        let result = if selector_hex == selector("signers(bytes32)") {
            assert_eq!(target, format!("0x{}", hex::encode([0x44; 20])));
            if fixture.rpc_failure {
                return Json(
                    serde_json::json!({"error":{"code":-32000,"message":"RPC unavailable"}}),
                );
            }
            let hash: [u8; 32] = bytes[4..36].try_into().unwrap();
            if (hash == fixture.credential_hash && !fixture.missing) || hash == fixture.legacy_hash
            {
                row(&fixture)
            } else {
                vec![0; 160]
            }
        } else if selector_hex == selector("signerGeneration()") {
            encode_word(fixture.current_generation).to_vec()
        } else if selector_hex == selector("k11Verifier()") {
            let mut word = [0; 32];
            word[12..].copy_from_slice(&[0x55; 20]);
            word.to_vec()
        } else {
            assert_eq!(target, format!("0x{}", hex::encode([0x55; 20])));
            assert_eq!(selector_hex,selector("verifyAssertion(bytes32,bytes32,bytes,bytes,uint256,uint256,uint256,uint256,uint256)"));
            let args = &bytes[4..];
            let offset = |index| {
                u64::from_be_bytes(word_at(args, index).unwrap()[24..].try_into().unwrap()) as usize
            };
            let blob = |index| {
                let at = offset(index);
                let len = u64::from_be_bytes(args[at + 24..at + 32].try_into().unwrap()) as usize;
                &args[at + 32..at + 32 + len]
            };
            let auth = blob(2);
            let client = blob(3);
            let signed = [auth, Sha256::digest(client).as_slice()].concat();
            let signature =
                Signature::from_scalars(word_at(args, 5).unwrap(), word_at(args, 6).unwrap())
                    .unwrap();
            encode_word(u64::from(
                fixture.public_key.verify(&signed, &signature).is_ok(),
            ))
            .to_vec()
        };
        Json(
            serde_json::json!({"jsonrpc":"2.0","id":1,"result":format!("0x{}",hex::encode(result))}),
        )
    }
    fn assertion(key: &SigningKey, challenge: &[u8; 32]) -> BrowserAssertion {
        let mut auth = Sha256::digest(b"localhost").to_vec();
        auth.extend_from_slice(&[5, 0, 0, 0, 1]);
        let client=format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"http://localhost:3115\"}}",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)).into_bytes();
        let signed = [auth.as_slice(), Sha256::digest(&client).as_slice()].concat();
        let signature: Signature = key.sign(&signed);
        let encode = |data: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
        BrowserAssertion {
            authenticator_data: encode(&auth),
            client_data_json: encode(&client),
            signature: encode(signature.to_der().as_bytes()),
            credential_id: encode(b"browser-key"),
        }
    }
    async fn fixture_call(
        missing: bool,
        active: bool,
        generation: u64,
        current_generation: u64,
        rpc_failure: bool,
        wrong_signature: bool,
        legacy_layout: bool,
    ) -> (Result<[u8; 32], BrokerError>, Vec<String>) {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let omni = [0x11; 32];
        let challenge = [0x22; 32];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fixture = Fixture {
            credential_hash: agentkeys_core::erc4337::credential_id_hash(b"browser-key"),
            legacy_hash: agentkeys_core::erc4337::master_cred_id_hash(&omni),
            public_key: *key.verifying_key(),
            active,
            generation,
            current_generation,
            missing,
            rpc_failure,
            legacy_layout,
            calls: calls.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/", post(rpc)).with_state(fixture),
            )
            .await
            .unwrap()
        });
        let signing_key = if wrong_signature {
            SigningKey::random(&mut rand_core::OsRng)
        } else {
            key
        };
        let result = resolve_assertion_signer(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            &[0x44; 20],
            &omni,
            &challenge,
            &assertion(&signing_key, &challenge),
        )
        .await;
        server.abort();
        let observed = calls.lock().unwrap().clone();
        (result, observed)
    }
    #[tokio::test]
    async fn resolves_additional_credential_on_the_bound_account() {
        let (result, _) = fixture_call(false, true, 7, 7, false, false, false).await;
        assert_eq!(
            result.unwrap(),
            agentkeys_core::erc4337::credential_id_hash(b"browser-key")
        );
    }
    #[tokio::test]
    async fn original_synthetic_signer_remains_usable_when_raw_id_is_absent() {
        let (result, _) = fixture_call(true, true, 7, 7, false, false, false).await;
        assert_eq!(
            result.unwrap(),
            agentkeys_core::erc4337::master_cred_id_hash(&[0x11; 32])
        );
    }
    #[tokio::test]
    async fn rejects_revoked_rotated_and_wrong_signature_credentials() {
        for (active, generation, current_generation, wrong_signature) in [
            (false, 7, 7, false),
            (true, 6, 7, false),
            (true, 7, 7, true),
        ] {
            let (result, calls) = fixture_call(
                false,
                active,
                generation,
                current_generation,
                false,
                wrong_signature,
                false,
            )
            .await;
            assert!(matches!(result, Err(BrokerError::Unauthorized(_))));
            assert!(!calls.iter().any(|call| call.ends_with(&hex::encode(
                agentkeys_core::erc4337::master_cred_id_hash(&[0x11; 32])
            ))));
        }
    }
    #[tokio::test]
    async fn legacy_four_word_accounts_preserve_original_signer_login() {
        let (result, calls) = fixture_call(true, true, 7, 999, false, false, true).await;
        assert_eq!(
            result.unwrap(),
            agentkeys_core::erc4337::master_cred_id_hash(&[0x11; 32])
        );
        assert!(!calls
            .iter()
            .any(|call| call == &format!("0x{}", selector("signerGeneration()"))));
    }

    #[tokio::test]
    async fn rpc_error_does_not_fall_back_to_synthetic_signer() {
        let (result, calls) = fixture_call(false, true, 7, 7, true, false, false).await;
        assert!(matches!(result, Err(BrokerError::BackendUnreachable(_))));
        assert_eq!(calls.len(), 1);
    }
    #[test]
    fn rejects_wrong_rp_challenge_and_missing_user_verification() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let challenge = [0x22; 32];
        let mut parts = decode_assertion_parts(&assertion(&key, &challenge)).unwrap();
        let rp = Sha256::digest(b"localhost").into();
        assert!(validate_assertion_context(&parts, &challenge, &rp).is_ok());
        assert!(validate_assertion_context(&parts, &[0x33; 32], &rp).is_err());
        assert!(validate_assertion_context(&parts, &challenge, &[0x33; 32]).is_err());
        parts.authenticator_data[32] = 1;
        assert!(validate_assertion_context(&parts, &challenge, &rp).is_err());
    }
}
