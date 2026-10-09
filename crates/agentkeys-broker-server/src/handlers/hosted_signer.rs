use agentkeys_core::device_crypto::{device_key_hash, ecrecover_eip191};
use agentkeys_core::erc4337::{
    additional_master_challenge, master_device_key_hash, AdditionalMaster, AgentRegister,
    ScopeGrant,
};
use agentkeys_protocol::hosted_signer::*;
use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use crate::accept_assertion::decode_assertion_parts;
use crate::account_signer::{
    credential_hash, decode_hex_result, read_live_signer, verify_assertion, word_at, LiveSigner,
};
use crate::error::BrokerError;
use crate::handlers::accept::{
    addr20, bearer, call_entrypoint_nonce, call_operator_master_wallet, eth_call,
    load_accept_config, load_chain_read_config, selector, SPONSOR_WINDOW_SECS,
};
use crate::sponsored_accept::{
    assemble_hosted_signer_userop, AcceptUserOpParams, BuildAcceptResponse,
};
use crate::state::SharedState;

fn hex0x(value: &[u8]) -> String {
    format!("0x{}", hex::encode(value))
}
fn now() -> Result<u64, BrokerError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| BrokerError::Internal(error.to_string()))
}
fn word(value: &str, name: &str) -> Result<[u8; 32], BrokerError> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| BrokerError::BadRequest(format!("{name}: {error}")))?
        .try_into()
        .map_err(|_| BrokerError::BadRequest(format!("{name} must be 32 bytes")))
}
async fn operator(state: &SharedState, headers: &HeaderMap) -> Result<[u8; 32], BrokerError> {
    let token =
        bearer(headers).map_err(|_| BrokerError::Unauthorized("session required".into()))?;
    let claims = crate::jwt::verify::verify_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &token,
    )?;
    if claims.agentkeys.parent_omni.is_some() {
        return Err(BrokerError::Forbidden("master session required".into()));
    }
    state
        .config
        .login_access
        .require_omni(state, &claims.agentkeys.omni_account)
        .await?;
    word(&claims.agentkeys.omni_account, "session omni")
}
async fn current_account(
    state: &SharedState,
    rpc: &str,
    registry: &[u8; 20],
    omni: &[u8; 32],
) -> Result<[u8; 20], BrokerError> {
    let account = call_operator_master_wallet(&state.http, rpc, registry, &hex0x(omni))
        .await
        .map_err(BrokerError::BackendUnreachable)?;
    if account == [0; 20] {
        return Err(BrokerError::Forbidden(
            "existing registered account required; enrollment never creates an account".into(),
        ));
    }
    Ok(account)
}
async fn operator_nonce(
    state: &SharedState,
    rpc: &str,
    registry: &[u8; 20],
    omni: &[u8; 32],
) -> Result<[u8; 32], BrokerError> {
    let data = format!(
        "0x{}{}",
        selector("operatorNonce(bytes32)"),
        hex::encode(omni)
    );
    let raw = decode_hex_result(
        &eth_call(&state.http, rpc, registry, &data)
            .await
            .map_err(BrokerError::BackendUnreachable)?,
    )
    .map_err(BrokerError::BackendUnreachable)?;
    word_at(&raw, 0).map_err(BrokerError::BackendUnreachable)
}
fn validate_origin(
    origin: &str,
    rp_id: &str,
    allowed_origins: &[String],
) -> Result<(), BrokerError> {
    let url = reqwest::Url::parse(origin)
        .map_err(|error| BrokerError::BadRequest(format!("origin: {error}")))?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.origin().ascii_serialization() != origin
        || url.host_str() != Some(rp_id)
        || !(url.scheme() == "https" || (url.scheme() == "http" && local))
        || !allowed_origins.iter().any(|allowed| allowed == origin)
    {
        return Err(BrokerError::Forbidden(
            "origin must be an allowed browser origin and rp_id must equal its host".into(),
        ));
    }
    Ok(())
}
fn allowed_origins() -> Vec<String> {
    agentkeys_protocol::browser_origins::parse_browser_origins(
        &std::env::var(crate::env::BROKER_BROWSER_ORIGINS).unwrap_or_default(),
    )
}
fn enrollment_challenge(intent: &HostedSignerIntent) -> Result<[u8; 32], BrokerError> {
    let mut digest = Sha256::new();
    digest.update(b"agentkeys:hosted-signer-enrollment:v1:");
    digest.update(
        serde_json::to_vec(intent).map_err(|error| BrokerError::Internal(error.to_string()))?,
    );
    Ok(digest.finalize().into())
}
fn validate_intent(
    intent: &HostedSignerIntent,
    omni: &[u8; 32],
    account: &[u8; 20],
    chain_id: u64,
    nonce: &[u8; 32],
    current_time: u64,
    origins: &[String],
) -> Result<LiveSigner, BrokerError> {
    if word(&intent.operator_omni, "operator_omni")? != *omni
        || addr20(&intent.account, "account").map_err(BrokerError::BadRequest)? != *account
        || intent.chain_id != chain_id
        || word(&intent.operator_nonce, "operator_nonce")? != *nonce
    {
        return Err(BrokerError::Forbidden(
            "enrollment belongs to another operator, account, chain, or stale operator nonce"
                .into(),
        ));
    }
    if intent.expires_at <= current_time
        || intent.expires_at > current_time.saturating_add(HOSTED_SIGNER_TTL_SECONDS)
    {
        return Err(BrokerError::BadRequest(
            "enrollment expired or has an invalid lifetime; restart on the new browser".into(),
        ));
    }
    validate_origin(&intent.origin, &intent.rp_id, origins)?;
    word(&intent.device_key_hash, "device_key_hash")?;
    let public_key_x = word(&intent.public_key_x, "public_key_x")?;
    let public_key_y = word(&intent.public_key_y, "public_key_y")?;
    let mut encoded = vec![4];
    encoded.extend_from_slice(&public_key_x);
    encoded.extend_from_slice(&public_key_y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
        .map_err(|_| BrokerError::BadRequest("invalid P-256 public key".into()))?;
    Ok(LiveSigner {
        credential_hash: credential_hash(&intent.credential_id)?,
        pub_x: public_key_x,
        pub_y: public_key_y,
        rp_id_hash: Sha256::digest(intent.rp_id.as_bytes()).into(),
    })
}
fn validate_public_proofs(
    intent: &HostedSignerIntent,
    proof: &BrowserAssertion,
    device_proof: &str,
) -> Result<[u8; 32], BrokerError> {
    if proof.authenticator_data.len()
        + proof.client_data_json.len()
        + proof.signature.len()
        + device_proof.len()
        > super::hosted_signer_pending::MAX_PUBLIC_REQUEST_BYTES
    {
        return Err(BrokerError::BadRequest("browser proof is too large".into()));
    }
    if proof.credential_id != intent.credential_id {
        return Err(BrokerError::Forbidden(
            "proof credential does not match enrollment".into(),
        ));
    }
    let parts = decode_assertion_parts(proof).map_err(BrokerError::BadRequest)?;
    let client_data: serde_json::Value = serde_json::from_slice(&parts.client_data_json)
        .map_err(|error| BrokerError::BadRequest(format!("client data: {error}")))?;
    let challenge = enrollment_challenge(intent)?;
    if client_data.get("origin").and_then(|value| value.as_str()) != Some(&intent.origin)
        || client_data.get("type").and_then(|value| value.as_str()) != Some("webauthn.get")
        || client_data
            .get("challenge")
            .and_then(|value| value.as_str())
            != Some(&URL_SAFE_NO_PAD.encode(challenge))
        || client_data
            .get("crossOrigin")
            .and_then(|value| value.as_bool())
            == Some(true)
    {
        return Err(BrokerError::Forbidden(
            "new credential proof has the wrong origin, challenge, or context".into(),
        ));
    }
    let address = ecrecover_eip191(&challenge, device_proof)
        .map_err(|_| BrokerError::Forbidden("new device proof rejected".into()))?;
    let derived_hash =
        device_key_hash(&address).map_err(|error| BrokerError::BadRequest(error.to_string()))?;
    if word(&derived_hash, "derived device hash")?
        != word(&intent.device_key_hash, "device_key_hash")?
    {
        return Err(BrokerError::Forbidden(
            "device proof does not own the requested K10 binding".into(),
        ));
    }
    Ok(challenge)
}

struct RegistryDevice {
    operator: [u8; 32],
    actor: [u8; 32],
    signer: LiveSigner,
    tier: u8,
    roles: u8,
    registered: bool,
    revoked: bool,
}
async fn registry_device(
    state: &SharedState,
    rpc: &str,
    registry: &[u8; 20],
    hash: &[u8; 32],
) -> Result<RegistryDevice, BrokerError> {
    let data = format!("0x{}{}", selector("getDevice(bytes32)"), hex::encode(hash));
    let raw = decode_hex_result(
        &eth_call(&state.http, rpc, registry, &data)
            .await
            .map_err(BrokerError::BackendUnreachable)?,
    )
    .map_err(BrokerError::BackendUnreachable)?;
    let field = |index| word_at(&raw, index).map_err(BrokerError::BackendUnreachable);
    Ok(RegistryDevice {
        operator: field(0)?,
        actor: field(1)?,
        signer: LiveSigner {
            credential_hash: field(2)?,
            rp_id_hash: field(3)?,
            pub_x: field(4)?,
            pub_y: field(5)?,
        },
        tier: field(6)?[31],
        roles: field(7)?[31],
        registered: field(8)? != [0; 32],
        revoked: field(10)? != [0; 32],
    })
}
fn device_is_master(device: &RegistryDevice, omni: &[u8; 32], role: u8) -> bool {
    device.operator == *omni
        && device.actor == *omni
        && device.tier == 1
        && device.roles & role == role
        && device.registered
        && !device.revoked
}

pub async fn start(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<HostedSignerStartRequest>,
) -> Result<Json<HostedSignerChallenge>, BrokerError> {
    let omni = operator(&state, &headers).await?;
    let (config, _) = load_accept_config().map_err(BrokerError::BackendUnreachable)?;
    let account = current_account(&state, &config.rpc_url, &config.registry, &omni).await?;
    let nonce = operator_nonce(&state, &config.rpc_url, &config.registry, &omni).await?;
    let current_time = now()?;
    let intent = HostedSignerIntent {
        operator_omni: hex0x(&omni),
        account: hex0x(&account),
        chain_id: config.chain_id,
        credential_id: request.credential_id,
        public_key_x: request.public_key_x,
        public_key_y: request.public_key_y,
        origin: request.origin,
        rp_id: request.rp_id,
        device_key_hash: request.device_key_hash,
        operator_nonce: hex0x(&nonce),
        expires_at: current_time + HOSTED_SIGNER_TTL_SECONDS,
    };
    let signer = validate_intent(
        &intent,
        &omni,
        &account,
        config.chain_id,
        &nonce,
        current_time,
        &allowed_origins(),
    )?;
    if read_live_signer(
        &state.http,
        &config.rpc_url,
        &account,
        &signer.credential_hash,
    )
    .await?
    .is_some()
    {
        return Err(BrokerError::BadRequest(
            "credential is already enrolled".into(),
        ));
    }
    let device_hash = word(&intent.device_key_hash, "device_key_hash")?;
    if registry_device(&state, &config.rpc_url, &config.registry, &device_hash)
        .await?
        .registered
    {
        return Err(BrokerError::BadRequest(
            "device key has already been registered; use its existing enrollment".into(),
        ));
    }
    let recovery_challenge = additional_master_challenge(
        &omni,
        &device_hash,
        HOSTED_SIGNER_CAP_MINT_ROLE,
        config.chain_id,
        &nonce,
    );
    Ok(Json(HostedSignerChallenge {
        challenge: hex0x(&enrollment_challenge(&intent)?),
        intent,
        recovery_challenge: hex0x(&recovery_challenge),
        attesting_device_key_hash: hex0x(&master_device_key_hash(&omni)),
    }))
}

pub async fn prepare(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<HostedSignerApproval>,
) -> Result<Json<HostedSignerChallenge>, BrokerError> {
    super::hosted_signer_pending::check_size(&request).map_err(BrokerError::BadRequest)?;
    let omni = operator(&state, &headers).await?;
    let (config, _) = load_accept_config().map_err(BrokerError::BackendUnreachable)?;
    let account = current_account(&state, &config.rpc_url, &config.registry, &omni).await?;
    let nonce = operator_nonce(&state, &config.rpc_url, &config.registry, &omni).await?;
    let intent = request.enrollment.intent;
    let signer = validate_intent(
        &intent,
        &omni,
        &account,
        config.chain_id,
        &nonce,
        now()?,
        &allowed_origins(),
    )?;
    let challenge = validate_public_proofs(&intent, &request.proof, &request.device_proof)?;
    verify_assertion(
        &state.http,
        &config.rpc_url,
        &account,
        &challenge,
        &signer,
        &request.proof,
    )
    .await?;
    let recovery = additional_master_challenge(
        &omni,
        &word(&intent.device_key_hash, "device_key_hash")?,
        HOSTED_SIGNER_CAP_MINT_ROLE,
        config.chain_id,
        &nonce,
    );
    Ok(Json(HostedSignerChallenge {
        intent,
        challenge: hex0x(&challenge),
        recovery_challenge: hex0x(&recovery),
        attesting_device_key_hash: hex0x(&master_device_key_hash(&omni)),
    }))
}

pub async fn build(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<HostedSignerBuildRequest>,
) -> Result<Json<BuildAcceptResponse>, BrokerError> {
    let omni = operator(&state, &headers).await?;
    let (config, broker_key) = load_accept_config().map_err(BrokerError::BackendUnreachable)?;
    let account = current_account(&state, &config.rpc_url, &config.registry, &omni).await?;
    let operator_nonce = operator_nonce(&state, &config.rpc_url, &config.registry, &omni).await?;
    let current_time = now()?;
    let signer = validate_intent(
        &request.intent,
        &omni,
        &account,
        config.chain_id,
        &operator_nonce,
        current_time,
        &allowed_origins(),
    )?;
    let challenge = validate_public_proofs(&request.intent, &request.proof, &request.device_proof)?;
    verify_assertion(
        &state.http,
        &config.rpc_url,
        &account,
        &challenge,
        &signer,
        &request.proof,
    )
    .await?;
    if read_live_signer(
        &state.http,
        &config.rpc_url,
        &account,
        &signer.credential_hash,
    )
    .await?
    .is_some()
    {
        return Err(BrokerError::BadRequest(
            "credential is already enrolled".into(),
        ));
    }
    let device_hash = word(&request.intent.device_key_hash, "device_key_hash")?;
    if registry_device(&state, &config.rpc_url, &config.registry, &device_hash)
        .await?
        .registered
    {
        return Err(BrokerError::BadRequest(
            "device key is already registered".into(),
        ));
    }
    let attesting_hash = word(
        &request.recovery_assertion.attesting_device_key_hash,
        "attesting_device_key_hash",
    )?;
    let attesting =
        registry_device(&state, &config.rpc_url, &config.registry, &attesting_hash).await?;
    if !device_is_master(&attesting, &omni, 2) {
        return Err(BrokerError::Forbidden(
            "approval requires an active recovery device of this operator".into(),
        ));
    }
    let recovery_challenge = additional_master_challenge(
        &omni,
        &device_hash,
        HOSTED_SIGNER_CAP_MINT_ROLE,
        config.chain_id,
        &operator_nonce,
    );
    verify_assertion(
        &state.http,
        &config.rpc_url,
        &config.registry,
        &recovery_challenge,
        &attesting.signer,
        &request.recovery_assertion.assertion,
    )
    .await?;
    let parts = decode_assertion_parts(&request.recovery_assertion.assertion)
        .map_err(BrokerError::BadRequest)?;
    let nonce = call_entrypoint_nonce(&state.http, &config.rpc_url, &config.entry_point, &account)
        .await
        .map_err(BrokerError::BackendUnreachable)?;
    let register = AgentRegister {
        device_key_hash: device_hash,
        operator_omni: omni,
        actor_omni: omni,
        link_code_redemption: Vec::new(),
        agent_pop_sig: Vec::new(),
    };
    let grant = ScopeGrant {
        services: Vec::new(),
        read_only: true,
        max_per_call: 0,
        max_per_period: 0,
        max_total: 0,
        period_seconds: 0,
    };
    let params = AcceptUserOpParams {
        entry_point: config.entry_point,
        chain_id: config.chain_id,
        master_account: account,
        registry: config.registry,
        scope: config.scope,
        nonce,
        account_gas_limits: config.account_gas_limits,
        pre_verification_gas: config.pre_verification_gas,
        gas_fees: config.gas_fees,
        paymaster: config.paymaster,
        paymaster_verification_gas_limit: config.paymaster_verification_gas_limit,
        paymaster_post_op_gas_limit: config.paymaster_post_op_gas_limit,
        valid_until: request
            .intent
            .expires_at
            .min(current_time + SPONSOR_WINDOW_SECS),
        valid_after: 0,
        broker_signer: config.broker_signer,
        register: &register,
        grant: &grant,
    };
    let master = AdditionalMaster {
        device_key_hash: &device_hash,
        operator_omni: &omni,
        credential_hash: &signer.credential_hash,
        rp_id_hash: &signer.rp_id_hash,
        pub_x: &signer.pub_x,
        pub_y: &signer.pub_y,
        roles: HOSTED_SIGNER_CAP_MINT_ROLE,
        attesting_device_key_hash: &attesting_hash,
        authenticator_data: &parts.authenticator_data,
        client_data_json: &parts.client_data_json,
        challenge_location: parts.challenge_location,
        r: &parts.r,
        s: &parts.s,
    };
    let assembled = assemble_hosted_signer_userop(&params, &master, &broker_key)
        .map_err(|error| BrokerError::Internal(error.to_string()))?;
    Ok(Json(
        assembled.into_build_response(&config.entry_point, config.chain_id),
    ))
}

pub async fn status(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<HostedSignerStatusRequest>,
) -> Result<Json<HostedSignerStatus>, BrokerError> {
    let omni = operator(&state, &headers).await?;
    let (rpc, registry) = load_chain_read_config().map_err(BrokerError::BackendUnreachable)?;
    let account = current_account(&state, &rpc, &registry, &omni).await?;
    let credential_hash = credential_hash(&request.credential_id)?;
    let signer = match read_live_signer(&state.http, &rpc, &account, &credential_hash).await {
        Ok(signer) => signer,
        Err(BrokerError::Unauthorized(_)) => None,
        Err(error) => return Err(error),
    };
    let active = signer.is_some();
    let device = registry_device(
        &state,
        &rpc,
        &registry,
        &word(&request.device_key_hash, "device_key_hash")?,
    )
    .await?;
    let device_active = device_is_master(&device, &omni, HOSTED_SIGNER_CAP_MINT_ROLE)
        && device.signer.credential_hash == credential_hash
        && signer.is_some_and(|signer| {
            signer.pub_x == device.signer.pub_x
                && signer.pub_y == device.signer.pub_y
                && signer.rp_id_hash == device.signer.rp_id_hash
        });
    Ok(Json(HostedSignerStatus {
        account: hex0x(&account),
        credential_id_hash: hex0x(&credential_hash),
        active,
        device_active,
    }))
}

pub async fn publish(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(mut request): Json<HostedSignerApproval>,
) -> Result<Json<agentkeys_protocol::hosted_signer::HostedSignerRequest>, BrokerError> {
    let omni = operator(&state, &headers).await?;
    let Json(enrollment) = prepare(State(state.clone()), headers, Json(request.clone())).await?;
    request.enrollment = enrollment;
    state
        .pending_ceremonies
        .hosted_signers
        .publish(omni, request, now()?)
        .map(Json)
        .map_err(BrokerError::BadRequest)
}
pub async fn pending(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<agentkeys_protocol::hosted_signer::HostedSignerPending>, BrokerError> {
    let omni = operator(&state, &headers).await?;
    let (rpc, registry) = load_chain_read_config().map_err(BrokerError::BackendUnreachable)?;
    current_account(&state, &rpc, &registry, &omni).await?;
    let requests = state
        .pending_ceremonies
        .hosted_signers
        .pending(omni, now()?)
        .map_err(BrokerError::Internal)?;
    Ok(Json(
        agentkeys_protocol::hosted_signer::HostedSignerPending { requests },
    ))
}
pub async fn dismiss(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<agentkeys_protocol::hosted_signer::HostedSignerRequestId>,
) -> Result<Json<serde_json::Value>, BrokerError> {
    let omni = operator(&state, &headers).await?;
    state
        .pending_ceremonies
        .hosted_signers
        .dismiss(omni, &request.id, now()?)
        .map_err(BrokerError::BadRequest)?;
    Ok(Json(serde_json::json!({"ok":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::device_crypto::{eip191_sign, evm_address};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};

    fn fixture() -> (HostedSignerIntent, SigningKey, k256::ecdsa::SigningKey) {
        let credential = SigningKey::random(&mut rand_core::OsRng);
        let point = credential.verifying_key().to_encoded_point(false);
        let device = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let intent = HostedSignerIntent {
            operator_omni: hex0x(&[1; 32]),
            account: hex0x(&[2; 20]),
            chain_id: 42,
            credential_id: URL_SAFE_NO_PAD.encode(b"new-browser"),
            public_key_x: hex0x(point.x().unwrap()),
            public_key_y: hex0x(point.y().unwrap()),
            origin: "https://console.example.test".into(),
            rp_id: "console.example.test".into(),
            device_key_hash: device_key_hash(&evm_address(device.verifying_key())).unwrap(),
            operator_nonce: hex0x(&[3; 32]),
            expires_at: 1100,
        };
        (intent, credential, device)
    }
    fn proof(intent: &HostedSignerIntent, key: &SigningKey) -> BrowserAssertion {
        let challenge = enrollment_challenge(intent).unwrap();
        let mut auth = Sha256::digest(intent.rp_id.as_bytes()).to_vec();
        auth.extend_from_slice(&[5, 0, 0, 0, 1]);
        let client = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\"}}",
            URL_SAFE_NO_PAD.encode(challenge),
            intent.origin
        )
        .into_bytes();
        let signature: Signature =
            key.sign(&[auth.as_slice(), Sha256::digest(&client).as_slice()].concat());
        BrowserAssertion {
            authenticator_data: URL_SAFE_NO_PAD.encode(auth),
            client_data_json: URL_SAFE_NO_PAD.encode(client),
            signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            credential_id: intent.credential_id.clone(),
        }
    }
    #[test]
    fn rejects_cross_operator_account_chain_nonce_and_expiry() {
        let (intent, _, _) = fixture();
        let origins = vec![intent.origin.clone()];
        assert!(validate_intent(&intent, &[1; 32], &[2; 20], 42, &[3; 32], 1000, &origins).is_ok());
        for (omni, account, chain, nonce, time) in [
            ([4; 32], [2; 20], 42, [3; 32], 1000),
            ([1; 32], [4; 20], 42, [3; 32], 1000),
            ([1; 32], [2; 20], 43, [3; 32], 1000),
            ([1; 32], [2; 20], 42, [4; 32], 1000),
            ([1; 32], [2; 20], 42, [3; 32], 1100),
            ([1; 32], [2; 20], 42, [3; 32], 499),
        ] {
            assert!(
                validate_intent(&intent, &omni, &account, chain, &nonce, time, &origins).is_err()
            );
        }
    }
    #[test]
    fn public_intent_tampering_invalidates_the_proof_and_k10_must_match() {
        let (intent, key, device) = fixture();
        let assertion = proof(&intent, &key);
        let challenge = enrollment_challenge(&intent).unwrap();
        let device_proof = eip191_sign(&device, &challenge).unwrap();
        assert!(validate_public_proofs(&intent, &assertion, &device_proof).is_ok());
        let mut changed = intent.clone();
        changed.account = hex0x(&[7; 20]);
        assert!(validate_public_proofs(&changed, &assertion, &device_proof).is_err());
        let other = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        assert!(validate_public_proofs(
            &intent,
            &assertion,
            &eip191_sign(&other, &challenge).unwrap()
        )
        .is_err());
        let mut wrong = assertion.clone();
        wrong.credential_id = URL_SAFE_NO_PAD.encode(b"other");
        assert!(validate_public_proofs(&intent, &wrong, &device_proof).is_err());
    }
    #[test]
    fn exact_origin_rp_binding_requires_the_configured_secure_origin() {
        let origins = vec!["https://console.example.test".to_string()];
        assert!(validate_origin(&origins[0], "console.example.test", &origins).is_ok());
        for (origin, rp) in [
            ("https://console.example.test", "example.test"),
            ("https://evil.example.test", "evil.example.test"),
            ("http://console.example.test", "console.example.test"),
            ("https://console.example.test/path", "console.example.test"),
        ] {
            assert!(validate_origin(origin, rp, &origins).is_err());
        }
    }
    #[test]
    fn recovery_device_is_operator_bound_active_master_with_recovery_role() {
        let (intent, _, _) = fixture();
        let signer = validate_intent(
            &intent,
            &[1; 32],
            &[2; 20],
            42,
            &[3; 32],
            1000,
            std::slice::from_ref(&intent.origin),
        )
        .unwrap();
        let mut device = RegistryDevice {
            operator: [1; 32],
            actor: [1; 32],
            signer,
            tier: 1,
            roles: 3,
            registered: true,
            revoked: false,
        };
        assert!(device_is_master(&device, &[1; 32], 2));
        assert!(!device_is_master(&device, &[4; 32], 2));
        device.roles = 1;
        assert!(!device_is_master(&device, &[1; 32], 2));
        device.roles = 3;
        device.revoked = true;
        assert!(!device_is_master(&device, &[1; 32], 2));
        device.revoked = false;
        device.tier = 3;
        assert!(!device_is_master(&device, &[1; 32], 2));
    }
}
