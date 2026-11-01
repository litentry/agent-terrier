use crate::{
    envelope,
    errors::{err_400, err_403, err_500, err_502, ApiError},
    state::SharedWorkerState,
    verify::{self, CapOp, CapToken, DataClass},
};
use agentkeys_core::object_store::ObjectError;

pub async fn verify_cap(
    state: &SharedWorkerState,
    cap: &CapToken,
    expected_op: CapOp,
    data_class: DataClass,
) -> Result<(), ApiError> {
    verify_authority(
        &state.config.authority,
        &state.http,
        cap,
        expected_op,
        data_class,
    )
    .await
}

pub async fn verify_authority(
    authority: &agentkeys_core::capability_verify::AuthorityConfig,
    http: &reqwest::Client,
    cap: &CapToken,
    expected_op: CapOp,
    data_class: DataClass,
) -> Result<(), ApiError> {
    verify::verify_signature(&authority.broker_public_key, cap)
        .map_err(|e| err_403(e.to_string(), "broker_sig_invalid"))?;
    verify::enforce_client_pop(cap).map_err(|e| err_403(e.to_string(), "cap_pop_invalid"))?;
    verify::check_op(cap, expected_op).map_err(|e| err_403(e.to_string(), "cap_op_mismatch"))?;
    verify::check_data_class(cap, data_class)
        .map_err(|e| err_403(e.to_string(), "cap_data_class_mismatch"))?;
    verify::check_freshness(cap).map_err(|e| err_403(e.to_string(), "cap_freshness_failed"))?;
    verify::check_chain_device(http, &authority.rpc_url, &authority.registry, cap)
        .await
        .map_err(|e| match e {
            verify::VerifyError::DeviceInactive => err_403(e.to_string(), "device_inactive"),
            verify::VerifyError::DeviceMismatch { .. } => {
                err_403(e.to_string(), "device_binding_mismatch")
            }
            verify::VerifyError::DeviceRoleMissing { .. } => {
                err_403(e.to_string(), "device_role_missing")
            }
            _ => err_502(e.to_string(), "chain_rpc"),
        })?;
    verify::check_chain_scope(http, &authority.rpc_url, &authority.scope, cap)
        .await
        .map_err(|e| match e {
            verify::VerifyError::NotInScope => err_403(e.to_string(), "service_not_in_scope"),
            _ => err_502(e.to_string(), "chain_rpc"),
        })?;
    verify::check_chain_k3_epoch(http, &authority.rpc_url, &authority.epoch, cap)
        .await
        .map_err(|e| match e {
            verify::VerifyError::K3Mismatch { .. } => err_403(e.to_string(), "k3_epoch_mismatch"),
            _ => err_502(e.to_string(), "chain_rpc"),
        })?;
    Ok(())
}

pub fn storage_error(error: ObjectError) -> ApiError {
    use crate::errors::{err_404, err_409};
    match error {
        ObjectError::Denied => err_403(error.to_string(), "storage_denied"),
        ObjectError::NotFound => err_404(
            error.to_string(),
            agentkeys_protocol::object_store::OBJECT_NOT_FOUND,
        ),
        ObjectError::Conflict => err_409(
            error.to_string(),
            agentkeys_protocol::object_store::OBJECT_REVISION_CONFLICT,
        ),
        ObjectError::InvalidRequest => err_400(error.to_string(), "object_request_invalid"),
        ObjectError::Unavailable | ObjectError::InvalidResponse => {
            err_502(error.to_string(), "storage_unavailable")
        }
    }
}

pub fn store_bytes(
    cap: &CapToken,
    plaintext_b64: Option<&str>,
    envelope_b64: Option<&str>,
    development_key: Option<&str>,
) -> Result<Vec<u8>, ApiError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    match (envelope_b64, plaintext_b64) {
        (Some(_), Some(_)) => Err(err_400(
            "exactly one of envelope_b64 / plaintext_b64 (both given)",
            "store_mode_ambiguous",
        )),
        (None, None) => Err(err_400(
            "exactly one of envelope_b64 / plaintext_b64 (neither given)",
            "store_mode_missing",
        )),
        (Some(env_b64), None) => {
            let bytes = STANDARD
                .decode(env_b64)
                .map_err(|e| err_400(e.to_string(), "envelope_b64_decode"))?;
            match envelope::version(&bytes) {
                Some(envelope::ENVELOPE_VERSION_V3) => Ok(bytes),
                Some(v) => Err(err_400(
                    format!("envelope_b64 must be a v3 envelope (got version 0x{v:02x})"),
                    "envelope_not_v3",
                )),
                None => Err(err_400(
                    format!(
                        "envelope_b64 too short to be an envelope ({} bytes)",
                        bytes.len()
                    ),
                    "envelope_truncated",
                )),
            }
        }
        (None, Some(pt_b64)) => {
            let kek_hex_stage1 = development_key.ok_or_else(|| {
                err_403(
                    "plaintext writes require an explicit development encryption key",
                    "plaintext_put_disabled",
                )
            })?;
            let plaintext = STANDARD
                .decode(pt_b64)
                .map_err(|e| err_400(e.to_string(), "plaintext_b64_decode"))?;
            let aad = envelope::aad(
                &cap.payload.operator_omni,
                &cap.payload.actor_omni,
                &cap.payload.service,
                cap.payload.k3_epoch,
            );
            envelope::encrypt(kek_hex_stage1, &plaintext, &aad)
                .map_err(|e| err_500(e.to_string(), "envelope_encrypt"))
        }
    }
}

pub async fn delete_prefix(
    state: &SharedWorkerState,
    cap: &CapToken,
    prefix: &str,
) -> Result<usize, ApiError> {
    let mut deleted = 0;
    let mut cursor = None;
    loop {
        let page = state
            .storage
            .list(cap, prefix, cursor.as_deref())
            .await
            .map_err(storage_error)?;
        for key in &page.keys {
            state
                .storage
                .delete(cap, key, None)
                .await
                .map_err(storage_error)?;
            deleted += 1;
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(deleted)
}
