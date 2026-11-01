//! Runtime lifecycle hooks for pairing, resolve, confirmed revocation and updates.
//! Authorization remains with the caller; runtime failures are returned explicitly.

use agentkeys_core::audit::{
    calldata::decode_calldata, envelope_for, AuditClient, AuditEnvelope, AuditOpKind, AuditResult,
    SandboxSpawnBody, SandboxTeardownBody,
};
use agentkeys_core::erc4337::decode_execute_batch;
use serde_json::json;

use crate::sandbox_backend::SandboxBackend;
use crate::state::SharedState;

/// The runtime outcome exposed to a device.
pub struct SandboxProvision {
    pub agent_url: Option<String>,
    pub sandbox_id: Option<String>,
    pub status: Option<String>,
    pub error: Option<String>,
}

impl SandboxProvision {
    /// The `"sandbox"` object attached to poll/resolve/spawn responses.
    /// `agent_url` is the delegate's bridge base — the daemon's spawn-time
    /// preset distribution derives its target from THIS, never from a
    /// hand-set laptop env (worker-URLs-are-derived rule).
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "sandbox_id": self.sandbox_id,
            "status": self.status,
            "error": self.error,
            "agent_url": self.agent_url,
        })
    }

    /// A caller stopped waiting while the ensure runs on (a create or a
    /// cold-start adopt in flight): no instance id yet, `Starting`, and the
    /// backend's static URL when it has one.
    pub fn still_starting(state: &SharedState) -> Option<Self> {
        let backend = state.sandbox.as_ref()?;
        Some(Self {
            agent_url: backend.static_agent_url(),
            sandbox_id: None,
            status: Some("Starting".to_string()),
            error: None,
        })
    }
}

/// Model-access provisioning result, evaluated only when a runtime is created.
pub struct GateProvision {
    pub envs: Vec<(String, String)>,
    /// `provisioned` | `not-configured` | `misconfigured` | `failed`.
    pub status: String,
    pub error: Option<String>,
}

/// Provision a per-delegate gate relay key and return the sandbox LLM envs +
/// status. Pure policy, no side effects beyond the gate call; the caller
/// decides eager (ceremony) vs lazy-on-create (resolve/poll).
///
/// `operator_omni_0x` MUST be the canonical `0x`+lowercase-hex operator omni so
/// the gate aggregates a delegate's budget under the SAME user across the
/// ceremony spawn and any later cold respawn (a case mismatch would fork the
/// rollup). `label` is cosmetic (gate rollup keys on `device_key_hash`); the
/// resolve path passes the durable spawn-context label when one exists (#546),
/// else `""`.
pub async fn provision_delegate_envs(
    http: &reqwest::Client,
    operator_omni_0x: &str,
    actor_omni: &str,
    device_key_hash: &str,
    label: &str,
) -> GateProvision {
    match crate::gate_admin::load_gate_admin_config() {
        None => GateProvision {
            envs: Vec::new(),
            status: "not-configured".into(),
            error: None,
        },
        Some(Err(e)) => {
            tracing::error!(error = %e, "gate admin MISCONFIGURED");
            GateProvision {
                envs: Vec::new(),
                status: "misconfigured".into(),
                error: Some(e),
            }
        }
        Some(Ok(cfg)) => match crate::gate_admin::provision_delegate(
            http,
            &cfg,
            operator_omni_0x,
            actor_omni,
            device_key_hash,
            label,
        )
        .await
        {
            Ok(key) => GateProvision {
                envs: agentkeys_protocol::model_runtime::relay_environment(
                    &cfg.turn_url,
                    key.secret,
                    &cfg.model_id,
                ),
                status: "provisioned".into(),
                error: None,
            },
            Err(e) => {
                tracing::error!(
                    device_key_hash = %device_key_hash,
                    error = %e,
                    "gate provisioning failed; runtime creation will be refused"
                );
                GateProvision {
                    envs: Vec::new(),
                    status: "failed".into(),
                    error: Some(e),
                }
            }
        },
    }
}

/// Shared identity and service configuration for initial creation and restart.
#[allow(clippy::too_many_arguments)] // the ONE env-assembly owner — a param per env source
pub(crate) fn delegate_identity_envs(
    actor_omni: &str,
    operator_omni: &str,
    k10_secret_hex: Option<&str>,
    session_jwt: Option<&str>,
    chat_channel_id: &str,
    service_environment: &[(String, String)],
    mgmt_token: Option<&str>,
    memory_ns: Option<&str>,
    bridge_token: Option<&str>,
) -> Vec<(String, String)> {
    use agentkeys_protocol::sandbox_env as env_names;
    let norm0x = |o: &str| format!("0x{}", crate::handlers::accept::norm_omni(o));
    let mut envs = vec![
        (env_names::ACTOR_OMNI.to_string(), norm0x(actor_omni)),
        (env_names::OPERATOR_OMNI.to_string(), norm0x(operator_omni)),
    ];
    // #577 — the sandbox-management bearer: enables the in-sandbox daemon's
    // session export/import surface for the one-click image update. Derived,
    // never stored (see `sandbox_mgmt_token`).
    if let Some(token) = mgmt_token.filter(|t| !t.trim().is_empty()) {
        envs.push((env_names::MGMT_TOKEN.to_string(), token.to_string()));
    }
    // #715 — the in-pod bearer: gates the bridge's chat/context routes and the
    // daemon's self surface, presented by every in-pod client. Derived like
    // the mgmt token (see `sandbox_bridge_token`); a sandbox without it is
    // fail-closed on both surfaces, never open.
    if let Some(token) = bridge_token.filter(|t| !t.trim().is_empty()) {
        envs.push((env_names::BRIDGE_TOKEN.to_string(), token.to_string()));
    }
    if let Some(secret) = k10_secret_hex.filter(|s| !s.trim().is_empty()) {
        envs.push((env_names::DEVICE_KEY_HEX.to_string(), secret.to_string()));
    }
    // #552 signer custody: the broker-minted J1 is the sandbox's credential
    // toward the signer's device-domain endpoints (rotated by resolve).
    // Exactly one of DEVICE_KEY_HEX / SESSION_JWT rides per spawn.
    if let Some(jwt) = session_jwt.filter(|j| !j.trim().is_empty()) {
        envs.push((env_names::SESSION_JWT.to_string(), jwt.trim().to_string()));
    }
    if !chat_channel_id.is_empty() {
        envs.push((
            env_names::CHAT_CHANNEL_ID.to_string(),
            chat_channel_id.to_string(),
        ));
    }
    envs.extend_from_slice(service_environment);
    // #594 — the delegate's own memory namespace, for the in-sandbox
    // checkpoint loop (OPTIONAL: absent, the daemon derives it from the
    // `opchat-<label>` channel id; pre-#594 rows have an empty ns).
    if let Some(ns) = memory_ns.filter(|n| !n.trim().is_empty()) {
        envs.push((env_names::MEMORY_NS.to_string(), ns.trim().to_string()));
    }
    envs
}

/// #660 stage 1 — the app-runtime env set a CREATE injects beside the
/// identity envs, from the durable spawn context (#663/#665/#666/#669): the
/// template id, the bound feeds, the availability policy, the mirror's
/// namespace list and the household tz offset. Every value is OPTIONAL to the
/// consumer (a role-preset delegate injects none of them) and provisioning
/// data only — the chain already grants every feed / namespace named here.
pub(crate) fn app_runtime_envs(ctx: &crate::storage::SpawnContext) -> Vec<(String, String)> {
    use agentkeys_protocol::sandbox_env as env_names;
    let mut envs = Vec::new();
    if !ctx.preset_id.trim().is_empty() {
        envs.push((env_names::APP_TEMPLATE.to_string(), ctx.preset_id.clone()));
    }
    if !ctx.bound_channels_json.trim().is_empty() {
        envs.push((
            env_names::BOUND_CHANNELS.to_string(),
            ctx.bound_channels_json.clone(),
        ));
    }
    if !ctx.availability.trim().is_empty() {
        envs.push((
            env_names::APP_AVAILABILITY.to_string(),
            ctx.availability.clone(),
        ));
    }
    if !ctx.memory_namespaces.trim().is_empty() {
        envs.push((
            env_names::MEMORY_NAMESPACES.to_string(),
            ctx.memory_namespaces.clone(),
        ));
    }
    if ctx.tz_offset_minutes != 0 {
        envs.push((
            env_names::APP_TZ_OFFSET_MINUTES.to_string(),
            ctx.tz_offset_minutes.to_string(),
        ));
    }
    envs
}

/// #577 — the per-delegate sandbox-management bearer: DERIVED from the
/// broker's session signing key + the delegate's `device_key_hash`, so the
/// broker can re-compute it at any later update call and NOTHING new sits at
/// rest (D2). Injected as `AGENTKEYS_SANDBOX_MGMT_TOKEN` at every create; the
/// in-sandbox daemon string-compares it as the bearer gating its session
/// export/import surface. keccak256 is a sponge — no length-extension issue
/// with the `secret || payload` shape. Rotating the broker session keypair
/// orphans PRE-rotation instances' tokens (their export then 401s and the
/// update proceeds without a session hand-off, surfaced — never fatal).
pub(crate) fn sandbox_mgmt_token(
    session_keypair: &crate::jwt::session::SessionKeypair,
    device_key_hash: &str,
) -> String {
    derived_sandbox_token(
        session_keypair,
        device_key_hash,
        b"agentkeys-sandbox-mgmt-v1:",
        "smt1",
    )
}

/// #715 — the per-delegate IN-POD bearer (`AGENTKEYS_BRIDGE_TOKEN`): the same
/// derivation as the mgmt token under a DISTINCT domain string, so the two
/// surfaces (runtime-home export/import vs chat/context) never share a
/// credential — a device or console that could ever hold the chat bearer must
/// not thereby hold the home snapshot. Re-derived by the broker at every
/// `/v1/agent/bridge` call; nothing at rest (D2).
pub(crate) fn sandbox_bridge_token(
    session_keypair: &crate::jwt::session::SessionKeypair,
    device_key_hash: &str,
) -> String {
    derived_sandbox_token(
        session_keypair,
        device_key_hash,
        b"agentkeys-sandbox-bridge-v1:",
        "sbt1",
    )
}

/// keccak256(session private key || domain || normalized device_key_hash):
/// deterministic per (broker key, delegate), `0x`/case-insensitive on the hash.
/// keccak256 is a sponge — no length-extension issue with the `secret ||
/// payload` shape. Rotating the broker session keypair orphans PRE-rotation
/// instances' tokens (surfaced — never fatal — by the callers).
fn derived_sandbox_token(
    session_keypair: &crate::jwt::session::SessionKeypair,
    device_key_hash: &str,
    domain: &[u8],
    prefix: &str,
) -> String {
    let norm = device_key_hash
        .trim()
        .trim_start_matches("0x")
        .to_lowercase();
    let mut buf = Vec::new();
    buf.extend_from_slice(session_keypair.private_key_pem.as_bytes());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(norm.as_bytes());
    format!(
        "{prefix}_{}",
        hex::encode(agentkeys_core::device_crypto::keccak256(&buf))
    )
}

/// #552 — mint the J1_agent a signer-custodied delegate sandbox boots with
/// (and that every re-create refreshes): actor = the delegate, parent = the
/// operator, `device_pubkey` = the signer-derived K10 address (what the
/// signer's #513-style chain gate re-checks). Loud None on failure — the
/// create then boots chat-silent with the consumer-side partial-env warn.
pub(crate) fn mint_delegate_session_jwt(
    state: &SharedState,
    actor_omni: &str,
    operator_omni: &str,
    derivation_path: &str,
    k10_address: &str,
) -> Option<String> {
    match crate::jwt::issue::mint_agent_session_jwt(
        &state.session_keypair,
        &state.config.oidc_issuer,
        actor_omni,
        operator_omni,
        derivation_path,
        k10_address,
        crate::handlers::agent::delegate_session_jwt_ttl_seconds(),
    ) {
        Ok(jwt) => Some(jwt),
        Err(e) => {
            tracing::warn!(
                actor_omni = %actor_omni,
                error = ?e,
                "#552 delegate J1 mint FAILED — the sandbox boots without a signer credential \
                 (chat loop will warn partial-env, not start)"
            );
            None
        }
    }
}

pub(crate) fn delegate_service_environment(
    lookup: impl Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    use agentkeys_protocol::sandbox_env;
    agentkeys_runtime::managed_agent::SERVICE_ENVIRONMENT
        .iter()
        .filter(|(service, _)| *service != "model")
        .filter_map(|(_, destination)| {
            let source = match *destination {
                sandbox_env::BROKER_URL => "BROKER_OIDC_ISSUER",
                sandbox_env::CHANNEL_WORKER_URL => "AGENTKEYS_WORKER_CHANNEL_URL",
                _ => destination,
            };
            lookup(source)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .map(|value| ((*destination).to_owned(), value))
        })
        .collect()
}

/// Ensure the delegate's sandbox exists (spawning it if needed) + emit the
/// `SandboxSpawn` envelope on an actual create. `None` = lifecycle disabled
/// on this host (no sandbox config) — callers return `agent_url: null` and
/// the device falls back to its compiled `AGENT_BASE_URL` (#367 semantics).
///
/// This is the resolve/poll re-spawn path (a delegate whose runtime must be
/// (re)created — legacy create-on-pair, or a future wake-on-event cold start).
/// #543: a create here is now METERED — the gate relay key is minted ON CREATE
/// via [`provision_delegate_envs`]; a configured relay must provision successfully.
/// Lazy by design: a
/// REUSED live instance never triggers a provision, so its relay key is never
/// rotated out from under it (the #543 correctness point).
///
/// #546: a create here injects the SAME identity + chat env set the ceremony
/// injects, reconstructed from the durable spawn-context row — a re-created
/// sandbox (runtime loss or wake cold-start) comes back with
/// its chat loop, not chat-silent. A delegate without a row (device-era
/// binding, §10.2-paired agent whose K10 never touched the broker, pre-#546
/// spawn) keeps today's env-less create.
pub async fn ensure_for_delegate(
    state: &SharedState,
    device_key_hash: &str,
    actor_omni: &str,
    operator_omni: &str,
) -> Option<SandboxProvision> {
    ensure_for_delegate_extra(state, device_key_hash, actor_omni, operator_omni, &[]).await
}

/// [`ensure_for_delegate`] with create-only extras appended to the identity +
/// app-runtime env set — the #669 wake's replay window
/// (`AGENTKEYS_WAKE_SINCE_MS`), which a REUSED instance never sees (its env is
/// fixed at create; the reuse path delivers through the running loop).
pub async fn ensure_for_delegate_extra(
    state: &SharedState,
    device_key_hash: &str,
    actor_omni: &str,
    operator_omni: &str,
    extra_envs: &[(String, String)],
) -> Option<SandboxProvision> {
    let ctx = match state.spawn_context_store.get(device_key_hash) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                device_key_hash = %device_key_hash,
                error = %e,
                "#546 spawn-context read FAILED — a create on this ensure will be chat-silent"
            );
            None
        }
    };
    let (base_envs, gate_label) = match &ctx {
        Some(c) => {
            let service_environment = delegate_service_environment(|name| std::env::var(name).ok());
            // Legacy rows carry the K10 secret; #552 signer-custodied rows
            // carry only the derived address — mint a FRESH J1 per create so
            // a re-created sandbox always boots with a live signer credential.
            let session_jwt = if c.k10_secret_hex.is_empty() && !c.k10_address.is_empty() {
                mint_delegate_session_jwt(
                    state,
                    actor_omni,
                    operator_omni,
                    "//respawned",
                    &c.k10_address,
                )
            } else {
                None
            };
            let mut envs = delegate_identity_envs(
                actor_omni,
                operator_omni,
                Some(&c.k10_secret_hex),
                session_jwt.as_deref(),
                &c.chat_channel_id,
                &service_environment,
                Some(&sandbox_mgmt_token(&state.session_keypair, device_key_hash)),
                Some(&c.memory_ns),
                Some(&sandbox_bridge_token(
                    &state.session_keypair,
                    device_key_hash,
                )),
            );
            // #660 — the app-runtime set rides every re-create too (a
            // re-created Chef must poll its WeChat feed, not just opchat).
            envs.extend(app_runtime_envs(c));
            envs.extend(extra_envs.iter().cloned());
            (envs, c.label.clone())
        }
        None => (Vec::new(), String::new()),
    };
    // Owned captures so the create-time closure is `'static`. The gate user_omni
    // is canonicalized to `0x`+lowercase-hex so a cold respawn aggregates under
    // the SAME operator budget the #427 ceremony spawn used (§15.3a).
    let http = state.http.clone();
    let op = format!("0x{}", crate::handlers::accept::norm_omni(operator_omni));
    let actor = actor_omni.to_string();
    let dkh = device_key_hash.to_string();
    let on_create: crate::sandbox_backend::CreateEnvProvider = Box::new(move || {
        Box::pin(async move {
            provision_delegate_envs(&http, &op, &actor, &dkh, &gate_label)
                .await
                .envs
        })
    });
    ensure_for_delegate_with_envs(
        state,
        device_key_hash,
        actor_omni,
        operator_omni,
        &base_envs,
        on_create,
    )
    .await
}

/// #427 spawn-ceremony variant: the same ensure with the delegate identity +
/// (eagerly-provisioned) gate-relay envs in `base_envs`; `on_create` yields any
/// create-only envs (the ceremony passes [`crate::sandbox_backend::no_create_envs`]
/// since it provisions eagerly, resolve/poll pass the lazy gate provider).
pub async fn ensure_for_delegate_with_envs(
    state: &SharedState,
    device_key_hash: &str,
    actor_omni: &str,
    operator_omni: &str,
    base_envs: &[(String, String)],
    on_create: crate::sandbox_backend::CreateEnvProvider,
) -> Option<SandboxProvision> {
    let backend = state.sandbox.clone()?;
    let static_agent_url = backend.static_agent_url();
    let ensured = crate::sandbox_backend::run_detached(ensure_on_backend(
        backend,
        device_key_hash.to_string(),
        actor_omni.to_string(),
        operator_omni.to_string(),
        base_envs.to_vec(),
        on_create,
    ))
    .await;
    Some(ensured.unwrap_or_else(|e| SandboxProvision {
        agent_url: static_agent_url,
        sandbox_id: None,
        status: None,
        error: Some(format!("{e:#}")),
    }))
}

/// The ensure itself, on owned inputs so it runs on its own task
/// ([`crate::sandbox_backend::run_detached`]): the create, its audit emit and
/// its log line finish even when the request that started them is gone.
async fn ensure_on_backend(
    backend: std::sync::Arc<SandboxBackend>,
    device_key_hash: String,
    actor_omni: String,
    operator_omni: String,
    base_envs: Vec<(String, String)>,
    on_create: crate::sandbox_backend::CreateEnvProvider,
) -> SandboxProvision {
    let device_key_hash = device_key_hash.as_str();
    let (actor_omni, operator_omni) = (actor_omni.as_str(), operator_omni.as_str());
    let backend = backend.as_ref();
    match backend
        .ensure_for_delegate_with_envs(device_key_hash, actor_omni, &base_envs, on_create)
        .await
    {
        Ok(outcome) => {
            tracing::info!(
                device_key_hash = %device_key_hash,
                backend = %backend.kind(),
                sandbox_id = %outcome.sandbox_id,
                status = %outcome.status,
                created = outcome.created,
                "#377/#440 delegate sandbox ensured"
            );
            if outcome.created {
                emit_spawn(
                    backend,
                    device_key_hash,
                    &outcome.sandbox_id,
                    actor_omni,
                    operator_omni,
                )
                .await;
            }
            SandboxProvision {
                agent_url: outcome.agent_url.or_else(|| backend.static_agent_url()),
                sandbox_id: Some(outcome.sandbox_id),
                status: Some(outcome.status),
                error: None,
            }
        }
        Err(e) => {
            // Surfaced, never swallowed: the device still gets its JWT (the
            // handler's main job) plus the exact spawn failure to report.
            // `{:#}` prints the WHOLE anyhow chain — a bare Display shows only
            // the top context ("ecs RunTask failed") and hides the AWS error
            // underneath (the #440 missing-TagResource hunt).
            let chain = format!("{e:#}");
            tracing::warn!(
                device_key_hash = %device_key_hash,
                backend = %backend.kind(),
                error = %chain,
                "#377/#440 delegate sandbox ensure FAILED — device keeps its session; talk path may 500 no_ready_instance"
            );
            SandboxProvision {
                agent_url: backend.static_agent_url(),
                sandbox_id: None,
                status: None,
                error: Some(chain),
            }
        }
    }
}

/// The `device_key_hash` argument of every `revokeAgentDevice` in a confirmed
/// `executeBatch` calldata. Pure — same decode chain as the #97 audit emit
/// (on-chain truth, never client-claimed fields); undecodable calldata or
/// non-revoke batches yield an empty list.
pub fn revoked_device_key_hashes(call_data: &[u8]) -> Vec<String> {
    let Ok(calls) = decode_execute_batch(call_data) else {
        return Vec::new();
    };
    calls
        .iter()
        .filter_map(|call| {
            let decoded = decode_calldata(&call.calldata).ok()?;
            if decoded.contract == "SidecarRegistry" && decoded.function == "revokeAgentDevice" {
                decoded.args.first()?.value.as_str().map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

/// Report cleanup separately from the already confirmed chain revocation.
pub async fn teardown_for_confirmed_batch(
    state: &SharedState,
    session_omni: [u8; 32],
    call_data: &[u8],
) -> Vec<agentkeys_protocol::RuntimeTeardownOutcome> {
    let revoked = revoked_device_key_hashes(call_data);
    let mut outcomes = Vec::new();
    for device_key_hash in revoked {
        let mut outcome = agentkeys_protocol::RuntimeTeardownOutcome {
            device_key_hash: device_key_hash.clone(),
            context_removed: false,
            runtime_stopped: false,
            error: None,
        };
        match state.spawn_context_store.delete(&device_key_hash) {
            Ok(true) => tracing::info!(
                device_key_hash = %device_key_hash,
                "#546 spawn context deleted for the revoked binding"
            ),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%device_key_hash, %error, "revoked spawn-context cleanup failed");
                outcome.error = Some("spawn_context_delete_failed".into());
            }
        }
        outcome.context_removed = outcome.error.is_none();
        let Some(backend) = state.sandbox.as_ref() else {
            outcome.error = Some("runtime_not_configured".into());
            outcomes.push(outcome);
            continue;
        };
        match backend.kill_for_device(&device_key_hash).await {
            Ok(killed) if killed.is_empty() => {
                outcome.runtime_stopped = true;
                tracing::info!(
                    device_key_hash = %device_key_hash,
                    "#377 unpair teardown: no live sandbox for the revoked device (no-op)"
                );
            }
            Ok(killed) => {
                outcome.runtime_stopped = true;
                for sandbox_id in killed {
                    tracing::info!(
                        device_key_hash = %device_key_hash,
                        sandbox_id = %sandbox_id,
                        "#377 unpair teardown: sandbox killed"
                    );
                    // Mirrors the DeviceRevoke envelope: the master (the
                    // verified session operator) performed the unpair, so
                    // actor = operator = session omni; the device is in the body.
                    let env = envelope_for(
                        session_omni,
                        session_omni,
                        AuditOpKind::SandboxTeardown,
                        SandboxTeardownBody {
                            device_key_hash: device_key_hash.clone(),
                            sandbox_id,
                            reason: "unpair".into(),
                        },
                        AuditResult::Success,
                        None,
                        None,
                    );
                    append_best_effort(env).await;
                }
            }
            Err(e) => {
                outcome.error = Some("runtime_stop_failed".into());
                tracing::warn!(
                    device_key_hash = %device_key_hash,
                    error = %format!("{e:#}"),
                    "unpair teardown failed; revoked binding blocks authorization and respawn"
                );
            }
        }
        outcomes.push(outcome);
    }
    outcomes
}

async fn emit_spawn(
    backend: &SandboxBackend,
    device_key_hash: &str,
    sandbox_id: &str,
    actor_omni: &str,
    operator_omni: &str,
) {
    let (Some(actor), Some(operator)) = (omni32(actor_omni), omni32(operator_omni)) else {
        tracing::warn!(
            actor_omni = %actor_omni,
            operator_omni = %operator_omni,
            "sandbox.spawn audit emit skipped: omni not 32-byte hex"
        );
        return;
    };
    let env = envelope_for(
        actor,
        operator,
        AuditOpKind::SandboxSpawn,
        SandboxSpawnBody {
            device_key_hash: device_key_hash.to_string(),
            sandbox_id: sandbox_id.to_string(),
            // The legacy wire name records the runtime namespace.
            function_id: backend.runtime_ref(),
        },
        AuditResult::Success,
        None,
        None,
    );
    append_best_effort(env).await;
}

/// Same best-effort posture + worker URL resolution as
/// [`audit_emit`](crate::handlers::audit_emit): the lifecycle event already
/// happened, so an append failure WARNs and never fails the caller. Shared
/// with the #577 update handler (its teardown emit mirrors the unpair one).
pub(crate) async fn append_best_effort(
    env: Result<AuditEnvelope, agentkeys_core::audit::AuditError>,
) {
    let env = match env {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "sandbox audit envelope build failed — event NOT in the audit feed");
            return;
        }
    };
    let url = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
        .unwrap_or_else(|_| crate::handlers::audit_emit::DEFAULT_AUDIT_WORKER_URL.to_string());
    if let Err(e) = AuditClient::new(url).append(&env).await {
        tracing::warn!(
            op_kind = env.op_kind,
            error = %e,
            "audit: durable append FAILED for a sandbox lifecycle event (best-effort) — event NOT in the audit feed"
        );
    }
}

/// Parse a `0x`-prefixed (or bare) 64-hex omni into its 32 raw bytes.
fn omni32(hex_str: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(hex_str.trim().trim_start_matches("0x")).ok()?;
    raw.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_core::erc4337::{revoke_batch_calldata, scope_batch_calldata, ScopeGrant};

    fn b32(x: u8) -> [u8; 32] {
        [x; 32]
    }
    fn addr(last: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = last;
        a
    }

    /// A #260 fleet revoke (N devices, one batch) yields every device hash,
    /// in order — the teardown set mirrors the DeviceRevoke envelope set.
    #[test]
    fn revoke_batch_yields_all_device_hashes() {
        let batch = revoke_batch_calldata(&addr(0xa1), &[b32(0x11), b32(0x12)]);
        assert_eq!(
            revoked_device_key_hashes(&batch),
            vec![
                format!("0x{}", "11".repeat(32)),
                format!("0x{}", "12".repeat(32)),
            ]
        );
    }

    /// Non-revoke batches (e.g. a scope re-grant) and garbage calldata tear
    /// nothing down.
    #[test]
    fn non_revoke_batches_yield_nothing() {
        let grant = ScopeGrant {
            services: vec![b32(0xc1)],
            read_only: true,
            max_per_call: 1,
            max_per_period: 1,
            max_total: 1,
            period_seconds: 60,
        };
        let batch = scope_batch_calldata(&addr(0xa2), &b32(0x22), &b32(0x33), &grant);
        assert!(revoked_device_key_hashes(&batch).is_empty());
        assert!(revoked_device_key_hashes(&[0xde, 0xad]).is_empty());
        assert!(revoked_device_key_hashes(&[]).is_empty());
    }

    #[test]
    fn omni32_parses_prefixed_and_bare() {
        assert_eq!(omni32(&format!("0x{}", "ab".repeat(32))), Some([0xab; 32]));
        assert_eq!(omni32(&"cd".repeat(32)), Some([0xcd; 32]));
        assert_eq!(omni32("0x1234"), None);
        assert_eq!(omni32("not-hex"), None);
    }

    /// #546 — the full assembly (a ceremony spawn or a spawn-context re-create)
    /// carries EVERY env the chat loop requires, so a re-created sandbox can
    /// never come up chat-silent for want of injection.
    #[test]
    fn delegate_identity_envs_full_set_covers_the_chat_contract() {
        let envs = delegate_identity_envs(
            &format!("0x{}", "AB".repeat(32)),
            &"CD".repeat(32),
            Some("0xdead"),
            None,
            "opchat-watchdog",
            &[(
                agentkeys_protocol::sandbox_env::BROKER_URL.into(),
                "https://broker.example.cn".into(),
            )],
            Some("smt1_feed"),
            Some("watchdog"),
            Some("sbt1_feed"),
        );
        let keys: Vec<&str> = envs.iter().map(|(k, _)| k.as_str()).collect();
        for required in agentkeys_protocol::sandbox_env::CHAT_REQUIRED {
            assert!(keys.contains(&required), "missing {required}: {keys:?}");
        }
        let get = |k: &str| {
            envs.iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        // Omnis canonicalized 0x+lowercase; URLs trimmed; no override key when
        // the channel worker URL is derived (never a required injection).
        assert_eq!(
            get("AGENTKEYS_ACTOR_OMNI"),
            format!("0x{}", "ab".repeat(32))
        );
        assert_eq!(
            get("AGENTKEYS_OPERATOR_OMNI"),
            format!("0x{}", "cd".repeat(32))
        );
        assert_eq!(get("AGENTKEYS_CHAT_CHANNEL_ID"), "opchat-watchdog");
        assert_eq!(get("AGENTKEYS_BROKER_URL"), "https://broker.example.cn");
        assert!(!keys.contains(&"AGENTKEYS_CHANNEL_WORKER_URL"));
        // #577 — the management bearer rides every armed create.
        assert_eq!(get("AGENTKEYS_SANDBOX_MGMT_TOKEN"), "smt1_feed");
        // #594 — the checkpoint namespace rides too.
        assert_eq!(get("AGENTKEYS_MEMORY_NS"), "watchdog");
        // #715 — the in-pod bearer rides every armed create.
        assert_eq!(get("AGENTKEYS_BRIDGE_TOKEN"), "sbt1_feed");
        assert!(!keys.contains(&"AGENTKEYS_STS_PROVIDER"));
    }

    #[test]
    fn local_service_addresses_cover_the_managed_runtime_without_forwarding_host_secrets() {
        let sources = std::collections::BTreeMap::from([
            ("BROKER_OIDC_ISSUER", "http://127.0.0.1:1"),
            ("AGENTKEYS_SIGNER_URL", "http://127.0.0.1:2"),
            ("AGENTKEYS_WORKER_CHANNEL_URL", "http://127.0.0.1:3"),
            ("AGENTKEYS_WORKER_CRED_URL", "http://127.0.0.1:4"),
            ("AGENTKEYS_WORKER_MEMORY_URL", "http://127.0.0.1:5"),
            ("AGENTKEYS_WORKER_CONFIG_URL", "http://127.0.0.1:6"),
            ("BROKER_SPONSOR_SIGNER_KEY", "synthetic-host-only-key"),
            ("AGENTKEYS_GATE_ADMIN_TOKEN", "synthetic-host-only-token"),
        ]);
        let environment =
            delegate_service_environment(|name| sources.get(name).map(|value| value.to_string()));
        assert_eq!(environment.len(), 6);
        for (service, name) in agentkeys_runtime::managed_agent::SERVICE_ENVIRONMENT {
            if *service != "model" {
                assert!(environment.iter().any(|(key, _)| key == name));
            }
        }
        assert!(!environment
            .iter()
            .any(|(_, value)| value.contains("host-only")));
        assert!(delegate_service_environment(|_| Some(" ".into())).is_empty());
    }

    /// #715 — the bridge token is a sibling derivation of the mgmt token under
    /// its own domain: deterministic, normalized, per-delegate, and NEVER equal
    /// to the mgmt token of the same delegate (distinct surfaces, distinct
    /// credentials).
    #[test]
    fn sandbox_bridge_token_is_derived_distinct_from_the_mgmt_token() {
        let dir = std::env::temp_dir().join(format!(
            "agentkeys-bridge-token-test-{}",
            std::process::id()
        ));
        let kp = crate::jwt::session::SessionKeypair::generate_and_persist(
            &dir.join("session-keypair.json"),
        )
        .unwrap();
        let a = sandbox_bridge_token(&kp, &format!("0x{}", "AB".repeat(32)));
        let b = sandbox_bridge_token(&kp, &"ab".repeat(32));
        assert_eq!(a, b, "0x-prefix and case must not fork the token");
        assert!(a.starts_with("sbt1_"), "{a}");
        assert_ne!(a, sandbox_bridge_token(&kp, &"cd".repeat(32)));
        assert_ne!(
            a.trim_start_matches("sbt1_"),
            sandbox_mgmt_token(&kp, &"ab".repeat(32)).trim_start_matches("smt1_"),
            "the bridge and mgmt tokens must derive under distinct domains"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #577 — the mgmt token is a pure derivation: stable per (key, delegate)
    /// so the broker can re-compute it at update time, `0x`/case-insensitive
    /// on the hash, distinct across delegates, never stored.
    #[test]
    fn sandbox_mgmt_token_is_deterministic_normalized_and_per_delegate() {
        let dir =
            std::env::temp_dir().join(format!("agentkeys-mgmt-token-test-{}", std::process::id()));
        let kp = crate::jwt::session::SessionKeypair::generate_and_persist(
            &dir.join("session-keypair.json"),
        )
        .unwrap();
        let a = sandbox_mgmt_token(&kp, &format!("0x{}", "AB".repeat(32)));
        let b = sandbox_mgmt_token(&kp, &"ab".repeat(32));
        assert_eq!(a, b, "0x-prefix and case must not fork the token");
        assert!(a.starts_with("smt1_"), "{a}");
        assert_ne!(a, sandbox_mgmt_token(&kp, &"cd".repeat(32)));
        let kp2 = crate::jwt::session::SessionKeypair::generate_and_persist(
            &dir.join("session-keypair-2.json"),
        )
        .unwrap();
        assert_ne!(
            a,
            sandbox_mgmt_token(&kp2, &"ab".repeat(32)),
            "a different broker key must derive a different token"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A context-less assembly (no K10 / channel / broker URL) injects only the
    /// omnis — never a partial chat set masquerading as configured.
    #[test]
    fn delegate_identity_envs_omits_absent_pieces() {
        let envs = delegate_identity_envs(
            &"ab".repeat(32),
            &"cd".repeat(32),
            None,
            None,
            "",
            &[(
                agentkeys_protocol::sandbox_env::CHANNEL_WORKER_URL.into(),
                "https://channel.example.cn/".into(),
            )],
            None,
            // #594 — a pre-#594 row's EMPTY ns injects nothing (the daemon
            // derives from the channel id instead).
            Some(""),
            None,
        );
        let keys: Vec<&str> = envs.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"AGENTKEYS_DEVICE_KEY_HEX"));
        assert!(!keys.contains(&"AGENTKEYS_BRIDGE_TOKEN"));
        assert!(!keys.contains(&"AGENTKEYS_STS_PROVIDER"));
        assert!(!keys.contains(&"AGENTKEYS_CHAT_CHANNEL_ID"));
        assert!(!keys.contains(&"AGENTKEYS_BROKER_URL"));
        assert!(!keys.contains(&"AGENTKEYS_SANDBOX_MGMT_TOKEN"));
        assert!(!keys.contains(&"AGENTKEYS_MEMORY_NS"));
        assert_eq!(
            envs.iter()
                .find(|(k, _)| k == "AGENTKEYS_CHANNEL_WORKER_URL")
                .map(|(_, v)| v.as_str()),
            Some("https://channel.example.cn/")
        );
    }
}
