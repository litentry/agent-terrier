//! The #440 sandbox-spawn seam: ONE broker-side interface over the per-cloud
//! delegate-sandbox drivers — [`ve_faas`](crate::ve_faas) (Volcano veFaaS,
//! #377) and [`aws_ecs`](crate::aws_ecs) (ECS/Fargate, #440). The handlers
//! ([`handlers::sandbox`](crate::handlers::sandbox)) speak ONLY this enum, so
//! adding a cloud never touches the pairing/resolve/spawn/unpair call sites —
//! the same closed-seam discipline as the #376 `--cloud` driver split on the
//! ops side.
//!
//! Exactly ONE backend per broker: both drivers configured is a boot-time
//! hard error (no-silent-override — a broker guessing between two spawn
//! targets is a mis-provisioned host, not a preference).

use anyhow::{bail, Result};

use crate::aws_ecs::{EcsSandboxClient, EcsSandboxConfig};
use crate::ve_faas::VeFaasClient;

/// #543 fail-closed direct-ark guard, shared by both drivers: a create whose
/// `extra_envs` carry no gate-provisioned `ARK_API_KEY` would inject the
/// SHARED host vendor key into the sandbox — the LLM-plane twin of the #541
/// ambient-storage-credential prohibition — and is refused unless the operator
/// explicitly opted the stack in with `AGENTKEYS_ALLOW_DIRECT_ARK=1`.
/// Gate-provisioned spawns (the #427 ceremony path, per-delegate `gk_` relay
/// key) always pass.
pub(crate) fn direct_ark_guard(
    extra_envs: &[(String, String)],
    allow_direct_ark: bool,
) -> Result<()> {
    let gate_provisioned = extra_envs.iter().any(|(k, _)| k == "ARK_API_KEY");
    if gate_provisioned || allow_direct_ark {
        return Ok(());
    }
    bail!(
        "refusing to inject the shared host ark key into a delegate sandbox: this spawn \
         carries no gate-minted relay key and AGENTKEYS_ALLOW_DIRECT_ARK=1 is not set (#543 \
         fail-closed default). Either the broker→gate admin surface is unwired \
         (AGENTKEYS_GATE_ADMIN_URL/_TOKEN/_TURN_URL — setup-broker-host step 5) or \
         provisioning FAILED — the ceremony's gate status/error says which; fix that rather \
         than opting this stack into UNMETERED direct-ark injection."
    )
}

/// The shared ensure outcome. `agent_url` is PER-OUTCOME because the two
/// clouds differ: veFaaS fronts every instance behind ONE static gateway
/// (`None` here — callers fall back to [`SandboxBackend::static_agent_url`]),
/// while an ECS task carries its own ENI URL (present once the ENI attached).
#[derive(Debug, Clone)]
pub struct EnsureOutcome {
    pub sandbox_id: String,
    /// `true` when this call actually created the runtime (the audit-emit
    /// trigger); `false` when a live labeled instance/task was reused.
    pub created: bool,
    pub status: String,
    pub agent_url: Option<String>,
}

/// A CREATE-only extra-env provider (#543): the backend invokes it — inside the
/// spawn lock, on the CREATE branch ONLY, never on reuse — to obtain envs merged
/// into the fresh instance. resolve/poll pass the gate-provisioning closure so a
/// delegate cold-respawn comes back METERED; because it fires only on create, a
/// REUSED live sandbox never has its relay key rotated out from under it. Owned
/// captures (no borrows) keep it `'static`; boxed so the enum dispatch stays a
/// single concrete signature (no generic ripple through both drivers).
pub type CreateEnvProvider = Box<
    dyn FnOnce()
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<(String, String)>> + Send>>
        + Send,
>;

/// The no-op provider: nothing extra beyond `base_envs` on create. The #427
/// ceremony uses it — it provisions the gate key EAGERLY (it always creates and
/// must record the status) and passes the result in `base_envs`, so its create
/// callback has nothing left to do.
pub fn no_create_envs() -> CreateEnvProvider {
    Box::new(|| Box::pin(async { Vec::new() }))
}

/// One live runtime row for the #577 update/status paths — id + coarse
/// status, cloud-agnostic (veFaaS SandboxId / ECS task ARN). `expire_at` is
/// the veFaaS lease deadline **normalized to RFC3339** at the driver boundary
/// ([`ve_faas::normalize_expire_at`](crate::ve_faas::normalize_expire_at) —
/// the vendor emits Go's ambiguous `… +0800 CST` form); empty on backends
/// without one (ECS tasks have no expiry).
#[derive(Debug, Clone)]
pub struct LiveRuntime {
    pub id: String,
    pub status: String,
    pub expire_at: String,
}

/// The per-cloud delegate-sandbox driver behind one interface.
pub enum SandboxBackend {
    // Both boxed: the clients carry config + memos (#714/#715) and differ
    // ~2× in size; one heap indirection per boot, matched by reference
    // everywhere (clippy::large_enum_variant).
    VeFaas(Box<VeFaasClient>),
    AwsEcs(Box<EcsSandboxClient>),
}

impl SandboxBackend {
    /// Read the environment ONCE and pick the backend: `SANDBOX_FUNCTION_ID`
    /// enables veFaaS (#377), `AGENTKEYS_SANDBOX_ECS_CLUSTER` enables ECS
    /// (#440), neither = lifecycle disabled (`Ok(None)`), BOTH = hard error.
    pub async fn from_env() -> Result<Option<Self>> {
        let ve = VeFaasClient::from_env()?;
        let ecs_cfg = EcsSandboxConfig::from_lookup(|k| std::env::var(k).ok())?;
        match (ve, ecs_cfg) {
            (Some(_), Some(_)) => bail!(
                "both sandbox drivers are configured (SANDBOX_FUNCTION_ID = veFaaS AND \
                 AGENTKEYS_SANDBOX_ECS_CLUSTER = ECS) — a broker runs exactly one spawn \
                 backend; unset one of them"
            ),
            (Some(ve), None) => Ok(Some(Self::VeFaas(Box::new(ve)))),
            (None, Some(cfg)) => Ok(Some(Self::AwsEcs(Box::new(
                EcsSandboxClient::new(cfg).await,
            )))),
            (None, None) => Ok(None),
        }
    }

    /// Driver name for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::VeFaas(_) => "ve_faas",
            Self::AwsEcs(_) => "aws_ecs",
        }
    }

    /// What this broker spawns into — the `function_id` field of the
    /// `SandboxSpawn` audit body (wire name unchanged, #203 discipline):
    /// the veFaaS application id, or `cluster/taskdef` on ECS.
    pub fn runtime_ref(&self) -> String {
        match self {
            Self::VeFaas(c) => c.config.function_id.clone(),
            Self::AwsEcs(c) => c.runtime_ref(),
        }
    }

    /// The statically-configured device-facing URL, when the cloud has one:
    /// veFaaS' shared gateway. ECS has none (per-task URLs ride the outcome).
    pub fn static_agent_url(&self) -> Option<String> {
        match self {
            Self::VeFaas(c) => Some(c.agent_url().to_string()),
            Self::AwsEcs(_) => None,
        }
    }

    /// Idempotent per-delegate ensure (reuse-or-create; quota ≤ 1 live runtime
    /// per delegate). `base_envs` are merged over the driver's base env on a
    /// CREATE; `on_create` yields ADDITIONAL envs computed only when a create
    /// actually happens (#543 — the metered gate key, never minted on reuse).
    pub async fn ensure_for_delegate_with_envs(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
        base_envs: &[(String, String)],
        on_create: CreateEnvProvider,
    ) -> Result<EnsureOutcome> {
        match self {
            Self::VeFaas(c) => {
                let o = c
                    .ensure_for_delegate_with_envs(
                        device_key_hash,
                        actor_omni,
                        base_envs,
                        on_create,
                    )
                    .await?;
                Ok(EnsureOutcome {
                    sandbox_id: o.sandbox_id,
                    created: o.created,
                    status: o.status,
                    agent_url: None,
                })
            }
            Self::AwsEcs(c) => {
                c.ensure_for_delegate_with_envs(device_key_hash, actor_omni, base_envs, on_create)
                    .await
            }
        }
    }

    /// Teardown on unpair — kill/stop every live broker-managed runtime
    /// labeled for the device; returns the killed ids (empty = valid no-op).
    pub async fn kill_for_device(&self, device_key_hash: &str) -> Result<Vec<String>> {
        match self {
            Self::VeFaas(c) => c.kill_for_device(device_key_hash).await,
            Self::AwsEcs(c) => c.kill_for_device(device_key_hash).await,
        }
    }

    /// #577 — the delegate's LIVE runtimes (the same match `kill_for_device`
    /// kills, without the kill): what an in-place update snapshots + reports
    /// before tearing down. Normally 0 or 1 (the ensure quota invariant).
    pub async fn live_for_device(&self, device_key_hash: &str) -> Result<Vec<LiveRuntime>> {
        match self {
            Self::VeFaas(c) => Ok(c
                .live_instances_for_device(device_key_hash)
                .await?
                .into_iter()
                .map(|i| LiveRuntime {
                    id: i.id,
                    status: i.status,
                    expire_at: i.expire_at,
                })
                .collect()),
            Self::AwsEcs(c) => Ok(c
                .live_for_device(device_key_hash)
                .await?
                .into_iter()
                .map(|(id, status)| LiveRuntime {
                    id,
                    status,
                    expire_at: String::new(),
                })
                .collect()),
        }
    }

    /// #577 — the configured CR tag ref this backend spawns from, when it has
    /// one (`CR_IMAGE` on veFaaS; ECS pins its image in the task definition).
    pub fn current_image_tag(&self) -> Option<String> {
        match self {
            Self::VeFaas(c) => Some(c.config.image.trim().to_string()).filter(|i| !i.is_empty()),
            Self::AwsEcs(_) => None,
        }
    }

    /// #577 — the current pre-cache registration for this broker's `CR_IMAGE`
    /// (what a create issued now would freeze). `Ok(None)` = no comparable
    /// registry on this backend (ECS pulls the tag at task start, so a
    /// re-created task always runs current bits) or `CR_IMAGE` unset.
    pub async fn current_image_registration(&self) -> Result<Option<crate::ve_faas::SandboxImage>> {
        match self {
            Self::VeFaas(c) => c.current_image_registration().await,
            Self::AwsEcs(_) => Ok(None),
        }
    }

    /// #577 — the image identity one live runtime FROZE at spawn. `Ok(None)` =
    /// unknowable on this backend (ECS) or the instance runs the app default.
    pub async fn booted_image_info(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<crate::ve_faas::InstanceImageInfo>> {
        match self {
            Self::VeFaas(c) => c.describe_image_info(sandbox_id).await,
            Self::AwsEcs(_) => Ok(None),
        }
    }

    /// #577 — where the broker reaches ONE instance's management surface (the
    /// dsh bridge's `/v1/sandbox/mgmt/*` routes on
    /// [`agentkeys_protocol::sandbox_env::SANDBOX_BRIDGE_PORT`] — the bridge,
    /// not the daemon, owns `$DSH_HOME`): a base URL + the headers that pin
    /// the request to THAT instance. veFaaS fronts every instance behind the
    /// shared gateway with per-request routing headers (the measured
    /// `x-faas-instance-name`/`x-faas-proxy-port` contract — AGENTS.ops
    /// verification recipe). `None` = no broker-reachable management path on
    /// this backend (ECS today: the per-task ENI is not guaranteed
    /// broker-routable) — the update proceeds WITHOUT a session hand-off and
    /// says so.
    pub fn instance_mgmt_endpoint(
        &self,
        sandbox_id: &str,
    ) -> Option<(String, Vec<(String, String)>)> {
        self.instance_endpoint(
            sandbox_id,
            agentkeys_protocol::sandbox_env::SANDBOX_BRIDGE_PORT,
        )
    }

    /// The agentkeys-daemon's own surface inside ONE instance (its
    /// `/v1/sandbox/self/*` routes on
    /// [`agentkeys_protocol::sandbox_env::SANDBOX_DAEMON_PORT`]) — the #717
    /// live-rebind push. Same routing contract as
    /// [`Self::instance_mgmt_endpoint`].
    pub fn instance_daemon_endpoint(
        &self,
        sandbox_id: &str,
    ) -> Option<(String, Vec<(String, String)>)> {
        self.instance_endpoint(
            sandbox_id,
            agentkeys_protocol::sandbox_env::SANDBOX_DAEMON_PORT,
        )
    }

    /// ONE builder for every broker→instance request through the shared
    /// veFaaS gateway: the routing headers (instance name + proxy port) plus,
    /// since #715, the gateway credential (`EnableSecretToken`) — attached
    /// here and nowhere else, so no per-port caller can forget it.
    fn instance_endpoint(
        &self,
        sandbox_id: &str,
        port: u16,
    ) -> Option<(String, Vec<(String, String)>)> {
        match self {
            Self::VeFaas(c) => {
                let mut headers = vec![
                    ("x-faas-instance-name".into(), sandbox_id.to_string()),
                    ("x-faas-proxy-port".into(), port.to_string()),
                ];
                if let Some((name, value)) = c.gateway_secret_header() {
                    headers.push((name, value));
                }
                Some((c.agent_url().to_string(), headers))
            }
            Self::AwsEcs(_) => None,
        }
    }

    /// #715 — the boot-time gateway posture line (veFaaS only; ECS has no
    /// shared gateway).
    pub async fn log_gateway_posture(&self) {
        if let Self::VeFaas(c) = self {
            c.log_gateway_posture().await;
        }
    }
}

#[cfg(test)]
mod tests {
    // The dual-config hard error is exercised at the config layer (each
    // driver's from_lookup is unit-tested in its own module); from_env's
    // dispatch arms are trivially total. What we pin here is the outcome
    // mapping: VE outcomes never carry a per-instance URL.
    use super::*;

    #[test]
    fn ve_outcome_maps_with_no_per_instance_url() {
        let o = EnsureOutcome {
            sandbox_id: "sb-1".into(),
            created: true,
            status: "Ready".into(),
            agent_url: None,
        };
        assert!(o.agent_url.is_none());
        assert!(o.created);
    }

    fn envs(keys: &[&str]) -> Vec<(String, String)> {
        keys.iter().map(|k| (k.to_string(), "v".into())).collect()
    }

    #[test]
    fn direct_ark_guard_passes_gate_provisioned_spawns_regardless_of_opt_in() {
        let gate = envs(&["ARK_API_KEY", "ARK_BASE_URL", "AGENTKEYS_DEVICE_KEY_HEX"]);
        assert!(direct_ark_guard(&gate, false).is_ok());
        assert!(direct_ark_guard(&gate, true).is_ok());
    }

    #[test]
    fn direct_ark_guard_refuses_unprovisioned_spawns_without_opt_in() {
        // The resolve/poll ensure paths (empty extra_envs) and a
        // provision-failed ceremony (identity envs only) both fail closed.
        for e in [envs(&[]), envs(&["AGENTKEYS_DEVICE_KEY_HEX"])] {
            let err = direct_ark_guard(&e, false).unwrap_err().to_string();
            assert!(err.contains("AGENTKEYS_ALLOW_DIRECT_ARK"), "{err}");
            assert!(err.contains("AGENTKEYS_GATE_ADMIN_URL"), "{err}");
        }
    }

    #[test]
    fn direct_ark_guard_allows_unprovisioned_spawns_under_explicit_opt_in() {
        assert!(direct_ark_guard(&envs(&["AGENTKEYS_DEVICE_KEY_HEX"]), true).is_ok());
    }

    #[tokio::test]
    async fn no_create_envs_yields_nothing() {
        // The ceremony's create callback contract: it provisions the gate key
        // EAGERLY (into base_envs) and leaves the create callback a no-op.
        assert!(no_create_envs()().await.is_empty());
    }

    #[tokio::test]
    async fn metered_create_provider_passes_the_guard_empty_fails_closed() {
        // Models the #543 resolve/poll cold-create contract at the seam the
        // backend uses: on CREATE it awaits the provider and the guard runs on
        // the result. A provider that mints the gate relay key → METERED (guard
        // passes); a provider that returns empty (gate not-configured / failed)
        // → fail-closed (guard refuses) — never a silent direct-ark boot.
        let metered: CreateEnvProvider =
            Box::new(|| Box::pin(async { vec![("ARK_API_KEY".into(), "gk_probe".into())] }));
        assert!(direct_ark_guard(&metered().await, false).is_ok());

        let failed: CreateEnvProvider = Box::new(|| Box::pin(async { Vec::new() }));
        assert!(direct_ark_guard(&failed().await, false).is_err());
    }
}
