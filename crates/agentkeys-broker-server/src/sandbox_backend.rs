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

/// The per-cloud delegate-sandbox driver behind one interface.
pub enum SandboxBackend {
    VeFaas(VeFaasClient),
    AwsEcs(EcsSandboxClient),
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
            (Some(ve), None) => Ok(Some(Self::VeFaas(ve))),
            (None, Some(cfg)) => Ok(Some(Self::AwsEcs(EcsSandboxClient::new(cfg).await))),
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

    /// Idempotent per-delegate ensure (reuse-or-create; quota ≤ 1 live
    /// runtime per delegate; `extra_envs` merged over the driver's base env
    /// on a CREATE).
    pub async fn ensure_for_delegate_with_envs(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
        extra_envs: &[(String, String)],
    ) -> Result<EnsureOutcome> {
        match self {
            Self::VeFaas(c) => {
                let o = c
                    .ensure_for_delegate_with_envs(device_key_hash, actor_omni, extra_envs)
                    .await?;
                Ok(EnsureOutcome {
                    sandbox_id: o.sandbox_id,
                    created: o.created,
                    status: o.status,
                    agent_url: None,
                })
            }
            Self::AwsEcs(c) => {
                c.ensure_for_delegate_with_envs(device_key_hash, actor_omni, extra_envs)
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
}
