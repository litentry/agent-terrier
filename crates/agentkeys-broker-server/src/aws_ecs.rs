//! Broker-driven ECS/Fargate sandbox lifecycle (issue #440) — the AWS-stack
//! twin of [`ve_faas`](crate::ve_faas): one hermes-sandbox task per delegate,
//! spawned/killed by the broker on the delegation/pairing lifecycle, behind
//! the SAME [`SandboxBackend`](crate::sandbox_backend) seam. Same image
//! (`docker/hermes-sandbox`, published to ECR by `build.sh`), same label
//! discipline, same quota invariant:
//!
//! | veFaaS action       | ECS twin                                          |
//! |---------------------|---------------------------------------------------|
//! | `CreateSandbox`     | `RunTask` (FARGATE, awsvpc, tagged)               |
//! | `ListSandboxes`     | `ListTasks(startedBy)` + `DescribeTasks(TAGS)`    |
//! | `DescribeSandbox`   | `DescribeTasks` (status + ENI ip)                 |
//! | `SetSandboxTimeout` | — (Fargate tasks have no expiry; reuse is a no-op;|
//! |                     |   idle teardown is a #440 follow-up)              |
//! | `KillSandbox`       | `StopTask`                                        |
//!
//! ## Per-delegate quota invariant (parity with #377)
//!
//! `RunTask` is append-only, so idempotency is enforced HERE: every
//! broker-spawned task carries the SAME identity tags as the VE driver
//! ([`LABEL_DEVICE_KEY_HASH`](crate::ve_faas::LABEL_DEVICE_KEY_HASH) et al —
//! one definition, imported), plus `startedBy = "agentkeys-broker"` as the
//! managed-by marker `ListTasks` can filter server-side. `ensure` serializes
//! spawns behind one lock, reuses the delegate's live tagged task, and
//! refuses to create past `max_tasks`. ECS surfaces per-item errors as a
//! `failures[]` array (NOT an HTTP error) — every call here checks it loudly.
//!
//! ## `agent_url` is PER-TASK (unlike VE's shared gateway)
//!
//! A Fargate task gets its own awsvpc ENI; the sandbox bridge answers on
//! `http://<task-private-ip>:<port>`. The ensure outcome carries that URL
//! once the ENI is attached (a just-created task may report `agent_url:
//! null` + a PROVISIONING status — the device's next resolve returns the URL
//! via the reuse path). Private-IP first ship: in-VPC consumers (broker,
//! gateway hop) reach it; the public-reachability story (NLB vs public-ENI
//! lookup) is an explicit #440 follow-up, NOT silently assumed.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};

use crate::ve_faas::{LABEL_ACTOR_OMNI, LABEL_DEVICE_KEY_HASH, LABEL_MANAGED_BY, MANAGED_BY_VALUE};

/// `startedBy` marker on every broker-run task — the server-side filter
/// `ListTasks` gives us for free (≤36 chars; the tag set is the authority).
pub const STARTED_BY: &str = "agentkeys-broker";

/// `lastStatus` values that count as "the delegate already has a task" —
/// reuse, never duplicate.
const LIVE_STATUSES: &[&str] = &["provisioning", "pending", "activating", "running"];

/// ECS sandbox config, read ONCE at boot (tests inject via
/// [`EcsSandboxConfig::from_lookup`], the #258 posture).
#[derive(Debug, Clone)]
pub struct EcsSandboxConfig {
    /// ECS cluster name/ARN (`AGENTKEYS_SANDBOX_ECS_CLUSTER`) — presence of
    /// this key is what ENABLES the ECS spawn driver.
    pub cluster: String,
    /// Task-definition family[:revision] (`AGENTKEYS_SANDBOX_ECS_TASKDEF`),
    /// registered by `provision-sandbox-ecs.sh` (setup-cloud.sh step 18).
    pub task_definition: String,
    /// awsvpc subnets (`AGENTKEYS_SANDBOX_ECS_SUBNETS`, comma-separated).
    pub subnets: Vec<String>,
    /// awsvpc security groups (`AGENTKEYS_SANDBOX_ECS_SECURITY_GROUPS`,
    /// comma-separated) — the provision script's SG admits :port from the
    /// broker SG only (private-IP model).
    pub security_groups: Vec<String>,
    /// Container name inside the task definition
    /// (`AGENTKEYS_SANDBOX_ECS_CONTAINER`, default `hermes-sandbox`) — the
    /// env-override target.
    pub container_name: String,
    /// The sandbox bridge port (`AGENTKEYS_SANDBOX_ECS_PORT`, default 8090 —
    /// the hermes bridge, same as the VE driver's default).
    pub port: u32,
    /// `AGENTKEYS_SANDBOX_ECS_ASSIGN_PUBLIC_IP` (default `1`): Fargate in a
    /// public subnet needs a public IP to PULL from ECR (no NAT in the
    /// default VPC). The `agent_url` still uses the PRIVATE ip either way.
    pub assign_public_ip: bool,
    /// Refuse to create past this many live tasks
    /// (`AGENTKEYS_SANDBOX_ECS_MAX_TASKS`, default 20) — the spawn-storm
    /// backstop, parity with the VE `max_instances`.
    pub max_tasks: usize,
    /// Optional region override (`AGENTKEYS_SANDBOX_ECS_REGION`); default =
    /// the SDK default chain (the broker EC2's region).
    pub region: Option<String>,
}

impl EcsSandboxConfig {
    /// Build from a lookup fn (`None` = unset). `Ok(None)` when the driver is
    /// disabled (no `AGENTKEYS_SANDBOX_ECS_CLUSTER`); `Err` on a half-set
    /// config — never a silently degraded one.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        let non_empty = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let Some(cluster) = non_empty("AGENTKEYS_SANDBOX_ECS_CLUSTER") else {
            return Ok(None);
        };
        let require = |k: &str| {
            non_empty(k).ok_or_else(|| {
                anyhow!(
                    "AGENTKEYS_SANDBOX_ECS_CLUSTER is set but {k} is not — the broker cannot \
                     RunTask without it. Run scripts/operator/cloud/provision-sandbox-ecs.sh \
                     (setup-cloud.sh step 18) to provision + write the full key set, or unset \
                     AGENTKEYS_SANDBOX_ECS_CLUSTER."
                )
            })
        };
        let csv = |v: String| -> Vec<String> {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let parse_u32 = |k: &str, default: u32| -> Result<u32> {
            match non_empty(k) {
                Some(v) => v
                    .parse::<u32>()
                    .with_context(|| format!("{k}={v:?} not a u32")),
                None => Ok(default),
            }
        };
        let subnets = csv(require("AGENTKEYS_SANDBOX_ECS_SUBNETS")?);
        let security_groups = csv(require("AGENTKEYS_SANDBOX_ECS_SECURITY_GROUPS")?);
        if subnets.is_empty() || security_groups.is_empty() {
            bail!("AGENTKEYS_SANDBOX_ECS_SUBNETS / _SECURITY_GROUPS must carry >=1 id each");
        }
        Ok(Some(Self {
            cluster,
            task_definition: require("AGENTKEYS_SANDBOX_ECS_TASKDEF")?,
            subnets,
            security_groups,
            container_name: non_empty("AGENTKEYS_SANDBOX_ECS_CONTAINER")
                .unwrap_or_else(|| "hermes-sandbox".to_string()),
            port: parse_u32("AGENTKEYS_SANDBOX_ECS_PORT", 8090)?,
            assign_public_ip: non_empty("AGENTKEYS_SANDBOX_ECS_ASSIGN_PUBLIC_IP")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            max_tasks: parse_u32("AGENTKEYS_SANDBOX_ECS_MAX_TASKS", 20)? as usize,
            region: non_empty("AGENTKEYS_SANDBOX_ECS_REGION"),
        }))
    }
}

/// One task row (the ECS twin of `SandboxInstance`) — pure data so the quota
/// decisions stay unit-testable without the SDK.
#[derive(Debug, Clone)]
pub struct TaskView {
    pub arn: String,
    pub status: String,
    pub tags: HashMap<String, String>,
    pub private_ip: Option<String>,
}

impl TaskView {
    pub fn is_live(&self) -> bool {
        let s = self.status.to_ascii_lowercase();
        LIVE_STATUSES.iter().any(|l| *l == s)
    }

    fn labeled_for(&self, device_key_hash: &str) -> bool {
        self.tags
            .get(LABEL_DEVICE_KEY_HASH)
            .is_some_and(|v| v.eq_ignore_ascii_case(device_key_hash))
            && self
                .tags
                .get(LABEL_MANAGED_BY)
                .is_some_and(|v| v == MANAGED_BY_VALUE)
    }
}

/// Pure quota decision: the delegate's live task among `rows`, if any.
fn pick_live_for_device<'a>(rows: &'a [TaskView], device_key_hash: &str) -> Option<&'a TaskView> {
    rows.iter()
        .find(|t| t.is_live() && t.labeled_for(device_key_hash))
}

/// The broker's ECS client. Credentials ride the broker EC2 instance role
/// (the default SDK chain) — `provision-sandbox-ecs.sh` attaches the scoped
/// RunTask/StopTask/List/Describe (+ PassRole on the exec role) policy.
pub struct EcsSandboxClient {
    ecs: aws_sdk_ecs::Client,
    pub config: EcsSandboxConfig,
    /// Same #338 isolated ark family as the VE driver — the family FILE
    /// carries whatever OpenAI-compatible endpoint this stack uses (Ark on
    /// VE; OpenRouter/Gemini-compatible on AWS). Resolved per spawn so a
    /// rotation lands without a broker restart.
    inference: agentkeys_inference_creds::Resolver,
    search_model: Option<String>,
    /// Spawns serialized — same rationale as the VE driver's ensure_lock.
    ensure_lock: tokio::sync::Mutex<()>,
}

impl EcsSandboxClient {
    /// Build the SDK client (region override honored) — config is injected,
    /// creds/region resolve via the default chain (instance role).
    pub async fn new(config: EcsSandboxConfig) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(r) = &config.region {
            loader = loader.region(aws_config::Region::new(r.clone()));
        }
        let sdk = loader.load().await;
        Self {
            ecs: aws_sdk_ecs::Client::new(&sdk),
            config,
            inference: agentkeys_inference_creds::Resolver::from_process(),
            search_model: std::env::var("SEARCH_MODEL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            ensure_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The audit `function_id` twin: what this broker spawns into.
    pub fn runtime_ref(&self) -> String {
        format!("{}/{}", self.config.cluster, self.config.task_definition)
    }

    fn agent_url_for(&self, ip: &str) -> String {
        format!("http://{}:{}", ip, self.config.port)
    }

    /// `ListTasks(startedBy)` + `DescribeTasks(TAGS)` → broker-managed rows.
    async fn list_managed_tasks(&self) -> Result<Vec<TaskView>> {
        let listed = self
            .ecs
            .list_tasks()
            .cluster(&self.config.cluster)
            .started_by(STARTED_BY)
            .send()
            .await
            .context("ecs ListTasks failed")?;
        let arns = listed.task_arns().to_vec();
        if arns.is_empty() {
            return Ok(Vec::new());
        }
        let described = self
            .ecs
            .describe_tasks()
            .cluster(&self.config.cluster)
            .set_tasks(Some(arns))
            .include(aws_sdk_ecs::types::TaskField::Tags)
            .send()
            .await
            .context("ecs DescribeTasks failed")?;
        // Per-item failures are data, not an HTTP error — MISSING (a task
        // already reaped) is normal churn; anything else is loud.
        for f in described.failures() {
            let reason = f.reason().unwrap_or("?");
            if reason != "MISSING" {
                tracing::warn!(
                    arn = f.arn().unwrap_or("?"),
                    reason,
                    "ecs DescribeTasks partial failure"
                );
            }
        }
        Ok(described.tasks().iter().map(task_view).collect())
    }

    /// The instance env — SAME contract as the VE driver (`instance_envs` +
    /// merge-over semantics), so a spawned sandbox boots identically on
    /// either cloud. A missing ark family is a HARD error with the rotation
    /// command — an instance without an LLM key boots broken in a way the
    /// device can't diagnose.
    fn instance_envs(&self) -> Result<Vec<(String, String)>> {
        let ark = self.inference.ark().map_err(|e| {
            anyhow!(
                "cannot spawn a delegate sandbox: the ark inference family does not resolve \
                 ({e}). Populate it with: AGENTKEYS_INFERENCE_CREDS_DIR=<dir> \
                 bash scripts/operator/secrets/rotate-inference-cred.sh ark"
            )
        })?;
        let mut envs = vec![
            ("ARK_API_KEY".to_string(), ark.api_key),
            ("LLM_ENDPOINT_ID".to_string(), ark.endpoint_id),
            ("ARK_BASE_URL".to_string(), ark.base_url),
        ];
        if let Some(m) = &self.search_model {
            envs.push(("SEARCH_MODEL".to_string(), m.clone()));
        }
        Ok(envs)
    }

    /// `RunTask` tagged for the delegate → the new task view.
    async fn run_for_delegate(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
        extra_envs: &[(String, String)],
    ) -> Result<TaskView> {
        use aws_sdk_ecs::types::{
            AssignPublicIp, AwsVpcConfiguration, ContainerOverride, KeyValuePair, LaunchType,
            NetworkConfiguration, Tag, TaskOverride,
        };
        let mut merged = self.instance_envs()?;
        for (k, v) in extra_envs {
            match merged.iter_mut().find(|(mk, _)| mk == k) {
                Some(slot) => slot.1 = v.clone(),
                None => merged.push((k.clone(), v.clone())),
            }
        }
        let mut container = ContainerOverride::builder().name(&self.config.container_name);
        for (k, v) in merged {
            container = container.environment(KeyValuePair::builder().name(k).value(v).build());
        }
        let vpc = AwsVpcConfiguration::builder()
            .set_subnets(Some(self.config.subnets.clone()))
            .set_security_groups(Some(self.config.security_groups.clone()))
            .assign_public_ip(if self.config.assign_public_ip {
                AssignPublicIp::Enabled
            } else {
                AssignPublicIp::Disabled
            })
            .build()
            .context("awsvpc configuration")?;
        let tag = |k: &str, v: &str| Tag::builder().key(k).value(v).build();
        let resp = self
            .ecs
            .run_task()
            .cluster(&self.config.cluster)
            .task_definition(&self.config.task_definition)
            .launch_type(LaunchType::Fargate)
            .network_configuration(
                NetworkConfiguration::builder()
                    .awsvpc_configuration(vpc)
                    .build(),
            )
            .overrides(
                TaskOverride::builder()
                    .container_overrides(container.build())
                    .build(),
            )
            .started_by(STARTED_BY)
            .tags(tag(LABEL_DEVICE_KEY_HASH, device_key_hash))
            .tags(tag(LABEL_ACTOR_OMNI, actor_omni))
            .tags(tag(LABEL_MANAGED_BY, MANAGED_BY_VALUE))
            .send()
            .await
            .context("ecs RunTask failed")?;
        if let Some(f) = resp.failures().first() {
            bail!(
                "ecs RunTask refused: arn={} reason={} detail={}",
                f.arn().unwrap_or("-"),
                f.reason().unwrap_or("?"),
                f.detail().unwrap_or("-")
            );
        }
        let task = resp
            .tasks()
            .first()
            .ok_or_else(|| anyhow!("ecs RunTask returned neither task nor failure"))?;
        let view = task_view(task);
        // Quota-invariant self-check, parity with the VE label check: the
        // fresh task must carry our tags or every future ensure duplicates.
        if !view.labeled_for(device_key_hash) {
            tracing::error!(
                task_arn = %view.arn,
                device_key_hash = %device_key_hash,
                "ECS tags NOT visible on the RunTask response — the per-delegate quota \
                 invariant (#440) is UNENFORCEABLE and future ensures will duplicate tasks \
                 until the cap. Inspect DescribeTasks TAGS."
            );
        }
        Ok(view)
    }

    /// THE ensure entry point (same contract as the VE driver): reuse the
    /// delegate's live tagged task, else RunTask; at most ONE live task per
    /// delegate. No extend leg — Fargate tasks have no expiry.
    pub async fn ensure_for_delegate_with_envs(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
        extra_envs: &[(String, String)],
    ) -> Result<crate::sandbox_backend::EnsureOutcome> {
        let _guard = self.ensure_lock.lock().await;

        let all = self.list_managed_tasks().await?;
        if let Some(mine) = pick_live_for_device(&all, device_key_hash) {
            return Ok(crate::sandbox_backend::EnsureOutcome {
                sandbox_id: mine.arn.clone(),
                created: false,
                status: mine.status.clone(),
                agent_url: mine.private_ip.as_deref().map(|ip| self.agent_url_for(ip)),
            });
        }

        let live_total = all.iter().filter(|t| t.is_live()).count();
        if live_total >= self.config.max_tasks {
            bail!(
                "refusing to spawn: {live_total} live tasks in {} >= AGENTKEYS_SANDBOX_ECS_MAX_TASKS ({}) — \
                 if tag matching is broken this cap is what bounds the damage; inspect ListTasks/DescribeTasks",
                self.config.cluster,
                self.config.max_tasks
            );
        }

        let view = self
            .run_for_delegate(device_key_hash, actor_omni, extra_envs)
            .await?;
        Ok(crate::sandbox_backend::EnsureOutcome {
            agent_url: view.private_ip.as_deref().map(|ip| self.agent_url_for(ip)),
            sandbox_id: view.arn,
            created: true,
            // A just-run task usually reports PROVISIONING with no ENI yet —
            // the device's next resolve returns the URL via the reuse path.
            status: view.status,
        })
    }

    /// Teardown on unpair: stop every live broker-managed task tagged for the
    /// device. Returns the stopped ARNs (empty = valid no-op).
    pub async fn kill_for_device(&self, device_key_hash: &str) -> Result<Vec<String>> {
        let all = self.list_managed_tasks().await?;
        let mut killed = Vec::new();
        for t in all
            .iter()
            .filter(|t| t.labeled_for(device_key_hash) && t.is_live())
        {
            self.ecs
                .stop_task()
                .cluster(&self.config.cluster)
                .task(&t.arn)
                .reason("agentkeys unpair teardown (#440)")
                .send()
                .await
                .with_context(|| format!("ecs StopTask {}", t.arn))?;
            killed.push(t.arn.clone());
        }
        Ok(killed)
    }
}

/// Map one SDK task to the pure view (tags + awsvpc ENI private ip).
fn task_view(task: &aws_sdk_ecs::types::Task) -> TaskView {
    let tags = task
        .tags()
        .iter()
        .filter_map(|t| Some((t.key()?.to_string(), t.value()?.to_string())))
        .collect();
    let private_ip = task
        .containers()
        .iter()
        .flat_map(|c| c.network_interfaces())
        .filter_map(|ni| ni.private_ipv4_address())
        .next()
        .map(str::to_string);
    TaskView {
        arn: task.task_arn().unwrap_or_default().to_string(),
        status: task.last_status().unwrap_or_default().to_string(),
        tags,
        private_ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_lookup<'a>(map: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            map.iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn config_absent_cluster_disables_driver() {
        assert!(EcsSandboxConfig::from_lookup(cfg_lookup(&[]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn config_half_set_is_a_hard_error() {
        let err = EcsSandboxConfig::from_lookup(cfg_lookup(&[(
            "AGENTKEYS_SANDBOX_ECS_CLUSTER",
            "agentkeys-sandbox",
        )]))
        .err()
        .unwrap();
        // Names a missing AGENTKEYS_SANDBOX_ECS_* key + the provisioning fix.
        assert!(err.to_string().contains("AGENTKEYS_SANDBOX_ECS_"), "{err}");
        assert!(
            err.to_string().contains("provision-sandbox-ecs.sh"),
            "{err}"
        );
    }

    #[test]
    fn config_defaults_and_csv_parsing() {
        let cfg = EcsSandboxConfig::from_lookup(cfg_lookup(&[
            ("AGENTKEYS_SANDBOX_ECS_CLUSTER", "agentkeys-sandbox"),
            ("AGENTKEYS_SANDBOX_ECS_TASKDEF", "hermes-sandbox"),
            ("AGENTKEYS_SANDBOX_ECS_SUBNETS", "subnet-a, subnet-b ,"),
            ("AGENTKEYS_SANDBOX_ECS_SECURITY_GROUPS", "sg-1"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(cfg.subnets, vec!["subnet-a", "subnet-b"]);
        assert_eq!(cfg.security_groups, vec!["sg-1"]);
        assert_eq!(cfg.container_name, "hermes-sandbox");
        assert_eq!(cfg.port, 8090);
        assert!(cfg.assign_public_ip);
        assert_eq!(cfg.max_tasks, 20);
        assert!(cfg.region.is_none());
    }

    #[test]
    fn config_public_ip_opt_out() {
        let cfg = EcsSandboxConfig::from_lookup(cfg_lookup(&[
            ("AGENTKEYS_SANDBOX_ECS_CLUSTER", "c"),
            ("AGENTKEYS_SANDBOX_ECS_TASKDEF", "t"),
            ("AGENTKEYS_SANDBOX_ECS_SUBNETS", "s"),
            ("AGENTKEYS_SANDBOX_ECS_SECURITY_GROUPS", "g"),
            ("AGENTKEYS_SANDBOX_ECS_ASSIGN_PUBLIC_IP", "0"),
        ]))
        .unwrap()
        .unwrap();
        assert!(!cfg.assign_public_ip);
    }

    fn row(arn: &str, status: &str, tags: &[(&str, &str)], ip: Option<&str>) -> TaskView {
        TaskView {
            arn: arn.into(),
            status: status.into(),
            tags: tags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            private_ip: ip.map(str::to_string),
        }
    }

    #[test]
    fn pick_live_matches_only_managed_tagged_live_rows() {
        let dev = "0xdev";
        let rows = vec![
            row(
                "stopped",
                "STOPPED",
                &[
                    (LABEL_DEVICE_KEY_HASH, dev),
                    (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
                ],
                None,
            ),
            row(
                "other",
                "RUNNING",
                &[
                    (LABEL_DEVICE_KEY_HASH, "0xother"),
                    (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
                ],
                Some("10.0.0.9"),
            ),
            // tagged but NOT broker-managed (operator hand-run task)
            row("manual", "RUNNING", &[(LABEL_DEVICE_KEY_HASH, dev)], None),
            row(
                "mine",
                "RUNNING",
                &[
                    (LABEL_DEVICE_KEY_HASH, dev),
                    (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
                ],
                Some("10.0.0.7"),
            ),
        ];
        assert_eq!(pick_live_for_device(&rows, dev).unwrap().arn, "mine");
        assert!(pick_live_for_device(&rows, "0xnobody").is_none());
    }

    #[test]
    fn provisioning_counts_live_and_match_is_case_insensitive() {
        let rows = vec![row(
            "boot",
            "PROVISIONING",
            &[
                (LABEL_DEVICE_KEY_HASH, "0xABCD"),
                (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
            ],
            None,
        )];
        assert_eq!(pick_live_for_device(&rows, "0xabcd").unwrap().arn, "boot");
        assert!(rows[0].is_live());
        assert!(!row("x", "DEPROVISIONING", &[], None).is_live());
    }
}
