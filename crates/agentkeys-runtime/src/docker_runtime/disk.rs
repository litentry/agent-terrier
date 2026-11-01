use super::*;

const MIB_IN_KIB: u64 = 1024;
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskPolicy {
    pub state_limit_mib: u32,
    pub min_free_mib: u32,
    pub check_interval_seconds: u32,
}

impl Default for DiskPolicy {
    fn default() -> Self {
        Self {
            state_limit_mib: 1024,
            min_free_mib: 1024,
            check_interval_seconds: 15,
        }
    }
}

impl DiskPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.state_limit_mib > 0
                && self.min_free_mib > 0
                && (1..=300).contains(&self.check_interval_seconds),
            "invalid development disk policy"
        );
        Ok(())
    }

    pub(super) fn from_json(value: Option<String>) -> Result<Self> {
        let policy: Self = match value {
            Some(value) => {
                serde_json::from_str(&value).context("invalid development disk policy JSON")?
            }
            None => Self::default(),
        };
        policy.validate()?;
        Ok(policy)
    }

    fn check(&self, sample: DiskUsage) -> Result<()> {
        ensure!(
            sample.used_kib <= u64::from(self.state_limit_mib) * MIB_IN_KIB,
            "development state allowance exceeded"
        );
        ensure!(
            sample.available_kib >= u64::from(self.min_free_mib) * MIB_IN_KIB,
            "development volume has insufficient free space"
        );
        Ok(())
    }
}

struct DiskUsage {
    used_kib: u64,
    available_kib: u64,
}

impl DiskUsage {
    fn parse(output: &[u8]) -> Result<Self> {
        ensure!(
            output.len() <= 4096,
            "disk measurement exceeded output bound"
        );
        let text = std::str::from_utf8(output).context("invalid disk measurement encoding")?;
        let lines: Vec<_> = text.lines().collect();
        ensure!(lines.len() == 3, "incomplete disk measurement");
        let used: Vec<_> = lines[0].split_whitespace().collect();
        let free: Vec<_> = lines[2].split_whitespace().collect();
        ensure!(
            used.len() == 2 && used[1] == STATE_DIRECTORY && free.len() == 6,
            "invalid disk measurement fields"
        );
        Ok(Self {
            used_kib: used[0].parse().context("invalid disk usage count")?,
            available_kib: free[3].parse().context("invalid disk free-space count")?,
        })
    }
}

impl LocalDockerCommand {
    pub(super) async fn check_disk(&self, id: &str, policy: &DiskPolicy) -> Result<()> {
        let output = tokio::time::timeout(
            SAMPLE_TIMEOUT,
            self.execute(
                &[
                    "exec".into(),
                    id.into(),
                    "env".into(),
                    "LC_ALL=C".into(),
                    "sh".into(),
                    "-c".into(),
                    "du -skx \"$1\" && df -Pk \"$1\"".into(),
                    "disk-usage".into(),
                    STATE_DIRECTORY.into(),
                ],
                None,
            ),
        )
        .await
        .context("development disk measurement timed out")??;
        policy.check(DiskUsage::parse(&output)?)
    }

    pub(super) async fn monitor_disk(&self, id: &str, policy: &DiskPolicy) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(u64::from(
                policy.check_interval_seconds,
            )))
            .await;
            self.check_disk(id, policy).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_denials_have_positive_boundary_controls() {
        let policy = DiskPolicy {
            state_limit_mib: 2,
            min_free_mib: 3,
            check_interval_seconds: 1,
        };
        assert!(policy
            .check(DiskUsage {
                used_kib: 2048,
                available_kib: 3072
            })
            .is_ok());
        assert!(policy
            .check(DiskUsage {
                used_kib: 2049,
                available_kib: 3072
            })
            .unwrap_err()
            .to_string()
            .contains("allowance exceeded"));
        assert!(policy
            .check(DiskUsage {
                used_kib: 2048,
                available_kib: 3071
            })
            .unwrap_err()
            .to_string()
            .contains("insufficient free space"));
    }

    #[test]
    fn invalid_configuration_and_measurements_are_not_zero_usage() {
        for value in [
            "{}",
            "null",
            r#"{"state_limit_mib":1,"min_free_mib":1,"check_interval_seconds":0}"#,
            r#"{"state_limit_mib":1,"min_free_mib":1,"check_interval_seconds":1,"extra":1}"#,
        ] {
            assert!(DiskPolicy::from_json(Some(value.into())).is_err());
        }
        for value in ["", "0", "0 /wrong\nFilesystem 1024-blocks Used Available Capacity Mounted\nvolume 1 1 0 100% /state", "garbage\ngarbage\ngarbage"] {
            assert!(DiskUsage::parse(value.as_bytes()).is_err());
        }
        let valid = format!("12 {STATE_DIRECTORY}\nFilesystem 1024-blocks Used Available Capacity Mounted\nvolume 100 12 88 12% {STATE_DIRECTORY}\n");
        let measured = DiskUsage::parse(valid.as_bytes()).unwrap();
        assert_eq!(measured.used_kib, 12);
        assert_eq!(measured.available_kib, 88);
    }
}
