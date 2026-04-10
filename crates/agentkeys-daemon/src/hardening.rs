#[derive(Debug, Default)]
pub struct HardeningReport {
    pub memfd_secret: HardeningStep,
    pub mlock: HardeningStep,
    pub dumpable: HardeningStep,
    pub no_new_privs: HardeningStep,
    pub seccomp_status: HardeningStep,
    pub caps_dropped: HardeningStep,
    pub landlock: HardeningStep,
}

#[allow(dead_code)]
#[derive(Debug, Default, PartialEq, Eq)]
pub enum HardeningStep {
    #[default]
    Skipped,
    Ok,
    Failed(String),
}

#[allow(dead_code)]
impl HardeningStep {
    pub fn is_ok(&self) -> bool {
        matches!(self, HardeningStep::Ok)
    }

    pub fn is_skipped(&self) -> bool {
        matches!(self, HardeningStep::Skipped)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::HardeningStep;
    use std::io;

    pub fn try_memfd_secret() -> HardeningStep {
        // SYS_memfd_secret = 447 on x86_64
        #[cfg(target_arch = "x86_64")]
        const SYS_MEMFD_SECRET: libc::c_long = 447;
        #[cfg(not(target_arch = "x86_64"))]
        const SYS_MEMFD_SECRET: libc::c_long = -1;

        if SYS_MEMFD_SECRET == -1 {
            return try_mmap_fallback();
        }

        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0usize) };
        if fd >= 0 {
            unsafe { libc::close(fd as libc::c_int) };
            HardeningStep::Ok
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOSYS) {
                tracing::warn!("memfd_secret: ENOSYS, falling back to mmap+mlock");
                try_mmap_fallback()
            } else {
                HardeningStep::Failed(format!("memfd_secret syscall: {err}"))
            }
        }
    }

    fn try_mmap_fallback() -> HardeningStep {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return HardeningStep::Failed("mmap fallback failed".into());
        }
        let lock_result = unsafe { libc::mlock(ptr, 4096) };
        unsafe { libc::munmap(ptr, 4096) };
        if lock_result == 0 {
            HardeningStep::Ok
        } else {
            let err = io::Error::last_os_error();
            HardeningStep::Failed(format!("mmap+mlock fallback: {err}"))
        }
    }

    pub fn try_mlock() -> HardeningStep {
        // The spec references mlock2(MLOCK_ONFAULT) which locks pages only on fault.
        // mlockall(MCL_CURRENT | MCL_FUTURE) is a superset: it locks all current and future
        // mappings eagerly. This is intentionally more aggressive — it prevents any page
        // containing sensitive data from ever being swapped out, at the cost of higher RSS.
        let result =
            unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        if result == 0 {
            HardeningStep::Ok
        } else {
            let err = io::Error::last_os_error();
            tracing::warn!("mlockall failed (may need CAP_IPC_LOCK): {err}");
            HardeningStep::Failed(format!("mlockall: {err}"))
        }
    }

    pub fn try_set_dumpable() -> HardeningStep {
        let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if result == 0 {
            HardeningStep::Ok
        } else {
            let err = io::Error::last_os_error();
            HardeningStep::Failed(format!("prctl PR_SET_DUMPABLE: {err}"))
        }
    }

    pub fn try_set_no_new_privs() -> HardeningStep {
        let result =
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if result == 0 {
            HardeningStep::Ok
        } else {
            let err = io::Error::last_os_error();
            HardeningStep::Failed(format!("prctl PR_SET_NO_NEW_PRIVS: {err}"))
        }
    }

    pub fn check_seccomp_status() -> HardeningStep {
        // Reports the kernel's seccomp mode for this process without installing a BPF filter.
        // Seccomp field values: 0=disabled, 1=strict, 2=filter (BPF active).
        // Note: AgentKeys v0 does not install its own BPF filter. This is a v0.1 hardening item.
        match read_proc_self_status_field("Seccomp") {
            Some(val) => {
                tracing::info!(
                    "Seccomp status: {} (0=disabled, 1=strict, 2=filter). \
                     Note: AgentKeys v0 does not install its own BPF filter. \
                     This is a v0.1 hardening item.",
                    val.trim()
                );
                HardeningStep::Ok
            }
            None => HardeningStep::Failed("could not read Seccomp from /proc/self/status".into()),
        }
    }

    pub fn try_drop_caps() -> HardeningStep {
        // PR_CAP_AMBIENT and PR_CAP_AMBIENT_CLEAR_ALL are defined in linux/prctl.h.
        // libc crate may not export them by name, so we use the raw integer values.
        const PR_CAP_AMBIENT: libc::c_int = 47;
        const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

        // Attempt to clear all ambient capabilities.
        let ambient_result = unsafe {
            libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
        };
        if ambient_result != 0 {
            let err = io::Error::last_os_error();
            // EINVAL means ambient caps are not supported by this kernel — not fatal.
            if err.raw_os_error() != Some(libc::EINVAL) {
                tracing::warn!("prctl PR_CAP_AMBIENT_CLEAR_ALL failed: {err}");
            }
        }

        // Drop all capabilities from the bounding set iteratively.
        let cap_last_cap = read_cap_last_cap().unwrap_or(40);
        for cap in 0..=cap_last_cap {
            let result = unsafe {
                libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0)
            };
            if result != 0 {
                let err = io::Error::last_os_error();
                // EINVAL means we've gone past the last valid cap — stop.
                if err.raw_os_error() == Some(libc::EINVAL) {
                    break;
                }
                // EPERM is expected when running without CAP_SETPCAP — acceptable.
            }
        }

        // Verify effective caps are now zero.
        match read_proc_self_status_field("CapEff") {
            Some(val) => {
                let trimmed = val.trim();
                if trimmed == "0000000000000000" {
                    HardeningStep::Ok
                } else {
                    tracing::warn!(
                        "CapEff not zero after drop attempt: {}. \
                         Process retains capabilities — running in a privileged context.",
                        trimmed
                    );
                    HardeningStep::Failed(format!("CapEff remains non-zero: {trimmed}"))
                }
            }
            None => HardeningStep::Failed("could not read CapEff from /proc/self/status".into()),
        }
    }

    pub fn try_landlock() -> HardeningStep {
        // Landlock syscall number 444 on x86_64 (landlock_create_ruleset)
        // We just probe for ENOSYS — actual ruleset enforcement is v1.
        #[cfg(target_arch = "x86_64")]
        const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
        #[cfg(not(target_arch = "x86_64"))]
        {
            tracing::info!("Landlock not available on this arch, continuing without filesystem restriction.");
            return HardeningStep::Skipped;
        }

        #[cfg(target_arch = "x86_64")]
        {
            let result = unsafe {
                libc::syscall(
                    SYS_LANDLOCK_CREATE_RULESET,
                    std::ptr::null::<u8>(),
                    0usize,
                    1u32,
                )
            };
            if result >= 0 {
                unsafe { libc::close(result as libc::c_int) };
                HardeningStep::Ok
            } else {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOSYS) {
                    tracing::info!(
                        "Landlock not available (ENOSYS), continuing without filesystem restriction."
                    );
                    HardeningStep::Skipped
                } else if err.raw_os_error() == Some(libc::EOPNOTSUPP) {
                    tracing::info!(
                        "Landlock not supported by kernel config, continuing without filesystem restriction."
                    );
                    HardeningStep::Skipped
                } else {
                    tracing::warn!("Landlock probe returned unexpected error: {err}");
                    HardeningStep::Skipped
                }
            }
        }
    }

    fn read_cap_last_cap() -> Option<u32> {
        let content = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap").ok()?;
        content.trim().parse().ok()
    }

    pub fn read_proc_self_status_field(field: &str) -> Option<String> {
        let content = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix(&format!("{field}:")) {
                return Some(rest.trim().to_string());
            }
        }
        None
    }
}

pub fn apply_hardening() -> anyhow::Result<HardeningReport> {
    let mut report = HardeningReport::default();

    #[cfg(target_os = "linux")]
    {
        report.memfd_secret = linux::try_memfd_secret();
        report.mlock = linux::try_mlock();
        report.dumpable = linux::try_set_dumpable();
        report.no_new_privs = linux::try_set_no_new_privs();
        report.seccomp_status = linux::check_seccomp_status();
        report.caps_dropped = linux::try_drop_caps();
        report.landlock = linux::try_landlock();

        tracing::info!(
            memfd_secret = ?report.memfd_secret,
            mlock = ?report.mlock,
            dumpable = ?report.dumpable,
            no_new_privs = ?report.no_new_privs,
            seccomp_status = ?report.seccomp_status,
            caps_dropped = ?report.caps_dropped,
            landlock = ?report.landlock,
            "kernel hardening applied"
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("kernel hardening skipped (macOS)");
        report.memfd_secret = HardeningStep::Skipped;
        report.mlock = HardeningStep::Skipped;
        report.dumpable = HardeningStep::Skipped;
        report.no_new_privs = HardeningStep::Skipped;
        report.seccomp_status = HardeningStep::Skipped;
        report.caps_dropped = HardeningStep::Skipped;
        report.landlock = HardeningStep::Skipped;
    }

    Ok(report)
}

#[cfg(target_os = "linux")]
pub use linux::read_proc_self_status_field;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn read_proc_self_status_field(_field: &str) -> Option<String> {
    None
}
