//! Contact-registry loading + the #418 admin write path. The registry is a
//! master-authored `policy`-class document (§14.5). Reads: every inbound turn
//! (L3). Writes: ONLY the master-driven bind ceremony through the admin-bearer-
//! gated endpoints (invite / claim / approve) — the gateway is the write
//! EXECUTOR for the master's parent-control actions, never an authority of its
//! own (a bind still requires the master's explicit approve). Syncing the doc
//! through the config data class is a follow-up (noted in the PR).

use std::sync::Arc;
use std::sync::RwLock;

use agentkeys_protocol::ContactRegistry;
use anyhow::Context;

/// A hot registry handle. `load` reads the file; `snapshot` returns a copy
/// under a read lock; `mutate` applies a master-authorized change and persists
/// it atomically (tmp + rename, `0600`).
#[derive(Clone)]
pub struct RegistryHandle {
    path: String,
    inner: Arc<RwLock<ContactRegistry>>,
}

impl RegistryHandle {
    /// Boot-time load. A MISSING file is the legitimate first-boot state (the
    /// registry is master-authored and grows via `mutate`, which persists it) —
    /// start empty and say so loudly. Any other read/parse failure stays a hard
    /// error, and `reload` stays strict: a registry that existed and then
    /// vanished at runtime is contact-list loss, never silently emptied.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let reg = match read_file(path) {
            Ok(reg) => reg,
            Err(e) if is_not_found(&e) => {
                tracing::warn!(
                    path,
                    "contact registry file absent — first boot, starting EMPTY \
                     (created on the first master-approved bind)"
                );
                ContactRegistry::default()
            }
            Err(e) => return Err(e),
        };
        Ok(RegistryHandle {
            path: path.to_string(),
            inner: Arc::new(RwLock::new(reg)),
        })
    }

    /// A snapshot of the current registry (clone — the registry is small).
    pub fn snapshot(&self) -> ContactRegistry {
        self.inner.read().expect("registry lock poisoned").clone()
    }

    /// Re-read the file (after the master rewrote it out-of-band). Returns the
    /// new bound count on success.
    pub fn reload(&self) -> anyhow::Result<usize> {
        let reg = read_file(&self.path)?;
        let n = reg.bound.len();
        *self.inner.write().expect("registry lock poisoned") = reg;
        Ok(n)
    }

    /// Apply a master-authorized mutation and persist it atomically. The
    /// closure's return value is passed through; on persist failure the
    /// in-memory change is kept (the next successful mutate re-persists it)
    /// but the error surfaces to the caller — never a silent half-write.
    pub fn mutate<T>(
        &self,
        f: impl FnOnce(&mut ContactRegistry) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut guard = self.inner.write().expect("registry lock poisoned");
        let out = f(&mut guard)?;
        persist(&self.path, &guard)?;
        Ok(out)
    }
}

fn read_file(path: &str) -> anyhow::Result<ContactRegistry> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading contact registry {path}"))?;
    let reg: ContactRegistry =
        serde_json::from_str(&raw).with_context(|| format!("parsing contact registry {path}"))?;
    Ok(reg)
}

/// True when the error chain bottoms out in io `NotFound`. `read_file` wraps
/// the io error in `.with_context`, so walk the chain rather than downcasting
/// only the head.
fn is_not_found(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::NotFound)
}

/// Atomic write (tmp + rename), `0600` — the registry holds openids (PII) and a
/// torn write must never eat the household's contact list.
fn persist(path: &str, reg: &ContactRegistry) -> anyhow::Result<()> {
    let raw = serde_json::to_string_pretty(reg).context("serializing contact registry")?;
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, &raw).with_context(|| format!("writing {tmp}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path).with_context(|| format!("renaming {tmp} → {path}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_protocol::{BindInvite, ContactTier};

    #[test]
    fn mutate_persists_atomically_and_reload_sees_it() {
        let path = std::env::temp_dir()
            .join(format!("ak-reg-mutate-{}.json", std::process::id()))
            .to_string_lossy()
            .to_string();
        std::fs::write(&path, r#"{"bound":[],"pending":[]}"#).unwrap();

        let handle = RegistryHandle::load(&path).unwrap();
        handle
            .mutate(|reg| {
                reg.invites.push(BindInvite {
                    bind_code: "AK-TEST01".into(),
                    contact_id: "c-grandma".into(),
                    display_name: "奶奶".into(),
                    tier: ContactTier::Elder,
                    reach: vec!["chef".into()],
                });
                Ok(())
            })
            .unwrap();

        // A FRESH handle reads the persisted invite (pre-#418 files parse too —
        // `invites` was absent in the seed file above).
        let fresh = RegistryHandle::load(&path).unwrap();
        assert_eq!(fresh.snapshot().invites.len(), 1);
        assert_eq!(fresh.snapshot().invites[0].bind_code, "AK-TEST01");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(&path).ok();
    }

    // First boot: no registry file yet (nothing bound) — the gateway must come
    // up EMPTY, not crash-loop (the live VE incident: nginx 502, restart
    // counter in the thousands). The first master-approved mutate then creates
    // the file, and a fresh load reads it back.
    #[test]
    fn load_missing_file_is_first_boot_empty() {
        let path = std::env::temp_dir()
            .join(format!("ak-reg-firstboot-{}.json", std::process::id()))
            .to_string_lossy()
            .to_string();
        std::fs::remove_file(&path).ok();

        let handle = RegistryHandle::load(&path).unwrap();
        let snap = handle.snapshot();
        assert!(snap.bound.is_empty() && snap.pending.is_empty() && snap.invites.is_empty());
        assert!(!std::path::Path::new(&path).exists(), "load never writes");

        handle
            .mutate(|reg| {
                reg.invites.push(BindInvite {
                    bind_code: "AK-FIRST1".into(),
                    contact_id: "c-first".into(),
                    display_name: "first".into(),
                    tier: ContactTier::Elder,
                    reach: vec![],
                });
                Ok(())
            })
            .unwrap();
        assert_eq!(
            RegistryHandle::load(&path)
                .unwrap()
                .snapshot()
                .invites
                .len(),
            1
        );
        std::fs::remove_file(&path).ok();
    }

    // The strict half of the contract: a registry that EXISTED and then
    // vanished at runtime is contact-list loss — reload must fail loud, never
    // silently empty the household's contacts.
    #[test]
    fn reload_missing_file_stays_a_hard_error() {
        let path = std::env::temp_dir()
            .join(format!("ak-reg-reload-{}.json", std::process::id()))
            .to_string_lossy()
            .to_string();
        std::fs::write(&path, r#"{"bound":[],"pending":[]}"#).unwrap();
        let handle = RegistryHandle::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(handle.reload().is_err());
    }
}
