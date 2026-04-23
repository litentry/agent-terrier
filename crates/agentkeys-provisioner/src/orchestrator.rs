use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use agentkeys_core::backend::CredentialBackend;
use agentkeys_types::{ProvisionEvent, ServiceName, Session, TripwireKind, WalletAddress};

use crate::error::{ProvisionError, ProvisionResult};
use crate::metrics::{self, ProvisionMetric, VerificationResultLabel};
use crate::subprocess::{spawn_and_collect, SubprocessConfig, SubprocessOutcome};

#[derive(Debug, Clone)]
pub struct ActiveProvision {
    pub service: String,
    pub started_at: Instant,
}

#[derive(Debug, Clone)]
pub struct Provisioner {
    active: Arc<Mutex<Option<ActiveProvision>>>,
}

impl Default for Provisioner {
    fn default() -> Self {
        Self::new()
    }
}

impl Provisioner {
    pub fn new() -> Self {
        Self {
            active: Arc::new(Mutex::new(None)),
        }
    }

    pub fn try_claim(&self, service: &str) -> ProvisionResult<ProvisionGuard> {
        let mut guard = self.active_lock();
        if let Some(existing) = guard.as_ref() {
            return Err(ProvisionError::InProgress {
                active_service: existing.service.clone(),
            });
        }
        *guard = Some(ActiveProvision {
            service: service.to_string(),
            started_at: Instant::now(),
        });
        Ok(ProvisionGuard {
            active: Arc::clone(&self.active),
        })
    }

    pub fn is_active(&self) -> bool {
        self.active_lock().is_some()
    }

    pub fn active_service(&self) -> Option<String> {
        self.active_lock().as_ref().map(|a| a.service.clone())
    }

    fn active_lock(&self) -> std::sync::MutexGuard<'_, Option<ActiveProvision>> {
        match self.active.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("provisioner mutex poisoned; resetting");
                let mut guard = poisoned.into_inner();
                *guard = None;
                guard
            }
        }
    }
}

#[derive(Debug)]
pub struct ProvisionGuard {
    active: Arc<Mutex<Option<ActiveProvision>>>,
}

impl Drop for ProvisionGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.active.lock() {
            *guard = None;
        } else if let Ok(mut guard) = self.active.clear_poison_and_lock() {
            *guard = None;
        }
    }
}

/// Best-effort dump of subprocess output to `~/.agentkeys/logs/provision-<service>-<ts>.log`.
/// Returns the file path if the write succeeded. Never errors — failure to write the log
/// must not mask the underlying provision failure.
fn write_provision_log(service: &str, outcome: &SubprocessOutcome) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok().map(PathBuf::from)?;
    let dir = home.join(".agentkeys").join("logs");
    std::fs::create_dir_all(&dir).ok()?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let safe_service: String = service
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let path = dir.join(format!("provision-{}-{}.log", safe_service, ts));

    let mut body = String::new();
    body.push_str(&format!(
        "service: {}\nexit_code: {:?}\nevents_emitted: {}\n\n=== subprocess stdout events ===\n",
        service,
        outcome.exit_code,
        outcome.events.len()
    ));
    for ev in &outcome.events {
        body.push_str(&format!("{:?}\n", ev));
    }
    body.push_str("\n=== subprocess stderr ===\n");
    body.push_str(&outcome.stderr);

    std::fs::write(&path, body).ok()?;
    Some(path)
}

/// Returns first 8 chars + `****...` + last 4. For keys shorter than 12 chars returns `****`.
pub fn mask_key(key: &str) -> String {
    if key.len() < 12 {
        return "****".to_string();
    }
    format!("{}****...{}", &key[..8], &key[key.len() - 4..])
}

#[derive(Debug, Clone)]
pub struct ProvisionSuccess {
    pub obtained_key_masked: String,
    pub key_verified: bool,
    pub stored: bool,
}

/// Placeholder re-verify: always returns Ok(true).
/// Real re-verification via a trait method is tracked in progress.txt.
fn re_verify_existing(_key: &str) -> bool {
    true
}

fn event_to_error(code: &agentkeys_types::ProvisionErrorCode, details: &str) -> ProvisionError {
    use agentkeys_types::ProvisionErrorCode;
    match code {
        ProvisionErrorCode::ProvisionInProgress => ProvisionError::InProgress {
            active_service: details.to_string(),
        },
        ProvisionErrorCode::TripwireExhausted => ProvisionError::Tripwire {
            kind: TripwireKind::SelectorTimeout,
            step: details.to_string(),
            elapsed_ms: 0,
        },
        ProvisionErrorCode::StoreFailed => ProvisionError::StoreFailed {
            obtained_key_masked: "****".to_string(),
            source: anyhow::anyhow!("{}", details),
        },
        ProvisionErrorCode::VerificationEndpointDown => ProvisionError::VerificationEndpointDown {
            service: details.to_string(),
        },
        _ => ProvisionError::Internal(details.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_provision(
    provisioner: &Provisioner,
    service: &str,
    script_command: &[&str],
    env: HashMap<String, String>,
    cwd: Option<&Path>,
    backend: Arc<dyn CredentialBackend>,
    session: &Session,
    agent_id: &WalletAddress,
    force: bool,
) -> ProvisionResult<ProvisionSuccess> {
    let started_at = Instant::now();
    let service_name = ServiceName(service.to_string());

    if !force {
        let existing = backend
            .read_credential(session, agent_id, &service_name)
            .await;
        if let Ok(existing_bytes) = existing {
            let existing_key = String::from_utf8_lossy(&existing_bytes).to_string();
            if re_verify_existing(&existing_key) {
                return Ok(ProvisionSuccess {
                    obtained_key_masked: mask_key(&existing_key),
                    key_verified: true,
                    stored: false,
                });
            }
        }
    }

    let _guard = provisioner.try_claim(service)?;

    let outcome = spawn_and_collect(script_command, env, cwd, SubprocessConfig::default()).await?;

    let mut api_key: Option<String> = None;
    for event in &outcome.events {
        match event {
            ProvisionEvent::Tripwire { kind, step, elapsed_ms } => {
                metrics::emit(&ProvisionMetric::TripWireFired {
                    service: service.to_string(),
                    kind: format!("{kind:?}"),
                    step: step.clone(),
                });
                return Err(ProvisionError::Tripwire {
                    kind: kind.clone(),
                    step: step.clone(),
                    elapsed_ms: *elapsed_ms,
                });
            }
            ProvisionEvent::Error { code, details } => {
                return Err(event_to_error(code, details));
            }
            ProvisionEvent::Success { api_key: key } => {
                api_key = Some(key.clone());
            }
            ProvisionEvent::Progress { .. } => {}
        }
    }

    let raw_key = api_key.ok_or_else(|| {
        let stderr_tail: String = outcome
            .stderr
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        let log_hint = match write_provision_log(service, &outcome) {
            Some(path) => format!("full log: {}", path.display()),
            None => "full log: (unable to write ~/.agentkeys/logs — check HOME + permissions)".to_string(),
        };
        ProvisionError::Internal(format!(
            "subprocess ended without terminal event (exit {:?}). {}. stderr tail:\n{}",
            outcome.exit_code,
            log_hint,
            if stderr_tail.is_empty() { "(empty)" } else { stderr_tail.as_str() }
        ))
    })?;

    let masked = mask_key(&raw_key);

    backend
        .store_credential(session, agent_id, &service_name, raw_key.as_bytes())
        .await
        .map_err(|e| ProvisionError::StoreFailed {
            obtained_key_masked: masked.clone(),
            source: anyhow::anyhow!("{}", e),
        })?;

    let duration_secs = started_at.elapsed().as_secs_f64();
    metrics::emit(&ProvisionMetric::TierUsed { service: service.to_string(), tier: 2 });
    metrics::emit(&ProvisionMetric::DurationSeconds {
        service: service.to_string(),
        seconds: duration_secs,
    });
    metrics::emit(&ProvisionMetric::VerificationResult {
        service: service.to_string(),
        result: VerificationResultLabel::Valid,
    });

    Ok(ProvisionSuccess {
        obtained_key_masked: masked,
        key_verified: true,
        stored: true,
    })
}

trait MutexExt<T> {
    fn clear_poison_and_lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, T>>;
}

impl<T> MutexExt<T> for Mutex<T> {
    fn clear_poison_and_lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, T>> {
        self.clear_poison();
        self.lock()
    }
}

#[cfg(test)]
mod orchestrate {
    use super::*;
    use agentkeys_core::backend::BackendError;
    use agentkeys_types::{
        AuditEvent, AuditFilter, AuthRequest, AuthRequestId, AuthRequestType, CanonicalBytes,
        EncryptedPairPayload, OpenedAuthRequest, PairCode, PairPayload, PublicKey,
        RegistrationToken, Scope, ServiceName, Session, SignedAuthDecision, WalletAddress,
    };
    use async_trait::async_trait;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    fn test_session() -> Session {
        Session {
            token: "test-token".to_string(),
            wallet: WalletAddress("0xtest".to_string()),
            scope: None,
            created_at: 0,
            ttl_seconds: 86400,
        }
    }

    struct TestBackend {
        read_result: Mutex<Option<Vec<u8>>>,
        store_should_fail: bool,
        store_called: AtomicBool,
    }

    impl TestBackend {
        fn new_empty() -> Self {
            Self {
                read_result: Mutex::new(None),
                store_should_fail: false,
                store_called: AtomicBool::new(false),
            }
        }

        fn new_with_existing(key: &str) -> Self {
            Self {
                read_result: Mutex::new(Some(key.as_bytes().to_vec())),
                store_should_fail: false,
                store_called: AtomicBool::new(false),
            }
        }

        fn new_store_fails_empty() -> Self {
            Self {
                read_result: Mutex::new(None),
                store_should_fail: true,
                store_called: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl CredentialBackend for TestBackend {
        async fn read_credential(
            &self,
            _session: &Session,
            _agent_id: &WalletAddress,
            _service: &ServiceName,
        ) -> Result<Vec<u8>, BackendError> {
            let guard = self.read_result.lock().unwrap();
            match guard.as_ref() {
                Some(bytes) => Ok(bytes.clone()),
                None => Err(BackendError::NotFound("no credential".to_string())),
            }
        }

        async fn store_credential(
            &self,
            _session: &Session,
            _agent_id: &WalletAddress,
            _service: &ServiceName,
            _ciphertext: &[u8],
        ) -> Result<(), BackendError> {
            self.store_called.store(true, Ordering::SeqCst);
            if self.store_should_fail {
                Err(BackendError::Internal("store failed".to_string()))
            } else {
                Ok(())
            }
        }

        async fn create_session(&self, _: agentkeys_types::AuthToken) -> Result<(Session, WalletAddress), BackendError> { unimplemented!() }
        async fn create_child_session(&self, _: &Session, _: Scope) -> Result<(Session, WalletAddress), BackendError> { unimplemented!() }
        async fn query_audit(&self, _: &Session, _: AuditFilter) -> Result<Vec<AuditEvent>, BackendError> { unimplemented!() }
        async fn revoke_session(&self, _: &Session, _: &Session) -> Result<(), BackendError> { unimplemented!() }
        async fn revoke_by_wallet(&self, _: &Session, _: &WalletAddress) -> Result<(), BackendError> { unimplemented!() }
        async fn teardown_agent(&self, _: &Session, _: &WalletAddress) -> Result<(), BackendError> { unimplemented!() }
        async fn shielding_key(&self) -> Result<PublicKey, BackendError> { unimplemented!() }
        async fn register_rendezvous(&self, _: &PublicKey, _: &PairCode) -> Result<RegistrationToken, BackendError> { unimplemented!() }
        async fn poll_rendezvous(&self, _: &RegistrationToken) -> Result<Option<PairPayload>, BackendError> { unimplemented!() }
        async fn deliver_rendezvous(&self, _: &Session, _: &PairCode, _: &EncryptedPairPayload) -> Result<(), BackendError> { unimplemented!() }
        async fn open_auth_request(&self, _: &PublicKey, _: AuthRequestType, _: &CanonicalBytes, _: Option<&WalletAddress>) -> Result<OpenedAuthRequest, BackendError> { unimplemented!() }
        async fn fetch_auth_request(&self, _: &Session, _: &PairCode) -> Result<AuthRequest, BackendError> { unimplemented!() }
        async fn approve_auth_request(&self, _: &Session, _: &AuthRequestId) -> Result<(), BackendError> { unimplemented!() }
        async fn await_auth_decision(&self, _: &AuthRequestId) -> Result<SignedAuthDecision, BackendError> { unimplemented!() }
        async fn recover_session(&self, _: &agentkeys_types::AgentIdentity, _: &agentkeys_types::RecoveryMethod) -> Result<(Session, WalletAddress), BackendError> { unimplemented!() }
        async fn list_credentials(&self, _: &Session, _: &WalletAddress) -> Result<Vec<ServiceName>, BackendError> { unimplemented!() }
        async fn resolve_identity(&self, _: &Session, _: &str) -> Result<WalletAddress, BackendError> { unimplemented!() }
        async fn get_scope(&self, _: &Session, _: &WalletAddress) -> Result<Option<Scope>, BackendError> { unimplemented!() }
        async fn update_scope(&self, _: &Session, _: &WalletAddress, _: &Scope) -> Result<(), BackendError> { unimplemented!() }
        async fn provision_inbox(&self, _: &Session, _: &WalletAddress) -> Result<agentkeys_types::InboxAddress, BackendError> { unimplemented!() }
        async fn list_inboxes(&self, _: &Session, _: &WalletAddress) -> Result<Vec<agentkeys_types::InboxAddress>, BackendError> { unimplemented!() }
    }

    #[tokio::test]
    async fn stores_credential() {
        let backend = Arc::new(TestBackend::new_empty());
        let provisioner = Provisioner::new();
        let session = test_session();
        let agent_id = WalletAddress("0xtest".to_string());

        let script = r#"printf '{"type":"progress","step":"creating_account"}\n'; printf '{"type":"success","api_key":"sk-or-v1-realkey12345abcd"}\n'"#;
        let cmd: Vec<&str> = vec!["sh", "-c", script];

        let result = run_provision(
            &provisioner,
            "openrouter",
            &cmd,
            HashMap::new(),
            None,
            backend.clone(),
            &session,
            &agent_id,
            true,
        )
        .await;

        assert!(result.is_ok(), "expected success: {:?}", result.err());
        let success = result.unwrap();
        assert!(success.stored);
        assert!(success.key_verified);
        assert!(backend.store_called.load(Ordering::SeqCst));
        assert!(!success.obtained_key_masked.contains("realkey12345abcd"), "masked key must not contain full raw key");
    }

    #[tokio::test]
    async fn duplicate_provision_skips_subprocess() {
        let existing_key = "sk-or-v1-existingkey1234";
        let backend = Arc::new(TestBackend::new_with_existing(existing_key));
        let provisioner = Provisioner::new();
        let session = test_session();
        let agent_id = WalletAddress("0xtest".to_string());

        // Sentinel script that would fail if actually spawned
        let cmd: Vec<&str> = vec!["sh", "-c", "exit 99"];

        let result = run_provision(
            &provisioner,
            "openrouter",
            &cmd,
            HashMap::new(),
            None,
            backend.clone(),
            &session,
            &agent_id,
            false,
        )
        .await;

        assert!(result.is_ok(), "expected success: {:?}", result.err());
        let success = result.unwrap();
        assert!(!success.stored, "should not store when duplicate");
        assert!(success.key_verified);
        assert!(!backend.store_called.load(Ordering::SeqCst), "store should not be called for duplicate");
    }

    #[tokio::test]
    async fn force_reprovisions_despite_existing() {
        let existing_key = "sk-or-v1-existingkey1234";
        let backend = Arc::new(TestBackend::new_with_existing(existing_key));
        let provisioner = Provisioner::new();
        let session = test_session();
        let agent_id = WalletAddress("0xtest".to_string());

        let script = r#"printf '{"type":"success","api_key":"sk-or-v1-newkeyabcdefgh"}\n'"#;
        let cmd: Vec<&str> = vec!["sh", "-c", script];

        let result = run_provision(
            &provisioner,
            "openrouter",
            &cmd,
            HashMap::new(),
            None,
            backend.clone(),
            &session,
            &agent_id,
            true,
        )
        .await;

        assert!(result.is_ok(), "expected success: {:?}", result.err());
        let success = result.unwrap();
        assert!(success.stored, "should store on force re-provision");
        assert!(backend.store_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn store_fails_after_verify() {
        let backend = Arc::new(TestBackend::new_store_fails_empty());
        let provisioner = Provisioner::new();
        let session = test_session();
        let agent_id = WalletAddress("0xtest".to_string());

        let script = r#"printf '{"type":"success","api_key":"sk-or-v1-newkeyabcdefgh"}\n'"#;
        let cmd: Vec<&str> = vec!["sh", "-c", script];

        let result = run_provision(
            &provisioner,
            "openrouter",
            &cmd,
            HashMap::new(),
            None,
            backend.clone(),
            &session,
            &agent_id,
            true,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ProvisionError::StoreFailed { obtained_key_masked, .. } => {
                assert!(!obtained_key_masked.is_empty(), "masked key should not be empty for recovery");
            }
            other => panic!("expected StoreFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn verification_failure_aborts() {
        let backend = Arc::new(TestBackend::new_store_fails_empty());
        let provisioner = Provisioner::new();
        let session = test_session();
        let agent_id = WalletAddress("0xtest".to_string());

        let script = r#"printf '{"type":"tripwire","kind":"verification_failed","step":"verify","elapsed_ms":500}\n'"#;
        let cmd: Vec<&str> = vec!["sh", "-c", script];

        let result = run_provision(
            &provisioner,
            "openrouter",
            &cmd,
            HashMap::new(),
            None,
            backend.clone(),
            &session,
            &agent_id,
            true,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ProvisionError::Tripwire { kind, .. } => {
                assert_eq!(kind, TripwireKind::VerificationFailed);
            }
            other => panic!("expected Tripwire, got {:?}", other),
        }
        assert!(!backend.store_called.load(Ordering::SeqCst), "store must not be called after tripwire");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn concurrent_provision_rejected() {
        let p = Provisioner::new();
        let _guard = p.try_claim("openrouter").unwrap();
        let err = p.try_claim("brave").unwrap_err();
        match err {
            ProvisionError::InProgress { active_service } => {
                assert_eq!(active_service, "openrouter");
            }
            _ => panic!("expected InProgress, got {:?}", err),
        }
    }

    #[test]
    fn guard_releases_on_drop() {
        let p = Provisioner::new();
        {
            let _guard = p.try_claim("openrouter").unwrap();
            assert!(p.is_active());
        }
        assert!(!p.is_active());
        let _guard = p.try_claim("brave").unwrap();
        assert_eq!(p.active_service(), Some("brave".into()));
    }

    #[test]
    fn mutex_recovery_after_panic() {
        let p = Provisioner::new();
        let p_clone = p.clone();
        let handle = thread::spawn(move || {
            let _guard = p_clone.try_claim("openrouter").unwrap();
            panic!("simulated panic inside provision");
        });
        let _ = handle.join();
        assert!(
            !p.is_active(),
            "after panic + guard drop the mutex should be unclaimed"
        );
        let guard2 = p.try_claim("brave");
        assert!(guard2.is_ok(), "third call must proceed after panic recovery");
    }
}
