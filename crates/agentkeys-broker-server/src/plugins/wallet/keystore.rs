//! `ClientSideKeystoreProvisioner` — Phase 0 wallet layer.
//!
//! The MetaMask model: the broker stores ONLY the wallet address and
//! associated metadata. The user holds the seed (BIP-39 mnemonic) in their
//! OS keychain on the daemon side. The broker has no key material it could
//! leak, no migration path to lose, and no signing capability — every
//! authenticated request from this user must arrive with a per-call
//! signature (US-011) from the daemon's local key.
//!
//! Stage 7 plan §3.5.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use super::{
    VerifiedIdentity, WalletAddress, WalletBinding, WalletError, WalletProvisioner, WalletRole,
};
use crate::plugins::Readiness;
use crate::storage::WalletStore;

const PLUGIN_NAME: &str = "client_keystore";

/// In-memory handle wrapping a `WalletStore`.
pub struct ClientSideKeystoreProvisioner {
    store: Arc<WalletStore>,
}

impl ClientSideKeystoreProvisioner {
    pub fn new(store: Arc<WalletStore>) -> Self {
        Self { store }
    }

    /// Convenience constructor for tests.
    #[cfg(test)]
    pub fn with_in_memory_store() -> Result<Self, WalletError> {
        Ok(Self::new(Arc::new(WalletStore::open_in_memory()?)))
    }
}

#[async_trait]
impl WalletProvisioner for ClientSideKeystoreProvisioner {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn ready(&self) -> Readiness {
        if self.store.writable() {
            Readiness::ready_with("client-side keystore: wallets table writable")
        } else {
            Readiness::unready("wallets table not writable")
        }
    }

    async fn bind_address(
        &self,
        _identity: &VerifiedIdentity,
        omni_account: &str,
        address: WalletAddress,
        role: WalletRole,
        parent_address: Option<WalletAddress>,
    ) -> Result<WalletBinding, WalletError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.store
            .bind(omni_account, &address, role, parent_address.as_ref(), now)
    }

    async fn lookup_by_omni_account(
        &self,
        omni_account: &str,
    ) -> Result<Vec<WalletBinding>, WalletError> {
        self.store.list_for_omni_account(omni_account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::auth::IdentityType;

    fn identity() -> VerifiedIdentity {
        VerifiedIdentity {
            identity_type: IdentityType::Evm,
            identity_value: "0xabcdef0123456789abcdef0123456789abcdef00".into(),
        }
    }

    #[tokio::test]
    async fn bind_then_lookup_round_trip() {
        let p = ClientSideKeystoreProvisioner::with_in_memory_store().unwrap();
        let addr = WalletAddress::parse("0xabcdef0123456789abcdef0123456789abcdef00").unwrap();
        let omni = "0".repeat(64);

        let binding = p
            .bind_address(&identity(), &omni, addr.clone(), WalletRole::Master, None)
            .await
            .unwrap();
        assert_eq!(binding.address, addr);
        assert_eq!(binding.role, WalletRole::Master);
        assert!(binding.parent_address.is_none());

        let found = p.lookup_by_omni_account(&omni).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], binding);
    }

    #[tokio::test]
    async fn rebind_same_role_is_idempotent() {
        let p = ClientSideKeystoreProvisioner::with_in_memory_store().unwrap();
        let addr = WalletAddress::parse("0xabcdef0123456789abcdef0123456789abcdef00").unwrap();
        let omni = "1".repeat(64);

        let first = p
            .bind_address(&identity(), &omni, addr.clone(), WalletRole::Master, None)
            .await
            .unwrap();
        let second = p
            .bind_address(&identity(), &omni, addr.clone(), WalletRole::Master, None)
            .await
            .unwrap();

        // Same row returned (created_at preserved).
        assert_eq!(first.address, second.address);
        assert_eq!(first.role, second.role);
        assert_eq!(first.created_at, second.created_at);

        // Only one row in storage.
        let all = p.lookup_by_omni_account(&omni).await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn rebind_different_role_is_rejected() {
        let p = ClientSideKeystoreProvisioner::with_in_memory_store().unwrap();
        let addr = WalletAddress::parse("0xabcdef0123456789abcdef0123456789abcdef00").unwrap();
        let omni = "2".repeat(64);

        p.bind_address(&identity(), &omni, addr.clone(), WalletRole::Master, None)
            .await
            .unwrap();
        let result = p
            .bind_address(&identity(), &omni, addr.clone(), WalletRole::Daemon, None)
            .await;
        assert!(matches!(result, Err(WalletError::Storage(_))));
    }

    #[tokio::test]
    async fn ready_reports_ready() {
        let p = ClientSideKeystoreProvisioner::with_in_memory_store().unwrap();
        assert!(p.ready().is_ready());
    }

    #[tokio::test]
    async fn name_is_stable() {
        let p = ClientSideKeystoreProvisioner::with_in_memory_store().unwrap();
        assert_eq!(p.name(), "client_keystore");
    }

    #[tokio::test]
    async fn lookup_returns_multiple_bindings_for_same_omni() {
        let p = ClientSideKeystoreProvisioner::with_in_memory_store().unwrap();
        let omni = "3".repeat(64);
        let master = WalletAddress::parse("0x1111111111111111111111111111111111111111").unwrap();
        let daemon = WalletAddress::parse("0x2222222222222222222222222222222222222222").unwrap();

        p.bind_address(&identity(), &omni, master.clone(), WalletRole::Master, None)
            .await
            .unwrap();
        p.bind_address(
            &identity(),
            &omni,
            daemon.clone(),
            WalletRole::Daemon,
            Some(master.clone()),
        )
        .await
        .unwrap();

        let bindings = p.lookup_by_omni_account(&omni).await.unwrap();
        assert_eq!(bindings.len(), 2);
        let daemon_binding = bindings.iter().find(|b| b.address == daemon).unwrap();
        assert_eq!(daemon_binding.role, WalletRole::Daemon);
        assert_eq!(daemon_binding.parent_address.as_ref().unwrap(), &master);
    }
}
