use crate::broker::{BrokerClient, BrokerError};
use agentkeys_protocol::auth::*;

type Result<T> = std::result::Result<T, BrokerError>;

impl BrokerClient {
    pub async fn email_request(&self, email: &str) -> Result<EmailChallenge> {
        self.post_json(
            "/v1/auth/email/request",
            None,
            &EmailRequest {
                email: email.trim().to_lowercase(),
                source_ip: None,
            },
        )
        .await
    }

    pub async fn hosted_email_request(&self, email: &str) -> Result<EmailChallenge> {
        self.require_private_login().await?;
        self.email_request(email).await
    }

    async fn require_private_login(&self) -> Result<LoginConfig> {
        let config = self.login_config().await?;
        if !config.email_allowlist_enabled {
            return Err(BrokerError::Rejected {
                endpoint: "/v1/auth/config".into(),
                status: 403,
                body: "Hosted sign-in is closed until the email allowlist is configured.".into(),
            });
        }
        Ok(config)
    }

    pub async fn email_status(&self, request_id: &str) -> Result<EmailStatus> {
        if request_id.is_empty()
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(BrokerError::Decode("invalid email request id".into()));
        }
        self.get_json(&format!("/v1/auth/email/status/{request_id}"), None)
            .await
    }

    pub async fn login_config(&self) -> Result<LoginConfig> {
        self.get_json("/v1/auth/config", None).await
    }

    pub async fn session_info(&self, bearer: &str) -> Result<MasterSessionInfo> {
        self.get_json("/v1/auth/session", Some(bearer)).await
    }

    pub async fn finish_identity_session(
        &self,
        signer_url: &str,
        identity_jwt: &str,
        identity_omni: &str,
        chain_id: u64,
    ) -> Result<MasterSession> {
        let signer = BrokerClient::new(signer_url);
        let derived: DerivedAddress = signer
            .post_json(
                "/dev/derive-address",
                Some(identity_jwt),
                &DeriveAddressRequest {
                    omni_account: identity_omni.into(),
                },
            )
            .await?;
        let _: serde_json::Value = self
            .post_json(
                "/v1/wallet/link",
                Some(identity_jwt),
                &WalletLink {
                    identity_type: "evm".into(),
                    identity_value: derived.address.clone(),
                },
            )
            .await?;
        let challenge: WalletChallenge = self
            .post_json(
                "/v1/auth/wallet/start",
                None,
                &WalletStart {
                    address: derived.address.clone(),
                    chain_id,
                    source_ip: None,
                },
            )
            .await?;
        let signed: SignedMessage = signer
            .post_json(
                "/dev/sign-message",
                Some(identity_jwt),
                &SignMessageRequest {
                    omni_account: identity_omni.into(),
                    message_hex: hex::encode(challenge.siwe_message.as_bytes()),
                },
            )
            .await?;
        if !derived.address.eq_ignore_ascii_case(&signed.address)
            || derived.key_version != signed.key_version
        {
            return Err(BrokerError::Decode(
                "signer identity changed during login".into(),
            ));
        }
        let session: MasterSession = self
            .post_json(
                "/v1/auth/wallet/verify",
                None,
                &WalletVerify {
                    request_id: challenge.request_id,
                    signature: signed.signature,
                },
            )
            .await?;
        if !session
            .wallet_address
            .eq_ignore_ascii_case(&derived.address)
        {
            return Err(BrokerError::Decode(
                "session wallet differs from verified signer".into(),
            ));
        }
        Ok(session)
    }

    pub async fn finish_email_login(&self, request_id: &str) -> Result<Option<MasterSession>> {
        match self.email_status(request_id).await? {
            EmailStatus::Pending => Ok(None),
            EmailStatus::Failed { reason } => Err(BrokerError::Rejected {
                endpoint: "/v1/auth/email/status".into(),
                status: 401,
                body: reason,
            }),
            EmailStatus::Verified {
                session_jwt,
                omni_account,
                ..
            } => {
                let config = self.require_private_login().await?;
                let chain_id = config
                    .chain_id
                    .parse()
                    .map_err(|_| BrokerError::Decode("invalid chain id".into()))?;
                self.finish_identity_session(
                    &config.signer_url,
                    &session_jwt,
                    &omni_account,
                    chain_id,
                )
                .await
                .map(Some)
            }
        }
    }
}
