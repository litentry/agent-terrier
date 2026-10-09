use crate::broker::{BrokerClient, BrokerError};
use agentkeys_protocol::hosted_signer::*;
use agentkeys_protocol::{
    BuildAcceptUserOpResponse, SubmitAcceptUserOpRequest, SubmitAcceptUserOpResponse,
};

impl BrokerClient {
    pub async fn hosted_signer_start(
        &self,
        bearer: &str,
        request: &HostedSignerStartRequest,
    ) -> Result<HostedSignerChallenge, BrokerError> {
        self.post_json("/v1/hosted/signer/start", Some(bearer), request)
            .await
    }
    pub async fn hosted_signer_prepare(
        &self,
        bearer: &str,
        request: &HostedSignerApproval,
    ) -> Result<HostedSignerChallenge, BrokerError> {
        self.post_json("/v1/hosted/signer/prepare", Some(bearer), request)
            .await
    }
    pub async fn hosted_signer_build(
        &self,
        bearer: &str,
        request: &HostedSignerBuildRequest,
    ) -> Result<BuildAcceptUserOpResponse, BrokerError> {
        self.post_json("/v1/hosted/signer/build", Some(bearer), request)
            .await
    }
    pub async fn hosted_signer_status(
        &self,
        bearer: &str,
        request: &HostedSignerStatusRequest,
    ) -> Result<HostedSignerStatus, BrokerError> {
        self.post_json("/v1/hosted/signer/status", Some(bearer), request)
            .await
    }
    pub async fn hosted_signer_submit(
        &self,
        bearer: &str,
        request: &SubmitAcceptUserOpRequest,
    ) -> Result<SubmitAcceptUserOpResponse, BrokerError> {
        self.post_json("/v1/accept/submit", Some(bearer), request)
            .await
    }
    pub async fn hosted_passkey_start(
        &self,
        omni: &str,
    ) -> Result<HostedPasskeyChallenge, BrokerError> {
        self.post_json(
            "/v1/auth/passkey/start",
            None,
            &HostedPasskeyStart {
                omni_account: omni.into(),
            },
        )
        .await
    }
    pub async fn hosted_passkey_finish(
        &self,
        request: &HostedPasskeyVerify,
    ) -> Result<agentkeys_protocol::auth::MasterSession, BrokerError> {
        let verified: HostedPasskeySession = self
            .post_json("/v1/auth/passkey/verify", None, request)
            .await?;
        Ok(agentkeys_protocol::auth::MasterSession {
            session_jwt: verified.session_jwt,
            omni_account: verified.omni_account,
            wallet_address: String::new(),
            expires_at: verified.expires_at,
        })
    }
}

impl BrokerClient {
    pub async fn hosted_signer_publish(
        &self,
        bearer: &str,
        request: &HostedSignerApproval,
    ) -> Result<HostedSignerRequest, BrokerError> {
        self.post_json("/v1/hosted/signer/publish", Some(bearer), request)
            .await
    }
    pub async fn hosted_signer_pending(
        &self,
        bearer: &str,
    ) -> Result<HostedSignerPending, BrokerError> {
        self.get_json("/v1/hosted/signer/pending", Some(bearer))
            .await
    }
    pub async fn hosted_signer_dismiss(
        &self,
        bearer: &str,
        request: &HostedSignerRequestId,
    ) -> Result<serde_json::Value, BrokerError> {
        self.post_json("/v1/hosted/signer/dismiss", Some(bearer), request)
            .await
    }
}
