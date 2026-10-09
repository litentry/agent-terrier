use std::collections::BTreeSet;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    error::BrokerError, handlers::accept::norm_omni, identity::derive_with_client_id,
    state::SharedState,
};

#[derive(Clone, Debug, Default)]
pub struct LoginAccess {
    emails: Option<BTreeSet<String>>,
}

impl LoginAccess {
    pub fn restricted(spec: &str) -> Result<Self, String> {
        let mut emails = BTreeSet::new();
        for entry in spec.split(',').filter(|entry| !entry.trim().is_empty()) {
            let email = entry.trim().to_lowercase();
            if email.contains(char::is_whitespace)
                || email.contains('*')
                || email.matches('@').count() != 1
                || email.starts_with('@')
                || email.ends_with('@')
            {
                return Err(
                    "BROKER_MASTER_LOGIN_ALLOWLIST must contain exact email addresses".into(),
                );
            }
            emails.insert(email);
        }
        Ok(Self {
            emails: Some(emails),
        })
    }

    pub fn is_restricted(&self) -> bool {
        self.emails.is_some()
    }

    fn linked_omnis(&self, state: &SharedState, email: &str) -> Result<Vec<String>, BrokerError> {
        let identity_omni = derive_with_client_id(&state.config.client_id, "email", email);
        let links = state
            .identity_link_store
            .list_for_master(identity_omni.as_str())
            .map_err(|_| BrokerError::Internal("identity lookup unavailable".into()))?;
        Ok(links
            .into_iter()
            .filter(|link| link.identity_type == "evm")
            .map(|link| {
                derive_with_client_id(
                    &state.config.client_id,
                    "evm",
                    &link.identity_value.to_lowercase(),
                )
                .to_string()
            })
            .collect())
    }

    pub fn require_email(&self, email: &str) -> Result<(), BrokerError> {
        let Some(emails) = &self.emails else {
            return Ok(());
        };
        let email = email.trim().to_lowercase();
        if !emails.contains(&email) {
            return Err(denied());
        }
        Ok(())
    }

    pub async fn require_omni(&self, state: &SharedState, omni: &str) -> Result<(), BrokerError> {
        let Some(emails) = &self.emails else {
            return Ok(());
        };
        for email in emails {
            if self
                .linked_omnis(state, email)?
                .iter()
                .any(|linked| norm_omni(linked) == norm_omni(omni))
            {
                return Ok(());
            }
        }
        Err(denied())
    }
}

pub fn denied() -> BrokerError {
    BrokerError::Forbidden(
        "Access is limited to approved email addresses. Contact the administrator for access."
            .into(),
    )
}

pub async fn enforce(State(state): State<SharedState>, request: Request, next: Next) -> Response {
    let access = &state.config.login_access;
    if !access.is_restricted() {
        return next.run(request).await;
    }
    let path = request.uri().path();
    if path.starts_with("/v1/auth/oauth2/") || path == "/auth/oauth2/callback" {
        return denied().into_response();
    }
    if let Some(token) = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(crate::auth::extract_bearer_token)
    {
        if let Ok(claims) = crate::jwt::verify::verify_session_jwt(
            &state.session_keypair,
            &state.config.oidc_issuer,
            token,
        ) {
            let identity = &claims.agentkeys;
            let result = if let Some(parent) = &identity.parent_omni {
                access.require_omni(&state, parent).await
            } else if identity.identity_type == "email" {
                access.require_email(&identity.identity_value)
            } else {
                access.require_omni(&state, &identity.omni_account).await
            };
            if let Err(error) = result {
                return error.into_response();
            }
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_addresses_only_and_explicit_empty_denies_all() {
        let policy = LoginAccess::restricted(" Alice@Example.test ,alice@example.test").unwrap();
        assert_eq!(policy.emails.unwrap().len(), 1);
        assert!(LoginAccess::restricted("").unwrap().is_restricted());
        for invalid in [
            "*",
            "*@example.test",
            "alice",
            "@example.test",
            "a@@b",
            "a b@example.test",
        ] {
            assert!(LoginAccess::restricted(invalid).is_err());
        }
    }
}
