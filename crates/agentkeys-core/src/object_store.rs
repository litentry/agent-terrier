use std::{sync::Arc, time::Duration};

use agentkeys_protocol::{
    capability::CapToken,
    object_store::{
        ObjectAction, ObjectErrorBody, ObjectRequest, ObjectResponse, MAX_LIST_KEYS,
        MAX_OBJECT_BYTES, OBJECT_NOT_FOUND, OBJECT_REVISION_CONFLICT, OBJECT_ROUTE,
    },
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = MAX_OBJECT_BYTES.div_ceil(3) * 4 + 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ObjectError {
    #[error("object access denied")]
    Denied,
    #[error("object not found")]
    NotFound,
    #[error("object revision conflict")]
    Conflict,
    #[error("invalid object request")]
    InvalidRequest,
    #[error("object service unavailable")]
    Unavailable,
    #[error("invalid object service response")]
    InvalidResponse,
}

#[async_trait]
/// Adapters independently enforce current capability authority on every operation.
pub trait ObjectStore: Send + Sync {
    async fn execute(&self, request: ObjectRequest) -> Result<ObjectResponse, ObjectError>;
}

pub struct HttpObjectStore {
    http: reqwest::Client,
    endpoint: reqwest::Url,
}

impl HttpObjectStore {
    pub fn new(base_url: &str) -> Result<Self, ObjectError> {
        let mut endpoint =
            reqwest::Url::parse(base_url).map_err(|_| ObjectError::InvalidRequest)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(ObjectError::InvalidRequest);
        }
        endpoint.set_path(OBJECT_ROUTE);
        Ok(Self {
            endpoint,
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(REQUEST_TIMEOUT)
                .build()
                .map_err(|_| ObjectError::Unavailable)?,
        })
    }
}

#[async_trait]
impl ObjectStore for HttpObjectStore {
    async fn execute(&self, request: ObjectRequest) -> Result<ObjectResponse, ObjectError> {
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .json(&request)
            .send()
            .await
            .map_err(|_| ObjectError::Unavailable)?;
        match response.status().as_u16() {
            200 => {}
            400 | 413 | 422 => return Err(ObjectError::InvalidRequest),
            401 | 403 => return Err(ObjectError::Denied),
            status @ (404 | 409) => {
                let bytes = response_bytes(&mut response, 1024).await?;
                let error: ObjectErrorBody =
                    serde_json::from_slice(&bytes).map_err(|_| ObjectError::Unavailable)?;
                return Err(match (status, error.code.as_str()) {
                    (404, OBJECT_NOT_FOUND) => ObjectError::NotFound,
                    (409, OBJECT_REVISION_CONFLICT) => ObjectError::Conflict,
                    _ => ObjectError::Unavailable,
                });
            }
            _ => return Err(ObjectError::Unavailable),
        }
        let bytes = response_bytes(&mut response, MAX_RESPONSE_BYTES).await?;
        serde_json::from_slice(&bytes).map_err(|_| ObjectError::InvalidResponse)
    }
}

async fn response_bytes(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, ObjectError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ObjectError::InvalidResponse);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ObjectError::Unavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(ObjectError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Clone)]
pub struct ObjectClient {
    store: Arc<dyn ObjectStore>,
}

pub struct StoredObject {
    pub bytes: Vec<u8>,
    pub revision: String,
}

pub struct ObjectPage {
    pub keys: Vec<String>,
    pub next: Option<String>,
}

impl ObjectClient {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    pub fn http(base_url: &str) -> Result<Self, ObjectError> {
        Ok(Self::new(Arc::new(HttpObjectStore::new(base_url)?)))
    }

    pub async fn get(&self, cap: &CapToken, key: &str) -> Result<StoredObject, ObjectError> {
        let response = self
            .store
            .execute(request(cap, ObjectAction::Get, key))
            .await?;
        let bytes = STANDARD
            .decode(response.value_b64.ok_or(ObjectError::InvalidResponse)?)
            .map_err(|_| ObjectError::InvalidResponse)?;
        let revision = response.revision.ok_or(ObjectError::InvalidResponse)?;
        if bytes.len() > MAX_OBJECT_BYTES
            || revision != hex::encode(Sha256::digest(&bytes))
            || !response.keys.is_empty()
            || response.truncated
        {
            return Err(ObjectError::InvalidResponse);
        }
        Ok(StoredObject { bytes, revision })
    }

    pub async fn put(
        &self,
        cap: &CapToken,
        key: &str,
        bytes: &[u8],
        expected_revision: Option<&str>,
    ) -> Result<String, ObjectError> {
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(ObjectError::InvalidRequest);
        }
        let mut request = request(cap, ObjectAction::Put, key);
        request.value_b64 = Some(STANDARD.encode(bytes));
        request.expected_revision = expected_revision.map(str::to_owned);
        let response = self.store.execute(request).await?;
        let revision = hex::encode(Sha256::digest(bytes));
        if response.revision.as_deref() != Some(&revision)
            || response.value_b64.is_some()
            || !response.keys.is_empty()
            || response.truncated
        {
            return Err(ObjectError::InvalidResponse);
        }
        Ok(revision)
    }

    pub async fn delete(
        &self,
        cap: &CapToken,
        key: &str,
        expected_revision: Option<&str>,
    ) -> Result<(), ObjectError> {
        let mut request = request(cap, ObjectAction::Delete, key);
        request.expected_revision = expected_revision.map(str::to_owned);
        let response = self.store.execute(request).await?;
        if response.value_b64.is_some()
            || response.revision.is_some()
            || !response.keys.is_empty()
            || response.truncated
        {
            return Err(ObjectError::InvalidResponse);
        }
        Ok(())
    }

    pub async fn list(
        &self,
        cap: &CapToken,
        prefix: &str,
        after: Option<&str>,
    ) -> Result<ObjectPage, ObjectError> {
        let mut request = request(cap, ObjectAction::List, prefix);
        request.after = after.map(str::to_owned);
        let response = self.store.execute(request).await?;
        let mut previous = after.unwrap_or("");
        if response.value_b64.is_some()
            || response.revision.is_some()
            || response.keys.len() > MAX_LIST_KEYS
            || (response.truncated && response.keys.is_empty())
        {
            return Err(ObjectError::InvalidResponse);
        }
        for key in &response.keys {
            if !key.starts_with(prefix)
                || key.as_str() <= previous
                || agentkeys_protocol::object_store::validate_key(key, false).is_err()
            {
                return Err(ObjectError::InvalidResponse);
            }
            previous = key;
        }
        let next = response
            .truncated
            .then(|| response.keys.last().unwrap().clone());
        Ok(ObjectPage {
            keys: response.keys,
            next,
        })
    }
}

fn request(cap: &CapToken, action: ObjectAction, key: &str) -> ObjectRequest {
    ObjectRequest {
        cap: cap.clone(),
        action,
        key: key.into(),
        value_b64: None,
        expected_revision: None,
        after: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_protocol::capability::{CapOp, CapPayload, DataClass};
    use axum::{http::StatusCode, routing::post, Json, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    fn cap() -> CapToken {
        CapToken {
            payload: CapPayload {
                operator_omni: "11".repeat(32),
                actor_omni: "11".repeat(32),
                service: "example".into(),
                op: CapOp::Fetch,
                data_class: DataClass::Credentials,
                device_key_hash: "22".repeat(32),
                k3_epoch: 1,
                issued_at: 1,
                expires_at: 2,
                nonce: "synthetic".into(),
            },
            broker_sig: "synthetic".into(),
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        }
    }

    struct Reply(Mutex<serde_json::Value>);

    #[async_trait]
    impl ObjectStore for Reply {
        async fn execute(&self, _request: ObjectRequest) -> Result<ObjectResponse, ObjectError> {
            serde_json::from_value(self.0.lock().unwrap().clone())
                .map_err(|_| ObjectError::InvalidResponse)
        }
    }

    #[tokio::test]
    async fn validates_revisions_and_list_scope_order_progress() {
        let reply = Arc::new(Reply(Mutex::new(serde_json::json!({}))));
        let client = ObjectClient::new(reply.clone());
        let cap = cap();
        let prefix = format!("bots/{}/credentials/", cap.payload.actor_omni);
        let first = format!("{prefix}a.enc");
        let second = format!("{prefix}b.enc");
        *reply.0.lock().unwrap() = serde_json::json!({"keys":[first,second],"truncated":true});
        let page = client.list(&cap, &prefix, None).await.unwrap();
        assert_eq!(page.next.as_deref(), Some(second.as_str()));
        for malformed in [
            serde_json::json!({"keys":[second,first]}),
            serde_json::json!({"keys":[first,first]}),
            serde_json::json!({"keys":[],"truncated":true}),
            serde_json::json!({"keys":["bots/other/credentials/a.enc"]}),
            serde_json::json!({"keys":[format!("{prefix}../secret")]}),
        ] {
            *reply.0.lock().unwrap() = malformed;
            assert!(matches!(
                client.list(&cap, &prefix, None).await,
                Err(ObjectError::InvalidResponse)
            ));
        }
        *reply.0.lock().unwrap() = serde_json::json!({"keys":[first]});
        assert!(matches!(
            client.list(&cap, &prefix, Some(&first)).await,
            Err(ObjectError::InvalidResponse)
        ));
        let bytes = b"encrypted fixture";
        let revision = hex::encode(Sha256::digest(bytes));
        *reply.0.lock().unwrap() =
            serde_json::json!({"value_b64":STANDARD.encode(bytes),"revision":revision});
        assert_eq!(client.get(&cap, &first).await.unwrap().bytes, bytes);
        reply.0.lock().unwrap()["revision"] = "wrong".into();
        assert!(matches!(
            client.get(&cap, &first).await,
            Err(ObjectError::InvalidResponse)
        ));
        *reply.0.lock().unwrap() = serde_json::json!({"revision":revision});
        assert_eq!(
            client.put(&cap, &first, bytes, Some("")).await.unwrap(),
            revision
        );
        reply.0.lock().unwrap()["revision"] = "wrong".into();
        assert!(matches!(
            client.put(&cap, &first, bytes, None).await,
            Err(ObjectError::InvalidResponse)
        ));
        assert_eq!(
            client.delete(&cap, &first, None).await,
            Err(ObjectError::InvalidResponse)
        );
    }

    #[tokio::test]
    async fn http_forwards_only_explicit_request_and_never_follows_redirect() {
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(serde_json::Value::Null));
        let received = captured.clone();
        let target_calls = calls.clone();
        let app = Router::new()
            .route(
                OBJECT_ROUTE,
                post(
                    move |headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| {
                        let received = received.clone();
                        async move {
                            for header in [
                                "authorization",
                                "x-aws-access-key-id",
                                "x-aws-secret-access-key",
                                "x-aws-session-token",
                            ] {
                                assert!(!headers.contains_key(header));
                            }
                            *received.lock().unwrap() = body;
                            (
                                StatusCode::TEMPORARY_REDIRECT,
                                [("location", "/unexpected")],
                            )
                        }
                    },
                ),
            )
            .route(
                "/unexpected",
                post(move || {
                    target_calls.fetch_add(1, Ordering::SeqCst);
                    async { "unexpected" }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async {
            axum::serve(listener, app).await.unwrap();
        });
        let store = HttpObjectStore::new(&format!("http://{address}")).unwrap();
        let request = request(&cap(), ObjectAction::Get, "fixture");
        let expected = serde_json::to_value(&request).unwrap();
        assert!(matches!(
            store.execute(request).await,
            Err(ObjectError::Unavailable)
        ));
        assert_eq!(*captured.lock().unwrap(), expected);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn errors_do_not_return_server_bodies_or_credentials() {
        for (status, expected) in [
            (400, ObjectError::InvalidRequest),
            (403, ObjectError::Denied),
            (404, ObjectError::Unavailable),
            (409, ObjectError::Unavailable),
            (503, ObjectError::Unavailable),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new().route(
                OBJECT_ROUTE,
                post(move || async move {
                    (
                        StatusCode::from_u16(status).unwrap(),
                        "sensitive fixture detail",
                    )
                }),
            );
            let server = tokio::spawn(async {
                axum::serve(listener, app).await.unwrap();
            });
            let store = HttpObjectStore::new(&format!("http://{address}")).unwrap();
            let error = store
                .execute(request(&cap(), ObjectAction::Get, "fixture"))
                .await
                .unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("sensitive"));
            server.abort();
        }
        for (status, code, expected) in [
            (404, OBJECT_NOT_FOUND, ObjectError::NotFound),
            (409, OBJECT_REVISION_CONFLICT, ObjectError::Conflict),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new().route(
                OBJECT_ROUTE,
                post(move || async move {
                    (
                        StatusCode::from_u16(status).unwrap(),
                        Json(ObjectErrorBody { code: code.into() }),
                    )
                }),
            );
            let server = tokio::spawn(async {
                axum::serve(listener, app).await.unwrap();
            });
            let store = HttpObjectStore::new(&format!("http://{address}")).unwrap();
            assert_eq!(
                store
                    .execute(request(&cap(), ObjectAction::Get, "fixture"))
                    .await
                    .unwrap_err(),
                expected
            );
            server.abort();
        }
        for endpoint in [
            "file:///tmp/data",
            "http://user:password@localhost",
            "http://localhost/data",
            "http://localhost?key=value",
            "http://localhost#fragment",
        ] {
            assert!(HttpObjectStore::new(endpoint).is_err());
        }
    }
}
