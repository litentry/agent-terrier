use crate::{crypto, device::DeviceIdentity};
use agentkeys_protocol::{
    auth::{SignMessageRequest, SignedMessage},
    normalize_omni_0x, AuditAppendV2, AuditAppendV2Resp, BrokerCapRequest, CapMintOp, CapToken,
    ConfigGetBody, ConfigGetResp, ConfigPutBody, CredFetchBody, CredFetchResp, CredStoreBody,
    CredStoreResp, MemoryGetBody, MemoryGetResp, MemoryPutBody, MemoryPutResp,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::DeserializeOwned, Serialize};

#[derive(Clone, Debug)]
pub struct DataEndpoints {
    pub broker_url: String,
    pub signer_url: String,
    pub config_url: String,
    pub memory_url: String,
    pub credential_url: String,
    pub audit_url: String,
    pub classify_url: Option<String>,
}

pub struct DataSession<'a> {
    pub bearer: &'a str,
    pub operator_omni: &'a str,
    pub actor_omni: &'a str,
    pub device: &'a DeviceIdentity,
    pub now_unix_seconds: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("data transport failed: {0}")]
    Transport(String),
    #[error("data request returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("data response is invalid: {0}")]
    Invalid(String),
    #[error("data cryptography failed: {0}")]
    Crypto(String),
}

impl DataError {
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Http { status, body } if agentkeys_protocol::object_store::worker_object_missing(*status, body))
    }
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::Http {
                status: 409 | 412,
                ..
            }
        )
    }
}

#[derive(Clone, Debug)]
pub struct ConfigDocument {
    pub plaintext: Vec<u8>,
    pub revision: String,
}

#[derive(Clone)]
pub struct DataClient {
    http: reqwest::Client,
    endpoints: DataEndpoints,
}

impl DataClient {
    pub fn new(endpoints: DataEndpoints) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoints,
        }
    }

    pub fn with_client(http: reqwest::Client, endpoints: DataEndpoints) -> Self {
        Self { http, endpoints }
    }

    pub async fn cap_mint(
        &self,
        session: &DataSession<'_>,
        operation: CapMintOp,
        service: &str,
    ) -> Result<CapToken, DataError> {
        let body =
            self.cap_request(session, operation.op_str(), operation.data_class(), service)?;
        self.send(
            self.http
                .post(endpoint(
                    &self.endpoints.broker_url,
                    operation.broker_path(),
                ))
                .bearer_auth(session.bearer)
                .json(&body),
        )
        .await
    }

    fn cap_request(
        &self,
        session: &DataSession<'_>,
        operation: &str,
        data_class: &str,
        service: &str,
    ) -> Result<BrokerCapRequest, DataError> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|error| DataError::Crypto(error.to_string()))?;
        let client_nonce = hex::encode(nonce);
        let operator_omni = normalize_omni_0x(session.operator_omni);
        let actor_omni = normalize_omni_0x(session.actor_omni);
        let signature = session
            .device
            .cap_pop_sig(
                &operator_omni,
                &actor_omni,
                service,
                operation,
                data_class,
                &client_nonce,
                session.now_unix_seconds,
            )
            .map_err(|error| DataError::Crypto(error.to_string()))?;
        Ok(BrokerCapRequest {
            operator_omni,
            actor_omni,
            service: service.into(),
            device_key_hash: session
                .device
                .device_key_hash()
                .map_err(|error| DataError::Crypto(error.to_string()))?,
            ttl_seconds: None,
            client_sig: Some(signature),
            client_nonce: Some(client_nonce),
            client_ts: Some(session.now_unix_seconds),
            delegation_path: None,
        })
    }

    pub async fn classify_tag(
        &self,
        session: &DataSession<'_>,
        data_class: &str,
        entity: &str,
    ) -> Result<(agentkeys_catalog::Classification, bool), DataError> {
        let catalog = agentkeys_catalog::Catalog::bundled();
        if data_class == "memory" {
            return Ok((catalog.classify_namespace(entity), false));
        }
        let Some(url) = &self.endpoints.classify_url else {
            return Ok((catalog.tag(entity), false));
        };
        let request = self.cap_request(
            session,
            "classify",
            data_class,
            &format!("classify:{data_class}"),
        )?;
        let cap: CapToken = self
            .send(
                self.http
                    .post(endpoint(&self.endpoints.broker_url, "/v1/cap/classify"))
                    .bearer_auth(session.bearer)
                    .json(&agentkeys_protocol::classify::ClassifyCapRequest {
                        request,
                        data_class: data_class.into(),
                    }),
            )
            .await?;
        let response: agentkeys_protocol::classify::ClassifyTagResponse = self
            .send(self.http.post(endpoint(url, "/v1/classify/tag")).json(
                &agentkeys_protocol::classify::ClassifyTagBody {
                    cap,
                    data_class: data_class.to_owned(),
                    entity: entity.to_owned(),
                },
            ))
            .await?;
        if !response.ok {
            return Err(DataError::Invalid(
                "classifier did not confirm result".into(),
            ));
        }
        Ok((response.classification, true))
    }

    pub(crate) async fn worker<T: DeserializeOwned>(
        &self,
        url: String,
        body: &impl Serialize,
    ) -> Result<T, DataError> {
        self.send(self.http.post(url).json(body)).await
    }

    async fn kek(&self, session: &DataSession<'_>, service: &str) -> Result<[u8; 32], DataError> {
        let actor = normalize_omni_0x(session.actor_omni).to_lowercase();
        let signature: SignedMessage = self
            .send(
                self.http
                    .post(endpoint(&self.endpoints.signer_url, "/dev/sign-message"))
                    .bearer_auth(session.bearer)
                    .json(&SignMessageRequest {
                        omni_account: actor.trim_start_matches("0x").into(),
                        message_hex: hex::encode(crypto::kek_message(&actor, service)),
                    }),
            )
            .await?;
        crypto::kek_from_signature(&signature.signature)
            .map_err(|error| DataError::Crypto(error.to_string()))
    }

    async fn encrypt(
        &self,
        session: &DataSession<'_>,
        service: &str,
        plaintext: &[u8],
    ) -> Result<String, DataError> {
        let key = self.kek(session, service).await?;
        let envelope = crypto::encrypt_v3(
            &key,
            plaintext,
            &crypto::aad_v3(session.actor_omni, service),
        )
        .map_err(|error| DataError::Crypto(error.to_string()))?;
        Ok(STANDARD.encode(envelope))
    }

    pub(crate) async fn decrypt(
        &self,
        session: &DataSession<'_>,
        service: &str,
        envelope: Option<String>,
        plaintext: Option<String>,
    ) -> Result<Vec<u8>, DataError> {
        match (envelope, plaintext) {
            (Some(envelope), None) => {
                let key = self.kek(session, service).await?;
                let bytes = STANDARD
                    .decode(envelope)
                    .map_err(|error| DataError::Invalid(error.to_string()))?;
                crypto::decrypt_v3(&key, &bytes, &crypto::aad_v3(session.actor_omni, service))
                    .map_err(|error| DataError::Crypto(error.to_string()))
            }
            (None, Some(plaintext)) => STANDARD
                .decode(plaintext)
                .map_err(|error| DataError::Invalid(error.to_string())),
            _ => Err(DataError::Invalid(
                "expected exactly one encrypted or legacy plaintext payload".into(),
            )),
        }
    }

    pub async fn config_get(
        &self,
        session: &DataSession<'_>,
        service: &str,
    ) -> Result<Option<ConfigDocument>, DataError> {
        let cap = self
            .cap_mint(session, CapMintOp::ConfigFetch, service)
            .await?;
        let response: ConfigGetResp = match self
            .worker(
                endpoint(&self.endpoints.config_url, "/v1/config/get"),
                &ConfigGetBody { cap },
            )
            .await
        {
            Ok(response) => response,
            Err(error) if error.is_missing() => return Ok(None),
            Err(error) => return Err(error),
        };
        let revision = response
            .revision
            .filter(|revision| !revision.is_empty())
            .ok_or_else(|| DataError::Invalid("config worker omitted storage revision".into()))?;
        let plaintext = self
            .decrypt(
                session,
                service,
                response.envelope_b64,
                response.plaintext_b64,
            )
            .await?;
        Ok(Some(ConfigDocument {
            plaintext,
            revision,
        }))
    }

    pub async fn config_put(
        &self,
        session: &DataSession<'_>,
        service: &str,
        plaintext: &[u8],
        expected_revision: &str,
    ) -> Result<(), DataError> {
        let cap = self
            .cap_mint(session, CapMintOp::ConfigStore, service)
            .await?;
        let envelope = self.encrypt(session, service, plaintext).await?;
        let response: MemoryPutResp = self
            .worker(
                endpoint(&self.endpoints.config_url, "/v1/config/put"),
                &ConfigPutBody {
                    cap,
                    plaintext_b64: None,
                    envelope_b64: Some(envelope),
                    expected_revision: Some(expected_revision.into()),
                },
            )
            .await?;
        if !response.ok {
            return Err(DataError::Invalid(
                "config worker did not confirm write".into(),
            ));
        }
        Ok(())
    }

    pub async fn memory_get(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        object_key: Option<String>,
    ) -> Result<Option<Vec<u8>>, DataError> {
        let service = agentkeys_protocol::service_knowledge(namespace);
        let cap = self
            .cap_mint(session, CapMintOp::MemoryGet, &service)
            .await?;
        let response: MemoryGetResp = match self
            .worker(
                endpoint(&self.endpoints.memory_url, "/v1/memory/get"),
                &MemoryGetBody {
                    cap,
                    namespace: namespace.into(),
                    object_key,
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) if error.is_missing() => return Ok(None),
            Err(error) => return Err(error),
        };
        STANDARD
            .decode(response.plaintext_b64)
            .map(Some)
            .map_err(|error| DataError::Invalid(error.to_string()))
    }

    pub async fn memory_put(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        object_key: Option<String>,
        plaintext: &[u8],
        expected_content_hash: &str,
    ) -> Result<MemoryPutResp, DataError> {
        let service = agentkeys_protocol::service_knowledge(namespace);
        let cap = self
            .cap_mint(session, CapMintOp::MemoryPut, &service)
            .await?;
        self.worker(
            endpoint(&self.endpoints.memory_url, "/v1/memory/put"),
            &MemoryPutBody {
                cap,
                namespace: namespace.into(),
                object_key,
                plaintext_b64: STANDARD.encode(plaintext),
                expected_content_hash: Some(expected_content_hash.into()),
            },
        )
        .await
    }

    pub async fn credential_list(
        &self,
        session: &DataSession<'_>,
    ) -> Result<Vec<String>, DataError> {
        let cap = self
            .cap_mint(session, CapMintOp::CredFetch, "credentials")
            .await?;
        let response: agentkeys_protocol::CredListResp = self
            .worker(
                endpoint(&self.endpoints.credential_url, "/v1/cred/list"),
                &CredFetchBody { cap },
            )
            .await?;
        Ok(response.services)
    }

    pub async fn credential_fetch(
        &self,
        session: &DataSession<'_>,
        service: &str,
    ) -> Result<Option<Vec<u8>>, DataError> {
        let cap = self
            .cap_mint(session, CapMintOp::CredFetch, service)
            .await?;
        let response: CredFetchResp = match self
            .worker(
                endpoint(&self.endpoints.credential_url, "/v1/cred/fetch"),
                &CredFetchBody { cap },
            )
            .await
        {
            Ok(response) => response,
            Err(error) if error.is_missing() => return Ok(None),
            Err(error) => return Err(error),
        };
        self.decrypt(
            session,
            service,
            response.envelope_b64,
            response.plaintext_b64,
        )
        .await
        .map(Some)
    }

    pub async fn credential_store(
        &self,
        session: &DataSession<'_>,
        service: &str,
        plaintext: &[u8],
    ) -> Result<CredStoreResp, DataError> {
        let cap = self
            .cap_mint(session, CapMintOp::CredStore, service)
            .await?;
        let envelope = self.encrypt(session, service, plaintext).await?;
        self.worker(
            endpoint(&self.endpoints.credential_url, "/v1/cred/store"),
            &CredStoreBody {
                cap,
                plaintext_b64: None,
                envelope_b64: Some(envelope),
            },
        )
        .await
    }

    pub async fn inbox_list(
        &self,
        session: &DataSession<'_>,
    ) -> Result<Vec<agentkeys_protocol::InboxItemMeta>, DataError> {
        let cap = self
            .cap_mint(session, CapMintOp::MemoryGet, "inbox")
            .await?;
        let response: agentkeys_protocol::InboxListResp = self
            .worker(
                endpoint(&self.endpoints.memory_url, "/v1/memory/inbox-list"),
                &agentkeys_protocol::InboxListBody { cap },
            )
            .await?;
        if !response.ok {
            return Err(DataError::Invalid("inbox list was not confirmed".into()));
        }
        Ok(response.items)
    }
    pub async fn inbox_get(
        &self,
        session: &DataSession<'_>,
        s3_key: &str,
    ) -> Result<agentkeys_protocol::InboxItem, DataError> {
        let cap = self
            .cap_mint(session, CapMintOp::MemoryGet, "inbox")
            .await?;
        let response: agentkeys_protocol::InboxGetResp = self
            .worker(
                endpoint(&self.endpoints.memory_url, "/v1/memory/inbox-get"),
                &agentkeys_protocol::InboxGetBody {
                    cap,
                    s3_key: s3_key.into(),
                },
            )
            .await?;
        if !response.ok {
            return Err(DataError::Invalid("inbox read was not confirmed".into()));
        }
        Ok(response.item)
    }
    pub async fn inbox_delete(
        &self,
        session: &DataSession<'_>,
        s3_key: &str,
    ) -> Result<(), DataError> {
        let cap = self
            .cap_mint(session, CapMintOp::MemoryInboxDelete, "inbox")
            .await?;
        let response: agentkeys_protocol::InboxDeleteResp = self
            .worker(
                endpoint(&self.endpoints.memory_url, "/v1/memory/inbox-delete"),
                &agentkeys_protocol::InboxDeleteBody {
                    cap,
                    s3_key: s3_key.into(),
                },
            )
            .await?;
        if !response.ok || !response.deleted {
            return Err(DataError::Invalid("inbox delete was not confirmed".into()));
        }
        Ok(())
    }

    pub async fn audit_append(
        &self,
        envelope: &AuditAppendV2,
    ) -> Result<AuditAppendV2Resp, DataError> {
        self.send(
            self.http
                .post(endpoint(&self.endpoints.audit_url, "/v1/audit/append/v2"))
                .json(envelope),
        )
        .await
    }

    pub async fn audit_fetch(&self, hash: &str) -> Result<Vec<u8>, DataError> {
        if hash.len() != 66
            || !hash.starts_with("0x")
            || !hash[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DataError::Invalid("invalid audit envelope hash".into()));
        }
        let response = self
            .http
            .get(endpoint(
                &self.endpoints.audit_url,
                &format!("/v1/audit/envelope/{hash}"),
            ))
            .send()
            .await
            .map_err(|error| DataError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(DataError::Http {
                status: response.status().as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| DataError::Transport(error.to_string()))?;
        let actual = format!(
            "0x{}",
            hex::encode(agentkeys_device_core::keccak256(&bytes))
        );
        if !hash.eq_ignore_ascii_case(&actual) {
            return Err(DataError::Invalid("audit envelope hash mismatch".into()));
        }
        Ok(bytes.to_vec())
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, DataError> {
        let response = request
            .send()
            .await
            .map_err(|error| DataError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(DataError::Http {
                status: response.status().as_u16(),
                body: response.text().await.unwrap_or_default(),
            });
        }
        response
            .json()
            .await
            .map_err(|error| DataError::Invalid(error.to_string()))
    }
}

fn endpoint(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    mod console_service_tests {
        include!("console_service_tests.rs");
    }

    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Fixture {
        cloud_requests: usize,
        requests: Vec<BrokerCapRequest>,
        documents: std::collections::HashMap<String, (String, String)>,
        inbox: Option<agentkeys_protocol::InboxItem>,
        fail_gc: bool,
        concurrent_namespace: Option<Vec<u8>>,
        memory: std::collections::HashMap<(String, Option<String>), Vec<u8>>,
        memory_writes: usize,
        signer_denied: bool,
        writes: usize,
        config_conflicts: usize,
    }
    type SharedFixture = Arc<Mutex<Fixture>>;

    fn bearer(headers: &HeaderMap) {
        assert_eq!(headers.get("authorization").unwrap(), "Bearer test-session");
    }
    fn capability_only_headers(headers: &HeaderMap) {
        assert!(!headers.contains_key("authorization"));
        assert!(!headers
            .keys()
            .any(|name| name.as_str().starts_with("x-aws-")));
    }
    async fn cap(
        State(state): State<SharedFixture>,
        headers: HeaderMap,
        Json(body): Json<BrokerCapRequest>,
    ) -> Json<Value> {
        bearer(&headers);
        state.lock().unwrap().requests.push(body.clone());
        Json(json!({"payload": body, "broker_sig": "fixture"}))
    }
    async fn unavailable_cloud(State(state): State<SharedFixture>) -> StatusCode {
        state.lock().unwrap().cloud_requests += 1;
        StatusCode::SERVICE_UNAVAILABLE
    }
    async fn sign(
        State(state): State<SharedFixture>,
        headers: HeaderMap,
        Json(body): Json<SignMessageRequest>,
    ) -> (StatusCode, Json<Value>) {
        bearer(&headers);
        if state.lock().unwrap().signer_denied {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"actor_mismatch"})),
            );
        }
        assert!(hex::decode(body.message_hex)
            .unwrap()
            .starts_with(b"agentkeys.kek.v1:0xab:"));
        (
            StatusCode::OK,
            Json(json!({"address":"fixture", "signature":hex::encode([7u8;65]), "key_version":1})),
        )
    }
    async fn get_doc(
        State(state): State<SharedFixture>,
        headers: HeaderMap,
        Json(body): Json<ConfigGetBody>,
    ) -> (StatusCode, Json<Value>) {
        capability_only_headers(&headers);
        let service = body.cap["payload"]["service"].as_str().unwrap();
        match state.lock().unwrap().documents.get(service) {
            Some((envelope, revision)) => (
                StatusCode::OK,
                Json(json!({"ok":true,"envelope_b64":envelope,"revision":revision})),
            ),
            None => (
                StatusCode::NOT_FOUND,
                Json(json!({"reason":"s3_no_such_key"})),
            ),
        }
    }
    async fn put_doc(
        State(state): State<SharedFixture>,
        headers: HeaderMap,
        Json(body): Json<ConfigPutBody>,
    ) -> (StatusCode, Json<Value>) {
        capability_only_headers(&headers);
        let mut fixture = state.lock().unwrap();
        let service = body.cap["payload"]["service"].as_str().unwrap().to_owned();
        if fixture.config_conflicts > 0 {
            fixture.config_conflicts -= 1;
            return (StatusCode::CONFLICT, Json(json!({"reason":"stale_base"})));
        }
        let current = fixture
            .documents
            .get(&service)
            .map(|(_, revision)| revision.as_str())
            .unwrap_or("");
        if body.expected_revision.as_deref() != Some(current) {
            return (StatusCode::CONFLICT, Json(json!({"reason":"stale_base"})));
        }
        fixture.writes += 1;
        let revision = format!("revision-{}", fixture.writes);
        fixture
            .documents
            .insert(service, (body.envelope_b64.unwrap(), revision));
        (
            StatusCode::OK,
            Json(json!({"ok":true,"s3_key":"fixture","envelope_size":32})),
        )
    }
    async fn get_memory(
        State(state): State<SharedFixture>,
        headers: HeaderMap,
        Json(body): Json<MemoryGetBody>,
    ) -> (StatusCode, Json<Value>) {
        capability_only_headers(&headers);
        if body.namespace == "forbidden" {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"reason":"cap_actor_mismatch"})),
            );
        }
        match state
            .lock()
            .unwrap()
            .memory
            .get(&(body.namespace, body.object_key))
        {
            Some(bytes) => (
                StatusCode::OK,
                Json(json!({"ok":true,"plaintext_b64":STANDARD.encode(bytes)})),
            ),
            None => (
                StatusCode::NOT_FOUND,
                Json(json!({"reason":"s3_no_such_key"})),
            ),
        }
    }
    async fn put_memory(
        State(state): State<SharedFixture>,
        headers: HeaderMap,
        Json(body): Json<MemoryPutBody>,
    ) -> (StatusCode, Json<Value>) {
        capability_only_headers(&headers);
        let mut fixture = state.lock().unwrap();
        if body.object_key.is_some() {
            if let Some(bytes) = fixture.concurrent_namespace.take() {
                fixture.memory.insert((body.namespace.clone(), None), bytes);
            }
        }
        let key = (body.namespace, body.object_key);
        let revision = fixture
            .memory
            .get(&key)
            .map(|bytes| crate::document_helpers::blob_hash(bytes))
            .unwrap_or_default();
        if body.expected_content_hash.as_deref() != Some(revision.as_str()) {
            return (StatusCode::CONFLICT, Json(json!({"reason":"stale_base"})));
        }
        fixture
            .memory
            .insert(key, STANDARD.decode(body.plaintext_b64).unwrap());
        fixture.memory_writes += 1;
        (
            StatusCode::OK,
            Json(json!({"ok":true,"s3_key":"fixture","envelope_size":32})),
        )
    }
    async fn get_inbox(
        State(state): State<SharedFixture>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        capability_only_headers(&headers);
        match &state.lock().unwrap().inbox {
            Some(item) => (StatusCode::OK, Json(json!({"ok":true,"item":item}))),
            None => (
                StatusCode::NOT_FOUND,
                Json(json!({"reason":"s3_no_such_key"})),
            ),
        }
    }
    async fn delete_inbox(
        State(state): State<SharedFixture>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        capability_only_headers(&headers);
        let mut fixture = state.lock().unwrap();
        if fixture.fail_gc {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"reason":"delete_denied"})),
            );
        }
        fixture.inbox = None;
        (StatusCode::OK, Json(json!({"ok":true,"deleted":true})))
    }
    async fn setup() -> (DataClient, SharedFixture, tokio::task::JoinHandle<()>) {
        setup_with_routes(Router::new()).await
    }
    async fn setup_with_routes(
        extra_routes: Router,
    ) -> (DataClient, SharedFixture, tokio::task::JoinHandle<()>) {
        let state = Arc::new(Mutex::new(Fixture::default()));
        let router = Router::new()
            .route("/v1/cap/config-fetch", post(cap))
            .route("/v1/cap/config-store", post(cap))
            .route("/v1/mint-oidc-jwt", post(unavailable_cloud))
            .route("/dev/sign-sts", post(unavailable_cloud))
            .route("/dev/sign-message", post(sign))
            .route("/v1/cap/memory-get", post(cap))
            .route("/v1/cap/memory-put", post(cap))
            .route(CapMintOp::MemoryInboxDelete.broker_path(), post(cap))
            .route("/v1/memory/inbox-get", post(get_inbox))
            .route("/v1/memory/inbox-delete", post(delete_inbox))
            .route("/v1/memory/get", post(get_memory))
            .route("/v1/memory/put", post(put_memory))
            .route("/v1/config/get", post(get_doc))
            .route("/v1/config/put", post(put_doc))
            .with_state(state.clone())
            .merge(extra_routes);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = DataClient::new(DataEndpoints {
            broker_url: endpoint.clone(),
            signer_url: endpoint.clone(),
            config_url: endpoint.clone(),
            memory_url: endpoint.clone(),
            credential_url: endpoint.clone(),
            audit_url: endpoint,
            classify_url: None,
        });
        (client, state, task)
    }

    #[tokio::test]
    async fn config_roundtrip_signs_real_device_pop_and_rejects_a_stale_tab() {
        let (client, state, task) = setup().await;
        let device = DeviceIdentity::from_random_bytes(&[1; 32]).unwrap();
        let session = DataSession {
            bearer: "test-session",
            operator_omni: "ab",
            actor_omni: "ab",
            device: &device,
            now_unix_seconds: 1234,
        };
        assert!(client
            .config_get(&session, "memory-taxonomy")
            .await
            .unwrap()
            .is_none());
        client
            .config_put(&session, "memory-taxonomy", b"first", "")
            .await
            .unwrap();
        let document = client
            .config_get(&session, "memory-taxonomy")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(document.plaintext, b"first");
        client
            .config_put(&session, "memory-taxonomy", b"second", &document.revision)
            .await
            .unwrap();
        let stale = client
            .config_put(
                &session,
                "memory-taxonomy",
                b"lost-update",
                &document.revision,
            )
            .await
            .unwrap_err();
        assert!(stale.is_conflict());
        assert_eq!(
            client
                .config_get(&session, "memory-taxonomy")
                .await
                .unwrap()
                .unwrap()
                .plaintext,
            b"second"
        );
        let fixture = state.lock().unwrap();
        assert_eq!(fixture.writes, 2);
        assert_eq!(fixture.cloud_requests, 0);
        for request in &fixture.requests {
            assert_eq!(request.device_key_hash, device.device_key_hash().unwrap());
            let operation = if request.client_sig.as_deref()
                == Some(
                    &device
                        .cap_pop_sig(
                            "0xab",
                            "0xab",
                            "memory-taxonomy",
                            "fetch",
                            "config",
                            request.client_nonce.as_deref().unwrap(),
                            1234,
                        )
                        .unwrap(),
                ) {
                "fetch"
            } else {
                "store"
            };
            assert_eq!(
                request.client_sig.as_deref(),
                Some(
                    device
                        .cap_pop_sig(
                            "0xab",
                            "0xab",
                            "memory-taxonomy",
                            operation,
                            "config",
                            request.client_nonce.as_deref().unwrap(),
                            1234
                        )
                        .unwrap()
                        .as_str()
                )
            );
        }
        assert_ne!(
            fixture.requests[0].client_nonce,
            fixture.requests[1].client_nonce
        );
        task.abort();
    }

    #[tokio::test]
    async fn signer_denial_prevents_encrypting_or_writing() {
        let (client, state, task) = setup().await;
        state.lock().unwrap().signer_denied = true;
        let device = DeviceIdentity::from_random_bytes(&[1; 32]).unwrap();
        let session = DataSession {
            bearer: "test-session",
            operator_omni: "ab",
            actor_omni: "ab",
            device: &device,
            now_unix_seconds: 1234,
        };
        let error = client
            .config_put(&session, "memory-taxonomy", b"must-not-write", "")
            .await
            .unwrap_err();
        assert!(matches!(error, DataError::Http { status: 403, .. }));
        assert_eq!(state.lock().unwrap().writes, 0);
        assert_eq!(state.lock().unwrap().cloud_requests, 0);
        task.abort();
    }

    #[tokio::test]
    async fn documents_preserve_native_persona_history_and_reject_stale_namespace_writes() {
        use crate::{console_documents::ConsoleDocuments, document_helpers::ApiMemoryEntryExt};
        use agentkeys_protocol::{
            console::StoredMemoryEntry,
            web_api::{ApiMemoryEntry, MasterMemoryPlantRequest},
            ContextKind,
        };
        let (client, state, task) = setup().await;
        let documents = ConsoleDocuments::new(client);
        let device = DeviceIdentity::from_random_bytes(&[1; 32]).unwrap();
        let session = DataSession {
            bearer: "test-session",
            operator_omni: "ab",
            actor_omni: "ab",
            device: &device,
            now_unix_seconds: 1234,
        };
        let first = documents
            .request(
                &session,
                "POST",
                "/v1/master/persona",
                json!({"delegate_omni":"0x11223344","body":"Be a careful cooking assistant."}),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first["version"], 1);
        assert_eq!(first["stored"], true);
        assert_eq!(first["applied"], false);
        documents
            .persona_edit(
                &session,
                "0x11223344",
                "Prefer concise answers.",
                "2026-10-09",
            )
            .await
            .unwrap();
        let state_view = documents
            .persona_read(&session, "0x11223344")
            .await
            .unwrap();
        assert_eq!(state_view.current.unwrap().body, "Prefer concise answers.");
        assert_eq!(
            state_view.versions[0].body,
            "Be a careful cooking assistant."
        );
        let (version, body) = documents
            .persona_rollback(&session, "0x11223344", 1, "2026-10-09")
            .await
            .unwrap();
        assert_eq!(version, 3);
        assert_eq!(body, "Be a careful cooking assistant.");
        let writes_before = state.lock().unwrap().memory_writes;
        assert!(documents
            .persona_edit(&session, "0x11223344", "I am AgentKeys", "today")
            .await
            .is_err());
        assert_eq!(state.lock().unwrap().memory_writes, writes_before);
        let entry = |body: &str| {
            ApiMemoryEntry::from_stored(
                "recipes",
                StoredMemoryEntry {
                    key: "soup".into(),
                    title: "Soup".into(),
                    body: body.into(),
                    updated: "today".into(),
                    bytes: body.len() as u64,
                    version: "v1".into(),
                    kind: ContextKind::Knowledge,
                },
            )
        };
        documents
            .plant(
                &session,
                MasterMemoryPlantRequest {
                    entries: vec![entry("first recipe")],
                },
            )
            .await
            .unwrap();
        let mut stale = documents.namespace_read(&session, "recipes").await.unwrap();
        documents
            .plant(
                &session,
                MasterMemoryPlantRequest {
                    entries: vec![entry("new recipe")],
                },
            )
            .await
            .unwrap();
        stale[0].body = "stale recipe".into();
        assert!(documents
            .namespace_write(&session, "recipes", &stale)
            .await
            .unwrap_err()
            .is_conflict());
        assert_eq!(
            documents
                .history_version(&session, "recipes", "soup", 1)
                .await
                .unwrap()
                .body,
            "first recipe"
        );
        assert_eq!(
            documents.namespace_read(&session, "recipes").await.unwrap()[0].body,
            "new recipe"
        );
        let writes_before = state.lock().unwrap().memory_writes;
        assert!(matches!(
            documents
                .namespace_read(&session, "forbidden")
                .await
                .unwrap_err(),
            DataError::Http { status: 403, .. }
        ));
        assert_eq!(state.lock().unwrap().memory_writes, writes_before);
        task.abort();
    }

    #[tokio::test]
    async fn inbox_review_conflict_and_gc_preserve_canonical_data() {
        use crate::{console_documents::ConsoleDocuments, console_inbox::ConsoleInbox};
        use agentkeys_protocol::{
            console::{InboxCurateRequest, StoredMemoryEntry},
            ContextKind, InboxItem,
        };
        let (client, state, task) = setup().await;
        let documents = ConsoleDocuments::new(client.clone());
        let inbox = ConsoleInbox::new(client);
        let device = DeviceIdentity::from_random_bytes(&[1; 32]).unwrap();
        let session = DataSession {
            bearer: "test-session",
            operator_omni: "ab",
            actor_omni: "ab",
            device: &device,
            now_unix_seconds: 1234,
        };
        let proposal = |kind| InboxItem {
            source_delegate_omni: "0x12345678".into(),
            ns: "recipes".into(),
            key: "soup".into(),
            body_b64: STANDARD.encode("proposed recipe"),
            content_hash: "reviewed-hash".into(),
            ts: 1234,
            kind,
        };
        let request = |confirm: Option<&str>, choice: Option<&str>| InboxCurateRequest {
            s3_key: "proposal".into(),
            confirm_content_hash: confirm.map(str::to_owned),
            on_conflict: choice.map(str::to_owned),
        };
        for kind in [
            ContextKind::Persona,
            ContextKind::Resource,
            ContextKind::Context,
        ] {
            state.lock().unwrap().inbox = Some(proposal(kind));
            assert!(matches!(
                inbox
                    .accept(&session, request(Some("reviewed-hash"), None))
                    .await
                    .unwrap_err(),
                DataError::Http { status: 403, .. }
            ));
        }
        state.lock().unwrap().inbox = Some(proposal(ContextKind::Skill));
        assert!(matches!(
            inbox
                .accept(&session, request(None, None))
                .await
                .unwrap_err(),
            DataError::Http { status: 428, .. }
        ));
        assert!(matches!(
            inbox
                .accept(&session, request(Some("stale"), None))
                .await
                .unwrap_err(),
            DataError::Http { status: 409, .. }
        ));
        assert_eq!(state.lock().unwrap().memory_writes, 0);
        let current = StoredMemoryEntry {
            key: "soup".into(),
            title: "Soup".into(),
            body: "current recipe".into(),
            updated: String::new(),
            bytes: 14,
            version: "v1".into(),
            kind: ContextKind::Knowledge,
        };
        documents
            .namespace_write(
                &session,
                "recipes",
                &VersionedConfig::new(vec![current.clone()], String::new()),
            )
            .await
            .unwrap();
        state.lock().unwrap().inbox = Some(proposal(ContextKind::Knowledge));
        assert!(matches!(
            inbox
                .accept(&session, request(None, None))
                .await
                .unwrap_err(),
            DataError::Http { status: 409, .. }
        ));
        let mut concurrent = current;
        concurrent.body = "concurrent edit".into();
        state.lock().unwrap().concurrent_namespace =
            Some(serde_json::to_vec(&vec![concurrent]).unwrap());
        assert!(inbox
            .accept(&session, request(None, Some("replace")))
            .await
            .unwrap_err()
            .is_conflict());
        assert_eq!(
            documents.namespace_read(&session, "recipes").await.unwrap()[0].body,
            "concurrent edit"
        );
        assert!(state.lock().unwrap().inbox.is_some());
        state.lock().unwrap().fail_gc = true;
        let error = inbox
            .accept(&session, request(None, Some("keep-both")))
            .await
            .unwrap_err();
        assert!(
            matches!(error,DataError::Http{status:502,body} if body.contains("inbox GC failed") && body.contains("planted"))
        );
        let entries = documents.namespace_read(&session, "recipes").await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].body, "concurrent edit");
        assert_eq!(entries[1].key, "soup-2");
        assert!(state.lock().unwrap().inbox.is_some());
        task.abort();
    }

    #[test]
    fn only_a_confirmed_missing_object_is_absent() {
        assert!(DataError::Http {
            status: 404,
            body: r#"{"reason":"object_not_found"}"#.into()
        }
        .is_missing());
        assert!(DataError::Http {
            status: 404,
            body: r#"{"reason":"s3_no_such_key"}"#.into()
        }
        .is_missing());
        for (status, body) in [
            (404, "route missing"),
            (403, r#"{"reason":"s3_no_such_key"}"#),
            (502, r#"{"reason":"s3_get"}"#),
        ] {
            assert!(!DataError::Http {
                status,
                body: body.into()
            }
            .is_missing());
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(transparent)]
pub struct VersionedConfig<T> {
    pub document: T,
    #[serde(skip)]
    pub revision: String,
}

impl<T> VersionedConfig<T> {
    pub fn new(document: T, revision: String) -> Self {
        Self { document, revision }
    }
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> VersionedConfig<U> {
        VersionedConfig::new(transform(self.document), self.revision)
    }
}
impl<T: Default> Default for VersionedConfig<T> {
    fn default() -> Self {
        Self::new(T::default(), String::new())
    }
}
impl<T> std::ops::Deref for VersionedConfig<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.document
    }
}
impl<T> std::ops::DerefMut for VersionedConfig<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.document
    }
}
