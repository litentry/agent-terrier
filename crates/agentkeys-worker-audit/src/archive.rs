use agentkeys_core::{audit::AuditEnvelope, protected_file};
use agentkeys_protocol::{AuditAppendV2, AuditAppendV2Resp};
use anyhow::ensure;
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::json;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

pub const MAX_ENVELOPE_BYTES: usize = 32 * 1024;
const APPLICATION_ID: u32 = 0x41544155;
const SCHEMA_VERSION: u32 = 1;

pub struct Archive {
    connection: Mutex<Connection>,
    token: zeroize::Zeroizing<String>,
}

type Failure = (StatusCode, Json<serde_json::Value>);
fn failure(status: StatusCode, code: &'static str) -> Failure {
    (status, Json(json!({"error":code})))
}
fn unavailable() -> Failure {
    failure(StatusCode::SERVICE_UNAVAILABLE, "audit_archive_unavailable")
}

pub fn normalize_hash(value: &str) -> Option<String> {
    let digits = value.strip_prefix("0x")?;
    (digits.len() == 64 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

impl Archive {
    pub fn open(
        database: &Path,
        token_file: &Path,
        deployment_identity: &str,
    ) -> anyhow::Result<Self> {
        let token = protected_file::read_token(token_file)?;
        ensure!(
            token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "archive credential must be a generated local token"
        );
        protected_file::prepare_database(database)?;
        let empty = database.metadata()?.len() == 0;
        let mut connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        if !empty {
            let identity: u32 =
                connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
            let version: u32 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            ensure!(
                identity == APPLICATION_ID && version == SCHEMA_VERSION,
                "unsupported audit archive database"
            );
        }
        connection.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
        )?;
        if empty {
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.execute_batch("CREATE TABLE archive_identity (id INTEGER PRIMARY KEY CHECK(id=1), deployment TEXT NOT NULL) STRICT; CREATE TABLE envelopes (hash TEXT PRIMARY KEY, operator TEXT NOT NULL, cbor BLOB NOT NULL) STRICT; CREATE INDEX envelopes_operator ON envelopes(operator);")?;
            transaction.execute(
                "INSERT INTO archive_identity VALUES (1, ?1)",
                [deployment_identity],
            )?;
            transaction.commit()?;
        }
        let saved: String = connection.query_row(
            "SELECT deployment FROM archive_identity WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            saved == deployment_identity,
            "audit archive belongs to another deployment"
        );
        Ok(Self {
            connection: Mutex::new(connection),
            token,
        })
    }

    fn authenticate(&self, headers: &HeaderMap) -> Result<(), Failure> {
        let supplied = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or("");
        let difference = supplied
            .as_bytes()
            .iter()
            .zip(self.token.as_bytes())
            .fold(0u8, |difference, (left, right)| difference | (left ^ right));
        if supplied.len() != self.token.len() || difference != 0 {
            return Err(failure(
                StatusCode::UNAUTHORIZED,
                "audit_archive_unauthorized",
            ));
        }
        Ok(())
    }

    pub fn append(&self, request: AuditAppendV2) -> Result<AuditAppendV2Resp, Failure> {
        let envelope = crate::handlers::canonical_envelope(request)
            .map_err(|_| failure(StatusCode::BAD_REQUEST, "audit_envelope_invalid"))?;
        envelope
            .typed_body()
            .ok_or_else(|| failure(StatusCode::BAD_REQUEST, "audit_envelope_invalid"))?;
        let bytes = envelope
            .to_canonical_cbor()
            .map_err(|_| failure(StatusCode::BAD_REQUEST, "audit_envelope_invalid"))?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "audit_envelope_too_large",
            ));
        }
        let hash = format!(
            "0x{}",
            hex::encode(envelope.envelope_hash().map_err(|_| unavailable())?)
        );
        let operator = format!("0x{}", hex::encode(envelope.operator_omni));
        let connection = self.connection.lock().map_err(|_| unavailable())?;
        connection
            .execute(
                "INSERT OR IGNORE INTO envelopes (hash,operator,cbor) VALUES (?1,?2,?3)",
                params![hash, operator, bytes],
            )
            .map_err(|_| unavailable())?;
        let saved: Vec<u8> = connection
            .query_row(
                "SELECT cbor FROM envelopes WHERE hash=?1 AND operator=?2",
                params![hash, operator],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        if saved != bytes {
            return Err(unavailable());
        }
        Ok(AuditAppendV2Resp {
            ok: true,
            envelope_hash: hash,
        })
    }

    pub fn list(
        &self,
        operator: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<agentkeys_protocol::AuditArchivePage, Failure> {
        let operator = normalize_hash(operator)
            .ok_or_else(|| failure(StatusCode::BAD_REQUEST, "audit_operator_invalid"))?;
        if limit == 0 || limit > 100 || cursor.is_some_and(|value| normalize_hash(value).is_none())
        {
            return Err(failure(StatusCode::BAD_REQUEST, "audit_cursor_invalid"));
        }
        let cursor = cursor.and_then(normalize_hash);
        let connection = self.connection.lock().map_err(|_| unavailable())?;
        let mut query = connection
            .prepare(
                "SELECT hash FROM envelopes WHERE operator=?1 AND hash>?2 ORDER BY hash LIMIT ?3",
            )
            .map_err(|_| unavailable())?;
        let rows = query
            .query_map(
                params![operator, cursor.as_deref().unwrap_or(""), limit + 1],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| unavailable())?;
        let mut hashes = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| unavailable())?;
        let next = if hashes.len() > limit {
            hashes.truncate(limit);
            hashes.last().cloned()
        } else {
            None
        };
        Ok(agentkeys_protocol::AuditArchivePage {
            envelope_hashes: hashes,
            next_cursor: next,
        })
    }
    pub fn fetch(&self, hash: &str, operator: Option<&str>) -> Result<Vec<u8>, Failure> {
        let hash = normalize_hash(hash)
            .ok_or_else(|| failure(StatusCode::BAD_REQUEST, "audit_hash_invalid"))?;
        let operator = operator
            .map(|value| {
                normalize_hash(value)
                    .ok_or_else(|| failure(StatusCode::BAD_REQUEST, "audit_operator_invalid"))
            })
            .transpose()?;
        let connection = self.connection.lock().map_err(|_| unavailable())?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT cbor FROM envelopes WHERE hash=?1 AND (?2 IS NULL OR operator=?2)",
                params![hash, operator],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| unavailable())?;
        let bytes =
            bytes.ok_or_else(|| failure(StatusCode::NOT_FOUND, "audit_envelope_not_found"))?;
        let envelope = AuditEnvelope::from_canonical_cbor(&bytes).map_err(|_| unavailable())?;
        if format!(
            "0x{}",
            hex::encode(envelope.envelope_hash().map_err(|_| unavailable())?)
        ) != hash
        {
            return Err(unavailable());
        }
        Ok(bytes)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    operator_omni: Option<String>,
}

async fn append(
    State(state): State<Arc<Archive>>,
    headers: HeaderMap,
    Json(request): Json<AuditAppendV2>,
) -> Result<Json<AuditAppendV2Resp>, Failure> {
    state.authenticate(&headers)?;
    Ok(Json(state.append(request)?))
}
async fn fetch(
    State(state): State<Arc<Archive>>,
    headers: HeaderMap,
    RoutePath(hash): RoutePath<String>,
    Query(selection): Query<Selection>,
) -> Result<Response, Failure> {
    state.authenticate(&headers)?;
    let bytes = state.fetch(&hash, selection.operator_omni.as_deref())?;
    Ok(([("content-type", "application/cbor")], Body::from(bytes)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListSelection {
    operator_omni: String,
    cursor: Option<String>,
    limit: Option<usize>,
}
async fn list(
    State(state): State<Arc<Archive>>,
    headers: HeaderMap,
    Query(selection): Query<ListSelection>,
) -> Result<Json<agentkeys_protocol::AuditArchivePage>, Failure> {
    state.authenticate(&headers)?;
    Ok(Json(state.list(
        &selection.operator_omni,
        selection.cursor.as_deref(),
        selection.limit.unwrap_or(20),
    )?))
}
pub fn router(state: Arc<Archive>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"ok":true})) }))
        .route("/v1/audit/envelopes", get(list))
        .route("/v1/audit/append/v2", post(append))
        .route("/v1/audit/envelope/:hash", get(fetch))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_BYTES))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::os::unix::fs::PermissionsExt;
    use tower::ServiceExt;

    fn request(operator: u8) -> AuditAppendV2 {
        let owner = format!("0x{}", hex::encode([operator; 32]));
        AuditAppendV2 {
            version: agentkeys_protocol::ENVELOPE_VERSION,
            ts_unix: 1234,
            actor_omni: owner.clone(),
            operator_omni: owner.clone(),
            op_kind: agentkeys_core::audit::AuditOpKind::ScopeRevoke as u8,
            op_body: json!({"agent_omni":owner}),
            result: 0,
            intent_text: None,
            intent_commitment: None,
        }
    }
    fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let token = root.join("service.key");
        protected_file::write(
            token.to_str().unwrap(),
            format!("{:064x}", 17).as_bytes(),
            true,
        )
        .unwrap();
        (directory, root.join("archive.db"), token)
    }
    fn count(archive: &Archive) -> u64 {
        archive
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM envelopes", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn durable_immutable_records_are_scoped_and_revalidated_after_restart() {
        let (_directory, database, token) = setup();
        let archive = Archive::open(&database, &token, "deployment-one").unwrap();
        let envelope_request = request(1);
        let receipt = archive.append(envelope_request.clone()).unwrap();
        let bytes = archive
            .fetch(
                &receipt.envelope_hash,
                Some(&envelope_request.operator_omni),
            )
            .unwrap();
        assert_eq!(
            archive
                .append(envelope_request.clone())
                .unwrap()
                .envelope_hash,
            receipt.envelope_hash
        );
        assert_eq!(count(&archive), 1);
        let other = request(2);
        assert_eq!(
            archive
                .fetch(&receipt.envelope_hash, Some(&other.operator_omni))
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        assert!(archive
            .list(&other.operator_omni, None, 20)
            .unwrap()
            .envelope_hashes
            .is_empty());
        assert_eq!(count(&archive), 1);
        drop(archive);
        let restored = Archive::open(&database, &token, "deployment-one").unwrap();
        assert_eq!(
            restored
                .fetch(
                    &receipt.envelope_hash,
                    Some(&envelope_request.operator_omni)
                )
                .unwrap(),
            bytes
        );
        assert!(Archive::open(&database, &token, "different-deployment").is_err());
        assert_eq!(count(&restored), 1);
        restored
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE envelopes SET cbor=?1 WHERE hash=?2",
                params![b"corrupt".as_slice(), receipt.envelope_hash],
            )
            .unwrap();
        assert_eq!(
            restored
                .fetch(
                    &receipt.envelope_hash,
                    Some(&envelope_request.operator_omni)
                )
                .unwrap_err()
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn authenticated_routes_reject_invalid_writes_without_side_effects() {
        let (_directory, database, token) = setup();
        let archive = Arc::new(Archive::open(&database, &token, "deployment").unwrap());
        let body = serde_json::to_vec(&request(1)).unwrap();
        for credential in [None, Some("wrong-credential")] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/v1/audit/append/v2")
                .header("content-type", "application/json");
            if let Some(credential) = credential {
                request = request.header("authorization", format!("Bearer {credential}"));
            }
            let response = router(archive.clone())
                .oneshot(request.body(Body::from(body.clone())).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(count(&archive), 0);
        }
        let credential = protected_file::read_token(&token).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/audit/append/v2")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", credential.as_str()))
            .body(Body::from(body))
            .unwrap();
        let response = router(archive.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt: AuditAppendV2Resp =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(count(&archive), 1);
        let mut invalid = super::tests::request(1);
        invalid.op_kind = 255;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/audit/append/v2")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", credential.as_str()))
            .body(Body::from(serde_json::to_vec(&invalid).unwrap()))
            .unwrap();
        assert_eq!(
            router(archive.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(count(&archive), 1);
        for route in ["/v1/audit/flush-all", "/v1/audit/append"] {
            let request = Request::builder()
                .method("POST")
                .uri(route)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                router(archive.clone())
                    .oneshot(request)
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        let request = Request::builder()
            .uri(format!("/v1/audit/envelope/{}", receipt.envelope_hash))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router(archive.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(count(&archive), 1);
    }

    #[test]
    fn insecure_service_credential_is_refused_before_database_creation() {
        let (_directory, database, token) = setup();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Archive::open(&database, &token, "deployment").is_err());
        assert!(!database.exists());
    }
}
