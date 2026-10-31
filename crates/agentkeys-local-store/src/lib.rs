use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use agentkeys_core::capability_verify::{self as verify, VerifyError};
use agentkeys_protocol::{
    capability::{CapOp, DataClass},
    object_store::{self, ObjectAction, ObjectRequest, ObjectResponse},
};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

const APPLICATION_ID: u32 = 0x41544f53;
const SCHEMA_VERSION: u32 = 1;

pub use agentkeys_core::capability_verify::AuthorityConfig;

pub struct LocalStore {
    connection: Mutex<Connection>,
    authority: AuthorityConfig,
    data_class: DataClass,
    http: reqwest::Client,
    #[cfg(test)]
    storage_operations: std::sync::atomic::AtomicUsize,
}

#[derive(Debug)]
pub struct StoreError {
    pub status: StatusCode,
    pub code: &'static str,
}

impl IntoResponse for StoreError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(object_store::ObjectErrorBody {
                code: self.code.into(),
            }),
        )
            .into_response()
    }
}

fn denied(code: &'static str) -> StoreError {
    StoreError {
        status: StatusCode::FORBIDDEN,
        code,
    }
}

fn failed(code: &'static str) -> StoreError {
    StoreError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code,
    }
}

fn invalid(code: &'static str) -> StoreError {
    StoreError {
        status: StatusCode::BAD_REQUEST,
        code,
    }
}

impl LocalStore {
    pub fn open(
        database: &Path,
        data_class: DataClass,
        authority: AuthorityConfig,
    ) -> Result<Self> {
        ensure!(
            data_class != DataClass::Speech,
            "speech is not an object data class"
        );
        verify::validate_broker_public_key(&authority.broker_public_key)?;
        prepare_database(database)?;
        let empty = database.metadata()?.len() == 0;
        let mut connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        if !empty {
            let application_id: u32 =
                connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
            let schema_version: u32 =
                connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
            ensure!(
                application_id == APPLICATION_ID && schema_version == SCHEMA_VERSION,
                "unsupported object-store database identity or schema"
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
            transaction.execute_batch("CREATE TABLE store_identity (id INTEGER PRIMARY KEY CHECK(id=1), data_class TEXT NOT NULL) STRICT;
                CREATE TABLE objects (key TEXT PRIMARY KEY, value BLOB NOT NULL, revision TEXT NOT NULL) STRICT;")?;
            transaction.execute(
                "INSERT INTO store_identity(id,data_class) VALUES(1,?1)",
                [data_class.as_str()],
            )?;
            transaction.commit()?;
        }
        let stored_class: String = connection.query_row(
            "SELECT data_class FROM store_identity WHERE id=1",
            [],
            |row| row.get(0),
        )?;
        ensure!(
            stored_class == data_class.as_str(),
            "database belongs to a different data class"
        );
        Ok(Self {
            connection: Mutex::new(connection),
            authority,
            data_class,
            #[cfg(test)]
            storage_operations: std::sync::atomic::AtomicUsize::new(0),
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    pub async fn execute(
        self: &Arc<Self>,
        request: ObjectRequest,
    ) -> Result<ObjectResponse, StoreError> {
        verify::verify_signature(&self.authority.broker_public_key, &request.cap)
            .map_err(|_| denied("broker_sig_invalid"))?;
        verify::enforce_client_pop(&request.cap).map_err(|_| denied("cap_pop_invalid"))?;
        verify::check_data_class(&request.cap, self.data_class)
            .map_err(|_| denied("cap_data_class_mismatch"))?;
        verify::check_freshness(&request.cap).map_err(|_| denied("cap_freshness_failed"))?;
        object_store::authorize_key(&request.cap.payload, request.action, &request.key)
            .map_err(denied)?;
        verify::check_chain_device(
            &self.http,
            &self.authority.rpc_url,
            &self.authority.registry,
            &request.cap,
        )
        .await
        .map_err(chain_error)?;
        verify::check_chain_scope(
            &self.http,
            &self.authority.rpc_url,
            &self.authority.scope,
            &request.cap,
        )
        .await
        .map_err(chain_error)?;
        verify::check_chain_k3_epoch(
            &self.http,
            &self.authority.rpc_url,
            &self.authority.epoch,
            &request.cap,
        )
        .await
        .map_err(chain_error)?;
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || store.execute_verified(request))
            .await
            .map_err(|_| failed("storage_task_failed"))?
    }

    fn execute_verified(&self, request: ObjectRequest) -> Result<ObjectResponse, StoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| failed("storage_unavailable"))?;
        verify::check_freshness(&request.cap).map_err(|_| denied("cap_freshness_failed"))?;
        if request.action != ObjectAction::Put && request.value_b64.is_some() {
            return Err(invalid("unexpected_object_value"));
        }
        if request.action != ObjectAction::List && request.after.is_some() {
            return Err(invalid("unexpected_list_cursor"));
        }
        if !matches!(request.action, ObjectAction::Put | ObjectAction::Delete)
            && request.expected_revision.is_some()
        {
            return Err(invalid("unexpected_revision"));
        }
        verify::enforce_client_pop(&request.cap).map_err(|_| denied("cap_pop_invalid"))?;
        #[cfg(test)]
        self.storage_operations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match request.action {
            ObjectAction::Get => {
                let found: Option<(Vec<u8>, String)> = connection
                    .query_row(
                        "SELECT value,revision FROM objects WHERE key=?1",
                        [&request.key],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .map_err(|_| failed("storage_read_failed"))?;
                let (value, revision) = found.ok_or(StoreError {
                    status: StatusCode::NOT_FOUND,
                    code: object_store::OBJECT_NOT_FOUND,
                })?;
                Ok(ObjectResponse {
                    value_b64: Some(STANDARD.encode(value)),
                    revision: Some(revision),
                    ..Default::default()
                })
            }
            ObjectAction::List => {
                if request
                    .after
                    .as_ref()
                    .is_some_and(|cursor| cursor.len() > object_store::MAX_OBJECT_KEY_BYTES)
                {
                    return Err(invalid("list_cursor_invalid"));
                }
                let mut statement = connection.prepare("SELECT key FROM objects WHERE substr(key,1,length(?1))=?1 AND key>?2 ORDER BY key LIMIT ?3")
                    .map_err(|_| failed("storage_list_failed"))?;
                let mut keys = statement
                    .query_map(
                        params![
                            request.key,
                            request.after.unwrap_or_default(),
                            object_store::MAX_LIST_KEYS + 1
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(|_| failed("storage_list_failed"))?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(|_| failed("storage_list_failed"))?;
                let truncated = keys.len() > object_store::MAX_LIST_KEYS;
                keys.truncate(object_store::MAX_LIST_KEYS);
                Ok(ObjectResponse {
                    keys,
                    truncated,
                    ..Default::default()
                })
            }
            ObjectAction::Put | ObjectAction::Delete => {
                let value = if request.action == ObjectAction::Put {
                    let encoded = request
                        .value_b64
                        .as_deref()
                        .ok_or(invalid("object_value_missing"))?;
                    if encoded.len() > object_store::MAX_OBJECT_BYTES.div_ceil(3) * 4 {
                        return Err(invalid("object_too_large"));
                    }
                    let value = STANDARD
                        .decode(encoded)
                        .map_err(|_| invalid("object_value_invalid"))?;
                    if value.len() > object_store::MAX_OBJECT_BYTES {
                        return Err(invalid("object_too_large"));
                    }
                    Some(value)
                } else {
                    None
                };
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|_| failed("storage_write_failed"))?;
                let current: Option<String> = transaction
                    .query_row(
                        "SELECT revision FROM objects WHERE key=?1",
                        [&request.key],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|_| failed("storage_read_failed"))?;
                let expected = if matches!(
                    request.cap.payload.op,
                    CapOp::Append | CapOp::ChannelPublish
                ) {
                    Some("")
                } else {
                    request.expected_revision.as_deref()
                };
                if expected.is_some_and(|expected| current.as_deref().unwrap_or("") != expected) {
                    return Err(StoreError {
                        status: StatusCode::CONFLICT,
                        code: object_store::OBJECT_REVISION_CONFLICT,
                    });
                }
                let revision = if let Some(value) = value {
                    let revision = hex::encode(Sha256::digest(&value));
                    transaction.execute("INSERT INTO objects(key,value,revision) VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,revision=excluded.revision",
                        params![request.key,value,revision]).map_err(|_| failed("storage_write_failed"))?;
                    Some(revision)
                } else {
                    transaction
                        .execute("DELETE FROM objects WHERE key=?1", [&request.key])
                        .map_err(|_| failed("storage_delete_failed"))?;
                    None
                };
                transaction
                    .commit()
                    .map_err(|_| failed("storage_commit_failed"))?;
                Ok(ObjectResponse {
                    revision,
                    ..Default::default()
                })
            }
        }
    }
}

fn chain_error(error: VerifyError) -> StoreError {
    match error {
        VerifyError::ChainRpc(_) => failed("chain_verification_unavailable"),
        VerifyError::DeviceInactive => denied("device_inactive"),
        VerifyError::DeviceMismatch { .. } => denied("device_binding_mismatch"),
        VerifyError::DeviceRoleMissing { .. } => denied("device_role_missing"),
        VerifyError::NotInScope => denied("service_not_in_scope"),
        VerifyError::K3Mismatch { .. } => denied("cap_epoch_mismatch"),
        _ => denied("cap_authority_invalid"),
    }
}

pub fn router(store: Arc<LocalStore>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(serde_json::json!({"ready":true})) }))
        .route(object_store::OBJECT_ROUTE, post(|State(store): State<Arc<LocalStore>>, Json(request): Json<ObjectRequest>| async move {
            store.execute(request).await.map(Json)
        }))
        .layer(DefaultBodyLimit::max(object_store::MAX_OBJECT_BYTES * 2))
        .with_state(store)
}

#[cfg(unix)]
fn prepare_database(database: &Path) -> Result<()> {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    ensure!(database.is_absolute(), "database path must be absolute");
    let directory = database
        .parent()
        .context("database requires a parent directory")?;
    ensure!(
        directory.canonicalize()? == directory,
        "database directory must not traverse symbolic links"
    );
    let directory_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(directory)?;
    let metadata = directory_file.metadata()?;
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0,
        "database directory must be owned by this user with mode 0700"
    );
    let database_string = database.to_str().context("database path must be UTF-8")?;
    match agentkeys_core::protected_file::open_read(database_string) {
        Ok(_) => (),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            agentkeys_core::protected_file::write(database_string, &[], true)?;
        }
        Err(error) => return Err(error),
    }
    for suffix in ["-journal", "-wal", "-shm"] {
        let companion = format!("{database_string}{suffix}");
        match agentkeys_core::protected_file::open_read(&companion) {
            Ok(_) => (),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_database(_database: &Path) -> Result<()> {
    anyhow::bail!("local object storage requires Unix file permissions")
}

#[cfg(test)]
mod tests;
