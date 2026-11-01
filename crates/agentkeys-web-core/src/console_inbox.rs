use crate::{
    console_documents::ConsoleDocuments,
    data::{DataClient, DataError, DataSession, VersionedConfig},
    document_helpers::{
        content_hash_for, free_key, label_for_ns, merge_stored_entries, valid_history_coords,
    },
};
use agentkeys_protocol::{
    console::{InboxCurateRequest, MemoryCategory, StoredMemoryEntry},
    web_api::ApiMemoryEntry,
    ContextKind, InboxItem, PERSONA_NAMESPACE,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

pub const SKILL_MAX_BYTES: usize = 64 * 1024;

pub fn curate_gate(
    kind: ContextKind,
    body_bytes: usize,
    confirm_content_hash: Option<&str>,
    item_content_hash: &str,
) -> Result<(), (u16, String)> {
    match kind {
        ContextKind::Knowledge => Ok(()),
        ContextKind::Persona => Err((
            403,
            "persona_not_inbox_adoptable: persona is master-authored only — reject this \
             proposal and edit the delegate's persona in parent-control (#390)"
                .to_string(),
        )),
        // #666 — a resource item is master-curated only: an app reads it under a
        // read-only grant and proposes corrections as KNOWLEDGE through its own
        // inbox; the item itself never enters canonical from a delegate.
        ContextKind::Resource => Err((
            403,
            "resource_not_inbox_adoptable: a resource item is master-curated only — reject \
             this proposal and edit the item via `agentkeys resource add` (#666)"
                .to_string(),
        )),
        // The sealed context document is the delegate's anchor — written by
        // the install / rebind ceremony only, never by a delegate proposal.
        ContextKind::Context => Err((
            403,
            "context_not_inbox_adoptable: the context document is sealed by the install / \
             rebind ceremony — reject this proposal"
                .to_string(),
        )),
        ContextKind::Skill => {
            if body_bytes > SKILL_MAX_BYTES {
                return Err((
                    413,
                    format!(
                        "skill_too_large: {body_bytes} bytes exceeds the {SKILL_MAX_BYTES}-byte \
                         skill cap"
                    ),
                ));
            }
            match confirm_content_hash {
                Some(h) if h == item_content_hash => Ok(()),
                Some(_) => Err((
                    409,
                    "skill_review_stale: confirm_content_hash does not match the proposal — \
                     re-view the body and retry with the hash it prints"
                        .to_string(),
                )),
                None => Err((
                    428,
                    "skill_review_required: a skill accept must carry confirm_content_hash \
                     (view the body first; the hash proves it was reviewed)"
                        .to_string(),
                )),
            }
        }
    }
}

pub struct PreparedInboxAccept {
    pub entry: ApiMemoryEntry,
    pub document: VersionedConfig<Vec<StoredMemoryEntry>>,
    pub replaced: Vec<StoredMemoryEntry>,
    pub planted: usize,
    pub history_by: String,
}

pub fn prepare_accept(
    item: &InboxItem,
    request: &InboxCurateRequest,
    document: VersionedConfig<Vec<StoredMemoryEntry>>,
) -> Result<PreparedInboxAccept, DataError> {
    let body = ConsoleInbox::item_body(item)?;
    curate_gate(
        item.kind,
        body.len(),
        request.confirm_content_hash.as_deref(),
        &item.content_hash,
    )
    .map_err(|(status, reason)| ConsoleInbox::failure(status, json!({"error":reason})))?;
    if item.ns == PERSONA_NAMESPACE || !valid_history_coords(&item.ns, &item.key) {
        return Err(ConsoleInbox::failure(
            400,
            json!({"error":"invalid canonical namespace/key"}),
        ));
    }
    let mut key = item.key.clone();
    if let Some(current) = document
        .iter()
        .find(|entry| entry.key == key && entry.body != body)
    {
        match request.on_conflict.as_deref() {
            Some("replace") => {}
            Some("keep-both") => key = free_key(&document, &key),
            _ => {
                return Err(ConsoleInbox::failure(
                    409,
                    json!({"error":"entry_exists","ns":item.ns,"key":key,"current_content_hash":content_hash_for(&item.ns,&key,&current.body),"current_body_b64":STANDARD.encode(&current.body),"proposed_content_hash":item.content_hash}),
                ))
            }
        }
    }
    let entry = ApiMemoryEntry {
        ns: item.ns.clone(),
        key: key.clone(),
        title: key.clone(),
        bytes: body.len() as u64,
        version: "1".into(),
        updated: String::new(),
        preview: body.chars().take(120).collect(),
        body,
        content_hash: String::new(),
        kind: item.kind,
    };
    let history_by = format!("merge:{}", item.source_delegate_omni);
    let replaced = document
        .iter()
        .filter(|old| old.key == key && old.body != entry.body)
        .cloned()
        .collect();
    let (entries, planted) =
        merge_stored_entries(&item.ns, document.document, std::slice::from_ref(&entry));
    Ok(PreparedInboxAccept {
        entry,
        document: VersionedConfig::new(entries, document.revision),
        replaced,
        planted,
        history_by,
    })
}

pub struct ConsoleInbox {
    data: DataClient,
    documents: ConsoleDocuments,
}
impl ConsoleInbox {
    pub fn new(data: DataClient) -> Self {
        Self {
            documents: ConsoleDocuments::new(data.clone()),
            data,
        }
    }
    fn failure(status: u16, body: Value) -> DataError {
        DataError::Http {
            status,
            body: body.to_string(),
        }
    }
    fn item_body(item: &InboxItem) -> Result<String, DataError> {
        let bytes = STANDARD
            .decode(&item.body_b64)
            .map_err(|error| DataError::Invalid(error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| DataError::Invalid(error.to_string()))
    }
    pub async fn request(
        &self,
        session: &DataSession<'_>,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Option<Value>, DataError> {
        let output = match (method, path) {
            ("GET", "/v1/master/inbox") => json!({"items":self.data.inbox_list(session).await?}),
            ("POST", "/v1/master/inbox/entry") => {
                let request: InboxCurateRequest = serde_json::from_value(body)
                    .map_err(|error| Self::failure(400, json!({"error":error.to_string()})))?;
                let item = self.data.inbox_get(session, &request.s3_key).await?;
                json!({"ok":true,"body":Self::item_body(&item)?,"ns":item.ns,"key":item.key,"source_delegate_omni":item.source_delegate_omni,"content_hash":item.content_hash,"ts":item.ts,"kind":item.kind})
            }
            ("POST", "/v1/master/inbox/reject") => {
                let request: InboxCurateRequest = serde_json::from_value(body)
                    .map_err(|error| Self::failure(400, json!({"error":error.to_string()})))?;
                self.data.inbox_delete(session, &request.s3_key).await?;
                json!({"ok":true,"deleted":true})
            }
            ("POST", "/v1/master/inbox/accept") => {
                let request: InboxCurateRequest = serde_json::from_value(body)
                    .map_err(|error| Self::failure(400, json!({"error":error.to_string()})))?;
                self.accept(session, request).await?
            }
            _ => return Ok(None),
        };
        Ok(Some(output))
    }
    pub async fn accept(
        &self,
        session: &DataSession<'_>,
        request: InboxCurateRequest,
    ) -> Result<Value, DataError> {
        let item = self.data.inbox_get(session, &request.s3_key).await?;
        let document = self.documents.namespace_read(session, &item.ns).await?;
        let prepared = prepare_accept(&item, &request, document)?;
        let key = prepared.entry.key.clone();
        let planted = prepared.planted;
        let entry = prepared.entry;
        if prepared.document.revision.is_empty() {
            let registry = self.documents.resource_registry(session).await?;
            if registry
                .items
                .iter()
                .any(|row| row.ns == item.ns && row.id != key)
            {
                return Err(Self::failure(
                    409,
                    json!({"error":"namespace data is missing while resource rows still exist","ns":item.ns}),
                ));
            }
        }
        for old in &prepared.replaced {
            self.documents
                .stash_history(session, &item.ns, old, &prepared.history_by)
                .await?;
        }
        if planted > 0 {
            self.documents
                .namespace_write(session, &item.ns, &prepared.document)
                .await?;
        }
        let mut followup_errors = Vec::new();
        if let Err(error) = self
            .documents
            .reconcile_taxonomy(
                session,
                &[MemoryCategory {
                    ns: item.ns.clone(),
                    label: label_for_ns(&item.ns),
                }],
            )
            .await
        {
            followup_errors.push(format!("taxonomy: {error}"));
        }
        if let Err(error) = self
            .documents
            .register_note_rows(session, std::slice::from_ref(&entry))
            .await
        {
            followup_errors.push(format!("resource registry: {error}"));
        }
        if !followup_errors.is_empty() {
            return Err(Self::failure(
                502,
                json!({"ok":false,"planted":planted,"ns":item.ns,"key":key,"error":"curated into canonical but metadata updates failed","details":followup_errors}),
            ));
        }
        if let Err(error) = self.data.inbox_delete(session, &request.s3_key).await {
            return Err(Self::failure(
                502,
                json!({"ok":false,"planted":planted,"ns":item.ns,"key":key,"error":format!("curated into canonical but inbox GC failed: {error}")}),
            ));
        }
        Ok(json!({"ok":true,"planted":planted,"ns":item.ns,"key":key}))
    }
}
