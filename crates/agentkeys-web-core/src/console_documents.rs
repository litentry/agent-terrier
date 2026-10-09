use crate::{
    data::{DataClient, DataError, DataSession, VersionedConfig},
    document_helpers::*,
    persona,
};
use agentkeys_protocol::{
    console::*,
    knowledge_history::{self, KnowledgeHistory, KnowledgeVersionBody, VersionIndex},
    persona_soul_key,
    web_api::{ApiMemoryEntry, MasterMemoryPlantRequest, MasterMemoryPlantResponse},
    ContextKind, PERSONA_NAMESPACE,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct ConsoleDocuments {
    pub data: DataClient,
    pub history_keep: u32,
    pub sandbox_configured: bool,
}

impl ConsoleDocuments {
    pub fn new(data: DataClient) -> Self {
        Self {
            data,
            history_keep: knowledge_history::DEFAULT_KEEP,
            sandbox_configured: false,
        }
    }

    pub async fn config_read<T: DeserializeOwned + Default>(
        &self,
        session: &DataSession<'_>,
        service: &str,
    ) -> Result<VersionedConfig<T>, DataError> {
        match self.data.config_get(session, service).await? {
            Some(document) => Ok(VersionedConfig::new(
                decode(&document.plaintext)?,
                document.revision,
            )),
            None => Ok(VersionedConfig::default()),
        }
    }
    pub async fn config_write<T: Serialize>(
        &self,
        session: &DataSession<'_>,
        service: &str,
        document: &VersionedConfig<T>,
    ) -> Result<(), DataError> {
        self.data
            .config_put(
                session,
                service,
                &encode(&document.document)?,
                &document.revision,
            )
            .await
    }
    pub async fn resource_registry(
        &self,
        session: &DataSession<'_>,
    ) -> Result<VersionedConfig<agentkeys_protocol::ResourceRegistryDoc>, DataError> {
        match self
            .data
            .config_get(session, agentkeys_protocol::RESOURCE_REGISTRY_SERVICE)
            .await?
        {
            None => Ok(VersionedConfig::default()),
            Some(document) => {
                let (registry, _) = agentkeys_protocol::ResourceRegistryDoc::from_slice_lenient(
                    &document.plaintext,
                )
                .map_err(|error| DataError::Invalid(error.to_string()))?;
                Ok(VersionedConfig::new(registry, document.revision))
            }
        }
    }
    pub async fn taxonomy(
        &self,
        session: &DataSession<'_>,
    ) -> Result<VersionedConfig<MemoryTaxonomy>, DataError> {
        self.config_read(session, TAXONOMY_SERVICE).await
    }
    pub async fn reconcile_taxonomy(
        &self,
        session: &DataSession<'_>,
        incoming: &[MemoryCategory],
    ) -> Result<Vec<MemoryCategory>, DataError> {
        let mut taxonomy = self.taxonomy(session).await?;
        taxonomy.document.categories = merge_categories(taxonomy.document.categories, incoming);
        taxonomy.version = 1;
        self.config_write(session, TAXONOMY_SERVICE, &taxonomy)
            .await?;
        Ok(taxonomy.document.categories)
    }
    pub async fn namespace_read(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
    ) -> Result<VersionedConfig<Vec<StoredMemoryEntry>>, DataError> {
        match self.data.memory_get(session, namespace, None).await? {
            Some(bytes) => {
                let text = std::str::from_utf8(&bytes)
                    .map_err(|error| DataError::Invalid(error.to_string()))?;
                Ok(VersionedConfig::new(
                    parse_stored_blob(text, namespace),
                    blob_hash(&bytes),
                ))
            }
            None => Ok(VersionedConfig::default()),
        }
    }
    pub async fn namespace_write(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        document: &VersionedConfig<Vec<StoredMemoryEntry>>,
    ) -> Result<(), DataError> {
        self.data
            .memory_put(
                session,
                namespace,
                None,
                &encode(&document.document)?,
                &document.revision,
            )
            .await?;
        Ok(())
    }
    async fn object_read<T: DeserializeOwned + Default>(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        key: &str,
    ) -> Result<VersionedConfig<T>, DataError> {
        match self
            .data
            .memory_get(session, namespace, Some(key.into()))
            .await?
        {
            Some(bytes) => Ok(VersionedConfig::new(decode(&bytes)?, blob_hash(&bytes))),
            None => Ok(VersionedConfig::default()),
        }
    }
    pub async fn history(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        key: &str,
    ) -> Result<KnowledgeHistory, DataError> {
        if !valid_history_coords(namespace, key) {
            return Err(invalid("invalid ns/key"));
        }
        let index: VersionedConfig<VersionIndex> = self
            .object_read(session, namespace, &knowledge_history::index_key(key))
            .await?;
        let mut versions = index.document.versions;
        versions.reverse();
        Ok(KnowledgeHistory {
            ns: namespace.into(),
            key: key.into(),
            keep: self.history_keep,
            storage: "durable".into(),
            versions,
        })
    }
    pub async fn history_version(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        key: &str,
        number: u32,
    ) -> Result<KnowledgeVersionBody, DataError> {
        let history = self.history(session, namespace, key).await?;
        let version = history
            .versions
            .into_iter()
            .find(|version| version.n == number)
            .ok_or_else(|| missing("version_unknown"))?;
        let bytes = self
            .data
            .memory_get(
                session,
                namespace,
                Some(knowledge_history::slot_key(key, version.slot)),
            )
            .await?
            .ok_or_else(|| missing("version_pruned"))?;
        let body =
            String::from_utf8(bytes).map_err(|error| DataError::Invalid(error.to_string()))?;
        if content_hash_for(namespace, key, &body) != version.content_hash {
            return Err(missing("version_pruned"));
        }
        Ok(KnowledgeVersionBody { version, body })
    }
    pub(crate) async fn stash_history(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        old: &StoredMemoryEntry,
        by: &str,
    ) -> Result<(), DataError> {
        let index_key = knowledge_history::index_key(&old.key);
        let mut index: VersionedConfig<VersionIndex> =
            self.object_read(session, namespace, &index_key).await?;
        let hash = content_hash_for(namespace, &old.key, &old.body);
        if index
            .newest()
            .is_some_and(|version| version.content_hash == hash)
        {
            return Ok(());
        }
        let version = index.record(
            self.history_keep,
            session.now_unix_seconds,
            old.body.len() as u64,
            hash,
            by,
            &old.version,
        );
        let slot_key = knowledge_history::slot_key(&old.key, version.slot);
        let prior = self
            .data
            .memory_get(session, namespace, Some(slot_key.clone()))
            .await?;
        let base = prior.as_deref().map(blob_hash).unwrap_or_default();
        self.data
            .memory_put(
                session,
                namespace,
                Some(slot_key),
                old.body.as_bytes(),
                &base,
            )
            .await?;
        self.data
            .memory_put(
                session,
                namespace,
                Some(index_key),
                &encode(&index.document)?,
                &index.revision,
            )
            .await?;
        Ok(())
    }
    pub async fn plant(
        &self,
        session: &DataSession<'_>,
        request: MasterMemoryPlantRequest,
    ) -> Result<MasterMemoryPlantResponse, DataError> {
        let mut groups = BTreeMap::<String, Vec<ApiMemoryEntry>>::new();
        for entry in request.entries {
            if entry.ns == PERSONA_NAMESPACE || entry.kind == ContextKind::Persona {
                return Err(invalid("persona uses the persona editor"));
            }
            if !valid_history_coords(&entry.ns, &entry.key) {
                return Err(invalid("invalid ns/key"));
            }
            groups.entry(entry.ns.clone()).or_default().push(entry);
        }
        let mut planted = 0;
        let mut skipped = 0;
        let mut total = 0;
        let mut categories = Vec::new();
        for (namespace, entries) in groups {
            let document = self.namespace_read(session, &namespace).await?;
            if document.revision.is_empty() {
                let registry = self.resource_registry(session).await?;
                let orphaned = registry
                    .items
                    .iter()
                    .filter(|item| {
                        item.ns == namespace && !entries.iter().any(|entry| entry.key == item.id)
                    })
                    .map(|item| item.id.clone())
                    .collect::<Vec<_>>();
                if !orphaned.is_empty() {
                    return Err(DataError::Http {status:409,body:json!({"error":"namespace data is missing while resource rows still exist", "namespace":namespace,"orphaned":orphaned}).to_string()});
                }
            }
            for old in document.iter().filter(|old| {
                entries
                    .iter()
                    .any(|entry| entry.key == old.key && entry.body != old.body)
            }) {
                self.stash_history(session, &namespace, old, "plant")
                    .await?;
            }
            let (merged, count) = merge_stored_entries(&namespace, document.document, &entries);
            total += merged.len();
            planted += count;
            skipped += entries.len() - count;
            if count > 0 {
                self.namespace_write(
                    session,
                    &namespace,
                    &VersionedConfig::new(merged, document.revision),
                )
                .await?;
            }
            categories.push(MemoryCategory {
                label: label_for_ns(&namespace),
                ns: namespace,
            });
        }
        let taxonomy_status = match self.reconcile_taxonomy(session, &categories).await {
            Ok(_) => "ok".into(),
            Err(error) => format!("failed: {error}"),
        };
        Ok(MasterMemoryPlantResponse {
            planted,
            skipped,
            total,
            taxonomy_status,
        })
    }
    pub async fn remove_entry(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        key: &str,
        by: &str,
    ) -> Result<usize, DataError> {
        if !valid_history_coords(namespace, key) || namespace == PERSONA_NAMESPACE {
            return Err(invalid("invalid ns/key"));
        }
        let mut document = self.namespace_read(session, namespace).await?;
        for old in document.iter().filter(|entry| entry.key == key) {
            self.stash_history(session, namespace, old, by).await?;
        }
        let count = document.len();
        document.retain(|entry| entry.key != key);
        let removed = count - document.len();
        if removed > 0 {
            self.namespace_write(session, namespace, &document).await?;
        }
        Ok(removed)
    }
    pub async fn persona_read(
        &self,
        session: &DataSession<'_>,
        delegate: &str,
    ) -> Result<ApiPersonaState, DataError> {
        validate_delegate_omni(delegate).map_err(|error| invalid(&error))?;
        let entries = self.namespace_read(session, PERSONA_NAMESPACE).await?;
        let (current, history) =
            persona::persona_view(entries.document, &persona_soul_key(delegate));
        Ok(ApiPersonaState {
            delegate_omni: agentkeys_protocol::normalize_omni_0x(delegate),
            current: current.map(|entry| ApiMemoryEntry::from_stored(PERSONA_NAMESPACE, entry)),
            versions: history
                .into_iter()
                .map(|entry| ApiMemoryEntry::from_stored(PERSONA_NAMESPACE, entry))
                .collect(),
            sandbox_configured: self.sandbox_configured,
        })
    }
    pub async fn persona_edit(
        &self,
        session: &DataSession<'_>,
        delegate: &str,
        body: &str,
        updated: &str,
    ) -> Result<u32, DataError> {
        validate_delegate_omni(delegate).map_err(|error| invalid(&error))?;
        persona::validate_persona_body(body).map_err(|error| invalid(&error))?;
        let document = self.namespace_read(session, PERSONA_NAMESPACE).await?;
        let (entries, version) = persona::rotate_persona(
            document.document,
            &persona_soul_key(delegate),
            body,
            updated,
        );
        self.namespace_write(
            session,
            PERSONA_NAMESPACE,
            &VersionedConfig::new(entries, document.revision),
        )
        .await?;
        Ok(version)
    }
    pub async fn persona_rollback(
        &self,
        session: &DataSession<'_>,
        delegate: &str,
        version: u32,
        updated: &str,
    ) -> Result<(u32, String), DataError> {
        validate_delegate_omni(delegate).map_err(|error| invalid(&error))?;
        let document = self.namespace_read(session, PERSONA_NAMESPACE).await?;
        let key = persona_soul_key(delegate);
        let body = persona::persona_body_for_version(&document, &key, version)
            .ok_or_else(|| missing("version_pruned"))?;
        persona::validate_persona_body(&body).map_err(|error| invalid(&error))?;
        let (entries, version) = persona::rotate_persona(document.document, &key, &body, updated);
        self.namespace_write(
            session,
            PERSONA_NAMESPACE,
            &VersionedConfig::new(entries, document.revision),
        )
        .await?;
        Ok((version, body))
    }
    pub async fn persona_delete(
        &self,
        session: &DataSession<'_>,
        delegate: &str,
    ) -> Result<usize, DataError> {
        validate_delegate_omni(delegate).map_err(|error| invalid(&error))?;
        let mut document = self.namespace_read(session, PERSONA_NAMESPACE).await?;
        let key = persona_soul_key(delegate);
        let prefix = format!("{key}@");
        let before = document.len();
        document.retain(|entry| entry.key != key && !entry.key.starts_with(&prefix));
        let removed = before - document.len();
        if removed > 0 {
            self.namespace_write(session, PERSONA_NAMESPACE, &document)
                .await?;
        }
        Ok(removed)
    }
    pub async fn credential_list(
        &self,
        session: &DataSession<'_>,
    ) -> Result<Vec<CredService>, DataError> {
        let mut services = Vec::new();
        for service in self.data.credential_list(session).await? {
            let (classification, _) = self
                .data
                .classify_tag(session, "credentials", &service)
                .await?;
            services.push(CredService {
                service,
                category: classification.category,
                sensitivity: classification.sensitivity,
            });
        }
        services.sort_by(|left, right| {
            (&left.category, &left.service).cmp(&(&right.category, &right.service))
        });
        Ok(services)
    }
    pub async fn register_note_rows(
        &self,
        session: &DataSession<'_>,
        entries: &[ApiMemoryEntry],
    ) -> Result<usize, DataError> {
        let mut registry = self.resource_registry(session).await?;
        let changed = register_note_entries(&mut registry, entries, session.now_unix_seconds);
        if changed > 0 {
            self.config_write(
                session,
                agentkeys_protocol::RESOURCE_REGISTRY_SERVICE,
                &registry,
            )
            .await?;
        }
        Ok(changed)
    }
    pub async fn request(
        &self,
        session: &DataSession<'_>,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Option<Value>, DataError> {
        let route = path.split('?').next().unwrap_or(path);
        let query = query_value(path);
        let output = match (method, route) {
            ("GET", "/v1/master/memory") => {
                json!({"categories": self.taxonomy(session).await?.document.categories})
            }
            ("GET", "/v1/master/memory/entry") => {
                let request: MemoryEntryQuery = from_value(query)?;
                let document = self.namespace_read(session, &request.ns).await?;
                let entries = document
                    .document
                    .into_iter()
                    .filter(|entry| request.key.as_ref().is_none_or(|key| key == &entry.key))
                    .map(|entry| ApiMemoryEntry::from_stored(&request.ns, entry))
                    .collect::<Vec<_>>();
                json!({"ns":request.ns,"entries":entries})
            }
            ("POST", "/v1/master/memory/plant") => {
                let request: MasterMemoryPlantRequest = from_value(body)?;
                let entries = request.entries.clone();
                let mut response = self.plant(session, request).await?;
                if let Err(error) = self.register_note_rows(session, &entries).await {
                    response.taxonomy_status = format!(
                        "{}; resource registry failed: {error}",
                        response.taxonomy_status
                    );
                }
                to_value(response)?
            }
            ("GET", "/v1/master/knowledge/history") => {
                let request: HistoryQuery = from_value(query)?;
                to_value(self.history(session, &request.ns, &request.key).await?)?
            }
            ("GET", "/v1/master/knowledge/history/version") => {
                let request: HistoryVersionQuery = from_value(query)?;
                to_value(
                    self.history_version(session, &request.ns, &request.key, request.n)
                        .await?,
                )?
            }
            ("GET", "/v1/master/config/presets") => {
                json!({"default_id":agentkeys_protocol::presets::DEFAULT_PRESET_ID,
                "presets":agentkeys_protocol::presets::bundled_presets().iter().map(|preset|json!({"id":preset.id,"label":preset.label,"description":preset.description,"categories":preset_categories(preset)})).collect::<Vec<_>>()})
            }
            ("POST", "/v1/master/config/init") => {
                let request: InitConfigRequest = from_value(body)?;
                let preset = agentkeys_protocol::presets::resolve_preset(&request.preset_id)
                    .ok_or_else(|| invalid("unknown preset_id"))?;
                to_value(InitConfigResponse {
                    preset_id: preset.id.into(),
                    taxonomy_status: "ok".into(),
                    categories: self
                        .reconcile_taxonomy(session, &preset_categories(preset))
                        .await?,
                })?
            }
            ("GET", "/v1/master/credentials") => {
                json!({"credentials":self.credential_list(session).await?})
            }
            ("POST", "/v1/master/credentials/store") => {
                let request: StoreCredRequest = from_value(body)?;
                let service = request.service.trim().to_lowercase();
                if service.is_empty() || service.len() > 64 || request.secret.is_empty() {
                    return Err(invalid("service and secret are required"));
                }
                self.data
                    .credential_store(session, &service, request.secret.as_bytes())
                    .await?;
                json!({"ok":true,"service":service,"category":self.data.classify_tag(session,"credentials",&service).await?.0.category})
            }
            ("POST", "/v1/master/classify/tag") => {
                let request: ClassifyTagRequest = from_value(body)?;
                let data_class =
                    normalize_data_class(&request.data_class).map_err(|error| invalid(&error))?;
                if request.entity.trim().is_empty() {
                    return Err(invalid("entity is required"));
                }
                let (classification, audited) = self
                    .data
                    .classify_tag(session, data_class, &request.entity)
                    .await?;
                json!({"data_class":data_class,"entity":request.entity.trim().to_lowercase(),"service":service_for(data_class,&request.entity),"classification":classification,"audited":audited})
            }
            ("POST", "/v1/master/classify/propose") => {
                let request: ProposeRequest = from_value(body)?;
                let mut proposals = Vec::new();
                for item in request.surface {
                    let data_class =
                        normalize_data_class(&item.data_class).map_err(|error| invalid(&error))?;
                    if item.entity.trim().is_empty() {
                        continue;
                    }
                    let (classification, _) = self
                        .data
                        .classify_tag(session, data_class, &item.entity)
                        .await?;
                    proposals.push(ProposedScope {
                        data_class: data_class.into(),
                        entity: item.entity.trim().to_lowercase(),
                        service: service_for(data_class, &item.entity),
                        category: classification.category,
                        sensitivity: classification.sensitivity,
                        gating: gating_for(classification.sensitivity),
                        confidence: classification.confidence,
                    });
                }
                json!({"actor_id":request.actor_id,"proposals":proposals})
            }
            ("POST", "/v1/master/persona") => {
                let request: PersonaEditRequest = from_value(body)?;
                let version = self
                    .persona_edit(
                        session,
                        &request.delegate_omni,
                        &request.body,
                        &date_utc(session.now_unix_seconds),
                    )
                    .await?;
                json!({"ok":true,"stored":true,"delegate_omni":request.delegate_omni,"version":version,"body":request.body,"applied":false})
            }
            ("POST", "/v1/master/persona/rollback") => {
                let request: PersonaRollbackRequest = from_value(body)?;
                let (version, body) = self
                    .persona_rollback(
                        session,
                        &request.delegate_omni,
                        request.version,
                        &date_utc(session.now_unix_seconds),
                    )
                    .await?;
                json!({"ok":true,"stored":true,"delegate_omni":request.delegate_omni,"version":version,"body":body,"applied":false})
            }
            ("GET", "/v1/master/persona") => {
                let request: PersonaQuery = from_value(query)?;
                to_value(self.persona_read(session, &request.delegate).await?)?
            }
            ("POST", "/v1/master/persona/delete") => {
                let request: PersonaQueryBody = from_value(body)?;
                json!({"ok":true,"removed":self.persona_delete(session,&request.delegate_omni).await?})
            }
            _ => return Ok(None),
        };
        Ok(Some(output))
    }
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, DataError> {
    serde_json::to_vec(value).map_err(|error| DataError::Invalid(error.to_string()))
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DataError> {
    serde_json::from_slice(bytes).map_err(|error| DataError::Invalid(error.to_string()))
}
fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, DataError> {
    serde_json::from_value(value).map_err(|error| invalid(&error.to_string()))
}
fn to_value(value: impl Serialize) -> Result<Value, DataError> {
    serde_json::to_value(value).map_err(|error| DataError::Invalid(error.to_string()))
}
fn invalid(message: &str) -> DataError {
    DataError::Http {
        status: 400,
        body: json!({"error":message}).to_string(),
    }
}
fn missing(message: &str) -> DataError {
    DataError::Http {
        status: 404,
        body: json!({"error":message}).to_string(),
    }
}
fn query_value(path: &str) -> Value {
    let mut value = serde_json::Map::new();
    if let Some((_, query)) = path.split_once('?') {
        let mut url = reqwest::Url::parse("file:///").expect("constant URL");
        url.set_query(Some(query));
        for (key, text) in url.query_pairs() {
            let item = if key == "n" {
                text.parse::<u32>()
                    .map(|number| json!(number))
                    .unwrap_or_else(|_| json!(text))
            } else {
                json!(text)
            };
            value.insert(key.into_owned(), item);
        }
    }
    Value::Object(value)
}
fn preset_categories(preset: &agentkeys_protocol::presets::ConfigPreset) -> Vec<MemoryCategory> {
    preset
        .categories
        .iter()
        .map(|(namespace, label)| MemoryCategory {
            ns: (*namespace).into(),
            label: (*label).into(),
        })
        .collect()
}
