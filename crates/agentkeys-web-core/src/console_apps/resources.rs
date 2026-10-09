use super::*;
use agentkeys_protocol::web_api::{ApiMemoryEntry, MasterMemoryPlantRequest};
struct CuratedResource {
    request: ResourceAddRequest,
    provenance: Option<(String, String, Vec<u8>)>,
}
impl ConsoleApps {
    pub(super) async fn resources(
        &self,
        session: &DataSession<'_>,
    ) -> Result<VersionedConfig<ResourceRegistryDoc>, DataError> {
        self.documents.resource_registry(session).await
    }
    pub(super) async fn resources_request(
        &self,
        session: &DataSession<'_>,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Option<Value>, DataError> {
        let result = match (method, path) {
            ("GET", "/v1/master/resources") => {
                json!({"items":self.resources(session).await?.document.items,"storage":"ok"})
            }
            ("POST", "/v1/master/resources/add") => {
                self.curate_resource(
                    session,
                    CuratedResource {
                        request: decode(body)?,
                        provenance: None,
                    },
                )
                .await?
            }
            ("POST", "/v1/master/resources/upload") => {
                let request: ResourceUploadRequest = decode(body)?;
                let raw = STANDARD
                    .decode(request.content_b64.trim())
                    .map_err(invalid)?;
                if raw.is_empty() || request.filename.trim().is_empty() {
                    return Err(invalid("filename and file bytes are required"));
                }
                if raw.len() > RESOURCE_UPLOAD_MAX_BYTES {
                    return Err(http_error(
                        413,
                        json!({"error":"file exceeds upload limit"}),
                    ));
                }
                let (text, image) =
                    extract_resource_text(&request.filename, &request.content_type, &raw)?;
                if image && request.kind != ResourceKind::Gallery {
                    return Err(invalid("an image must be a gallery item"));
                }
                self.curate_resource(
                    session,
                    CuratedResource {
                        request: ResourceAddRequest {
                            id: request.id,
                            name: request.name,
                            name_zh: request.name_zh,
                            kind: request.kind,
                            tags: request.tags,
                            sensitivity: request.sensitivity,
                            ns: request.ns,
                            body: text,
                            base_content_hash: request.base_content_hash,
                        },
                        provenance: Some((request.filename, request.content_type, raw)),
                    },
                )
                .await?
            }
            ("POST", "/v1/master/resources/remove") => {
                let request: ResourceRemoveRequest = decode(body)?;
                let id = request.id.trim().to_lowercase();
                let mut registry = self.resources(session).await?;
                let Some(row) = registry.find(&id).cloned() else {
                    return Ok(Some(json!({"ok":true,"removed":false})));
                };
                if !request.force {
                    let users = self
                        .apps(session)
                        .await?
                        .live()
                        .filter(|app| {
                            app.bindings
                                .resources
                                .iter()
                                .any(|binding| binding.item_id == id)
                        })
                        .map(|app| app.label.clone())
                        .collect::<Vec<_>>();
                    if !users.is_empty() {
                        return Err(http_error(
                            409,
                            json!({"reason":"resource_in_use","apps":users}),
                        ));
                    }
                }
                self.documents
                    .remove_entry(session, &row.ns, &row.id, "remove")
                    .await?;
                registry.remove(&id);
                self.documents
                    .config_write(session, RESOURCE_REGISTRY_SERVICE, &registry)
                    .await
                    .map_err(|error| {
                        invalid(format!(
                            "resource entry removed; registry save failed: {error}"
                        ))
                    })?;
                json!({"ok":true,"removed":true,"item":row,"storage":"ok"})
            }
            ("POST", "/v1/master/resources/retype") => {
                let request: ResourceRetypeRequest = decode(body)?;
                let mut registry = self.resources(session).await?;
                let item = registry
                    .retype(
                        &request.id.trim().to_lowercase(),
                        request.kind,
                        request.tags.map(normalize_tags),
                        request.sensitivity,
                        session.now_unix_seconds,
                    )
                    .cloned()
                    .ok_or_else(|| http_error(404, json!({"error":"resource not found"})))?;
                self.documents
                    .config_write(session, RESOURCE_REGISTRY_SERVICE, &registry)
                    .await?;
                json!({"ok":true,"item":item,"storage":"ok"})
            }
            _ => return Ok(None),
        };
        Ok(Some(result))
    }
    async fn curate_resource(
        &self,
        session: &DataSession<'_>,
        curated: CuratedResource,
    ) -> Result<Value, DataError> {
        let mut request = curated.request;
        request.id = request.id.trim().to_lowercase();
        request.ns = request.ns.trim().into();
        request.name = request.name.trim().into();
        if !is_valid_resource_id(&request.id)
            || request.ns.is_empty()
            || request.ns.contains(['/', '\\', '*', '?', ' '])
            || request.ns.contains("..")
            || request.ns == PERSONA_NAMESPACE
            || request.name.is_empty()
            || request.body.trim().is_empty()
        {
            return Err(invalid(
                "valid resource id, namespace, name and content are required",
            ));
        }
        let mut registry = self.resources(session).await?;
        if let Some(base) = &request.base_content_hash {
            if registry.find(&request.id).map(|item| &item.content_hash) != Some(base) {
                return Err(http_error(
                    409,
                    json!({"error":"stale_base","id":request.id,"current":registry.find(&request.id),"current_content_hash":registry.find(&request.id).map(|row|&row.content_hash)}),
                ));
            }
        }
        let version = registry
            .find(&request.id)
            .map_or(1, |item| item.version + 1);
        let bytes = request.body.len() as u64;
        let plant = self
            .documents
            .plant(
                session,
                MasterMemoryPlantRequest {
                    entries: vec![ApiMemoryEntry {
                        ns: request.ns.clone(),
                        key: request.id.clone(),
                        title: request.name.clone(),
                        bytes,
                        version: format!("v{version}"),
                        updated: today(session.now_unix_seconds),
                        preview: request.body.chars().take(120).collect(),
                        body: request.body.clone(),
                        content_hash: String::new(),
                        kind: ContextKind::Resource,
                    }],
                },
            )
            .await?;
        if plant.taxonomy_status != "ok" {
            return Err(invalid(format!(
                "resource content saved; taxonomy save failed: {}",
                plant.taxonomy_status
            )));
        }
        let (filename, content_type, raw_object_key, raw_bytes, raw_stored) =
            match curated.provenance {
                Some((filename, content_type, raw)) => {
                    let key = format!("files/{}", request.id);
                    let previous = self
                        .data
                        .memory_get(session, &request.ns, Some(key.clone()))
                        .await?;
                    let revision = previous.as_deref().map(blob_hash).unwrap_or_default();
                    self.data
                        .memory_put(session, &request.ns, Some(key.clone()), &raw, &revision)
                        .await
                        .map_err(|error| {
                            invalid(format!(
                                "resource content saved; source upload failed: {error}"
                            ))
                        })?;
                    (filename, content_type, key, raw.len() as u64, Some(true))
                }
                None => (String::new(), String::new(), String::new(), 0, None),
            };
        registry.upsert(ResourceItemRow {
            id: request.id.clone(),
            name: request.name,
            name_zh: request.name_zh.trim().into(),
            ns: request.ns.clone(),
            object_key: request.id.clone(),
            kind: request.kind,
            tags: normalize_tags(request.tags),
            sensitivity: request.sensitivity,
            version: 0,
            content_hash: content_hash_for(&request.ns, &request.id, &request.body),
            bytes,
            created_at: session.now_unix_seconds,
            updated_at: session.now_unix_seconds,
            filename,
            content_type,
            raw_object_key,
            raw_bytes,
        });
        self.documents
            .config_write(session, RESOURCE_REGISTRY_SERVICE, &registry)
            .await
            .map_err(|error| {
                invalid(format!(
                    "resource content saved; registry save failed: {error}"
                ))
            })?;
        Ok(
            json!({"item":registry.find(&request.id),"version":version,"storage":"ok","extracted_bytes":bytes,"raw_stored":raw_stored}),
        )
    }
}
fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    tags.into_iter()
        .map(|tag| tag.trim().to_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect()
}
fn extract_resource_text(
    filename: &str,
    content_type: &str,
    bytes: &[u8],
) -> Result<(String, bool), DataError> {
    let lower = filename.to_ascii_lowercase();
    let extension = lower.rsplit('.').next().unwrap_or("");
    let content_type = content_type.to_ascii_lowercase();
    if content_type.starts_with("text/")
        || matches!(
            content_type.as_str(),
            "application/json" | "application/csv" | "application/x-yaml"
        )
        || matches!(
            extension,
            "txt" | "md" | "markdown" | "csv" | "tsv" | "json" | "yaml" | "yml"
        )
    {
        return Ok((String::from_utf8_lossy(bytes).into_owned(), false));
    }
    if content_type == "application/pdf" || extension == "pdf" {
        return pdf_extract::extract_text_from_mem(bytes)
            .map(|text| (text, false))
            .map_err(|error| {
                http_error(
                    422,
                    json!({"error":format!("PDF text extraction failed: {error}")}),
                )
            });
    }
    if content_type.starts_with("image/")
        || matches!(extension, "png" | "jpg" | "jpeg" | "gif" | "webp")
    {
        return Ok((
            format!("[image] {filename} ({} bytes, {content_type})", bytes.len()),
            true,
        ));
    }
    Err(http_error(415, json!({"error":"unsupported file type"})))
}
