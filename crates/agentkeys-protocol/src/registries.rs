//! The two policy-class registry docs the framework adds (#664, arch.md §17.7
//! rows): the **`app-registry`** (readable install state — template@version,
//! bindings, delegate omni, status) and the **`resource-registry`** (curated
//! read-only items — `id → {ns, object_key, kind, tags, sensitivity, version}`).
//! Records, NEVER authority (D1): the chain rows the install ceremony minted
//! are the authority; these docs let the console and the CLI read what was
//! installed and what may be bound. Both ride the Config data class through
//! the daemon's existing master-only `config-store` / `config-fetch` paths
//! (the `channel-registry` / `binding-manifest` pattern).

use serde::{Deserialize, Serialize};

use crate::{AppInstallBindings, Availability, BoundChannel, ResourceKind, Sensitivity};

/// The Config-class service name of the app registry doc.
pub const APP_REGISTRY_SERVICE: &str = "app-registry";
/// The Config-class service name of the resource registry doc.
pub const RESOURCE_REGISTRY_SERVICE: &str = "resource-registry";

/// An installed application's lifecycle state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum AppInstanceStatus {
    /// The install ceremony was submitted; the chain has not confirmed yet.
    Pending,
    #[default]
    Installed,
    /// The archive ceremony closed it (grants revoked, slot freed).
    Uninstalled,
}

impl AppInstanceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AppInstanceStatus::Pending => "pending",
            AppInstanceStatus::Installed => "installed",
            AppInstanceStatus::Uninstalled => "uninstalled",
        }
    }
}

/// One `app instance` row (arch.md §5): template@version ⊗ the master's
/// bindings ⊗ the minted grant set ⊗ its delegate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppInstanceRow {
    /// The delegate label (unique per operator) — the instance id.
    pub label: String,
    pub template_id: String,
    pub template_version: String,
    #[serde(default)]
    pub template_schema: u32,
    /// The delegate's HDKD child omni (`0x`).
    pub actor_omni: String,
    pub device_key_hash: String,
    pub memory_ns: String,
    pub chat_channel_id: String,
    #[serde(default)]
    pub bindings: AppInstallBindings,
    #[serde(default)]
    pub bound_channels: Vec<BoundChannel>,
    /// The delegate's granted service NAMES at install (the sheet).
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub availability: Availability,
    #[serde(default)]
    pub status: AppInstanceStatus,
    #[ts(type = "number")]
    pub installed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub uninstalled_at: Option<u64>,
    /// #425 O4 — the keep-vs-delete choice recorded at uninstall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub resources_kept: Option<bool>,
    /// The aliases the install wrote into contacts' `reach` (undone at
    /// uninstall) — one per messaging slot, normally just the label.
    #[serde(default)]
    pub reach_aliases: Vec<String>,
}

/// The `app-registry` doc.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppRegistryDoc {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub apps: Vec<AppInstanceRow>,
}

impl AppRegistryDoc {
    pub fn find(&self, label: &str) -> Option<&AppInstanceRow> {
        self.apps.iter().find(|a| a.label == label)
    }

    /// Insert or replace by label.
    pub fn upsert(&mut self, row: AppInstanceRow) {
        match self.apps.iter_mut().find(|a| a.label == row.label) {
            Some(existing) => *existing = row,
            None => self.apps.push(row),
        }
    }

    /// Live (installed or pending) instances.
    pub fn live(&self) -> impl Iterator<Item = &AppInstanceRow> {
        self.apps
            .iter()
            .filter(|a| a.status != AppInstanceStatus::Uninstalled)
    }
}

/// One `resource item` row (arch.md §5): a master-curated canonical memory
/// object registered for read-only distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ResourceItemRow {
    /// `^[a-z0-9-]{1,48}$`, unique in the registry.
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub name_zh: String,
    /// The canonical memory namespace the item lives in (`knowledge:<ns>` is the
    /// read-only grant an app compiles to).
    pub ns: String,
    /// The entry key inside the namespace's canonical blob.
    pub object_key: String,
    pub kind: ResourceKind,
    #[serde(default)]
    pub tags: Vec<String>,
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub content_hash: String,
    #[serde(default)]
    #[ts(type = "number")]
    pub bytes: u64,
    #[ts(type = "number")]
    pub created_at: u64,
    #[ts(type = "number")]
    pub updated_at: u64,
    /// Upload provenance (2026-09-13): the source file's name and media type,
    /// and the keyed memory object holding its raw bytes (`files/<id>`) — empty
    /// for a pasted item, or when no durable memory plane held the file.
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub raw_object_key: String,
    #[serde(default)]
    #[ts(type = "number")]
    pub raw_bytes: u64,
}

/// The `resource-registry` doc.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ResourceRegistryDoc {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub items: Vec<ResourceItemRow>,
    /// Rows a reader could not parse — a kind or field shape a NEWER build
    /// minted (measured 2026-09-13: two stacked branches sharing the VE test
    /// stack, the older one refusing the whole registry over one `note` row).
    /// Carried verbatim so an older daemon never erases them on its next
    /// write, and promoted back into `items` by a build that can read them.
    /// Never on the wire to the console.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[ts(skip)]
    pub opaque: Vec<serde_json::Value>,
}

impl ResourceRegistryDoc {
    /// Row-by-row load: every row under `items` or `opaque` this build can
    /// read becomes an item; the rest stay opaque. Returns the doc and the
    /// number of rows that stayed opaque. A document that is not an object is
    /// still an error.
    pub fn from_slice_lenient(bytes: &[u8]) -> Result<(Self, usize), serde_json::Error> {
        let v: serde_json::Value = serde_json::from_slice(bytes)?;
        if !v.is_object() {
            return Err(serde::de::Error::custom("resource-registry: not an object"));
        }
        let version = v.get("version").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        let mut items = Vec::new();
        let mut opaque = Vec::new();
        for key in ["items", "opaque"] {
            if let Some(rows) = v.get(key).and_then(|x| x.as_array()) {
                for row in rows {
                    match serde_json::from_value::<ResourceItemRow>(row.clone()) {
                        Ok(r) => items.push(r),
                        Err(_) => opaque.push(row.clone()),
                    }
                }
            }
        }
        let skipped = opaque.len();
        Ok((
            Self {
                version,
                items,
                opaque,
            },
            skipped,
        ))
    }

    pub fn find(&self, id: &str) -> Option<&ResourceItemRow> {
        self.items.iter().find(|i| i.id == id)
    }

    /// Insert (version 1) or replace (version + 1, `created_at` kept).
    pub fn upsert(&mut self, mut row: ResourceItemRow) -> u32 {
        match self.items.iter_mut().find(|i| i.id == row.id) {
            Some(existing) => {
                row.version = existing.version + 1;
                row.created_at = existing.created_at;
                *existing = row;
                existing.version
            }
            None => {
                row.version = 1;
                let v = row.version;
                self.items.push(row);
                v
            }
        }
    }

    /// Drop an item by id — the row, if it was registered.
    pub fn remove(&mut self, id: &str) -> Option<ResourceItemRow> {
        let idx = self.items.iter().position(|i| i.id == id)?;
        Some(self.items.remove(idx))
    }

    /// Change an item's TYPE metadata in place (D-K2 — the type is metadata, so
    /// a retype is not a new version): the kind, and optionally the tags and
    /// the tier. `None` when no row carries the id.
    pub fn retype(
        &mut self,
        id: &str,
        kind: ResourceKind,
        tags: Option<Vec<String>>,
        sensitivity: Option<Sensitivity>,
        now: u64,
    ) -> Option<&ResourceItemRow> {
        let row = self.items.iter_mut().find(|i| i.id == id)?;
        row.kind = kind;
        if let Some(t) = tags {
            row.tags = t;
        }
        if let Some(s) = sensitivity {
            row.sensitivity = s;
        }
        row.updated_at = now;
        Some(row)
    }

    /// Items a template request may bind: same kind, and every requested tag
    /// present when the request carries tags.
    pub fn matching<'a>(
        &'a self,
        kind: ResourceKind,
        tags: &'a [String],
    ) -> impl Iterator<Item = &'a ResourceItemRow> + 'a {
        self.items
            .iter()
            .filter(move |i| i.kind == kind && tags.iter().all(|t| i.tags.contains(t)))
    }
}

/// The resource-item id charset.
pub fn is_valid_resource_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, kind: ResourceKind, tags: &[&str]) -> ResourceItemRow {
        ResourceItemRow {
            id: id.into(),
            name: id.into(),
            name_zh: String::new(),
            ns: "household-health".into(),
            object_key: id.into(),
            kind,
            tags: tags.iter().map(|t| t.to_string()).collect(),
            sensitivity: Sensitivity::Safe,
            version: 0,
            content_hash: String::new(),
            bytes: 0,
            created_at: 10,
            updated_at: 10,
            filename: String::new(),
            content_type: String::new(),
            raw_object_key: String::new(),
            raw_bytes: 0,
        }
    }

    #[test]
    fn resource_registry_loads_row_by_row_and_keeps_what_it_cannot_read() {
        let good = serde_json::to_value(item("gene", ResourceKind::Document, &[])).unwrap();
        let mut newer = good.clone();
        newer["id"] = serde_json::json!("from-the-future");
        newer["kind"] = serde_json::json!("hologram");
        let doc = serde_json::json!({ "version": 3, "items": [good, newer] });
        let (reg, skipped) =
            ResourceRegistryDoc::from_slice_lenient(doc.to_string().as_bytes()).unwrap();
        assert_eq!(skipped, 1);
        assert_eq!(reg.version, 3);
        assert_eq!(reg.items.len(), 1);
        assert_eq!(reg.items[0].id, "gene");
        assert_eq!(reg.opaque[0]["id"], "from-the-future");
        // written back verbatim — an older build never erases the newer row
        let written = serde_json::to_string(&reg).unwrap();
        assert!(written.contains("\"hologram\""));
        // a build that can read a row parked under `opaque` promotes it
        let mut parked = serde_json::to_value(item("diet", ResourceKind::Profile, &[])).unwrap();
        parked["version"] = serde_json::json!(4);
        let doc = serde_json::json!({ "version": 1, "items": [], "opaque": [parked] });
        let (reg, skipped) =
            ResourceRegistryDoc::from_slice_lenient(doc.to_string().as_bytes()).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(reg.items[0].id, "diet");
        assert!(reg.opaque.is_empty());
        assert!(ResourceRegistryDoc::from_slice_lenient(b"[]").is_err());
    }

    #[test]
    fn resource_registry_retype_changes_only_metadata() {
        let mut reg = ResourceRegistryDoc::default();
        reg.upsert(item("wifi", ResourceKind::Note, &[]));
        reg.upsert(item("wifi", ResourceKind::Note, &[])); // v2
        let row = reg
            .retype(
                "wifi",
                ResourceKind::Profile,
                Some(vec!["home".into()]),
                Some(Sensitivity::Sensitive),
                99,
            )
            .cloned()
            .expect("row");
        assert_eq!(row.kind, ResourceKind::Profile);
        assert_eq!(row.tags, vec!["home".to_string()]);
        assert_eq!(row.sensitivity, Sensitivity::Sensitive);
        assert_eq!(row.version, 2, "a retype is metadata, never a version");
        assert_eq!(row.updated_at, 99);
        // kind only: tags + tier untouched
        let row = reg
            .retype("wifi", ResourceKind::Dataset, None, None, 100)
            .cloned()
            .unwrap();
        assert_eq!(row.tags, vec!["home".to_string()]);
        assert_eq!(row.sensitivity, Sensitivity::Sensitive);
        assert!(reg
            .retype("nope", ResourceKind::Note, None, None, 1)
            .is_none());
    }

    #[test]
    fn resource_registry_remove_drops_the_row_once() {
        let mut reg = ResourceRegistryDoc::default();
        reg.upsert(item("gene", ResourceKind::Document, &[]));
        reg.upsert(item("diet", ResourceKind::Profile, &[]));
        assert_eq!(reg.remove("gene").map(|r| r.id), Some("gene".to_string()));
        assert!(reg.remove("gene").is_none());
        assert_eq!(reg.items.len(), 1);
        assert_eq!(reg.items[0].id, "diet");
    }

    #[test]
    fn resource_registry_upsert_versions_and_matches_by_kind_and_tags() {
        let mut reg = ResourceRegistryDoc::default();
        assert_eq!(
            reg.upsert(item(
                "gene",
                ResourceKind::Document,
                &["genetics", "nutrition"]
            )),
            1
        );
        assert_eq!(
            reg.upsert(item("prefs", ResourceKind::Profile, &["diet"])),
            1
        );
        let mut newer = item("gene", ResourceKind::Document, &["genetics"]);
        newer.created_at = 99;
        assert_eq!(reg.upsert(newer), 2);
        let gene = reg.find("gene").unwrap();
        assert_eq!(gene.version, 2);
        assert_eq!(gene.created_at, 10, "created_at survives a re-add");
        let genetics = ["genetics".to_string()];
        let docs: Vec<&str> = reg
            .matching(ResourceKind::Document, &genetics)
            .map(|i| i.id.as_str())
            .collect();
        assert_eq!(docs, vec!["gene"]);
        let nutrition = ["nutrition".to_string()];
        assert!(reg
            .matching(ResourceKind::Document, &nutrition)
            .next()
            .is_none());
        assert_eq!(reg.matching(ResourceKind::Profile, &[]).count(), 1);
    }

    #[test]
    fn app_registry_upsert_and_live_filter() {
        let mut reg = AppRegistryDoc::default();
        let row = |label: &str, status: AppInstanceStatus| AppInstanceRow {
            label: label.into(),
            template_id: "chef".into(),
            template_version: "1.0.0".into(),
            template_schema: 1,
            actor_omni: "0xabc".into(),
            device_key_hash: "0xdef".into(),
            memory_ns: format!("app-{label}"),
            chat_channel_id: format!("opchat-{label}"),
            bindings: AppInstallBindings::default(),
            bound_channels: vec![],
            services: vec![],
            availability: Availability::AlwaysOn,
            status,
            installed_at: 1,
            uninstalled_at: None,
            resources_kept: None,
            reach_aliases: vec![label.to_string()],
        };
        reg.upsert(row("chef", AppInstanceStatus::Pending));
        reg.upsert(row("chef", AppInstanceStatus::Installed));
        reg.upsert(row("old", AppInstanceStatus::Uninstalled));
        assert_eq!(reg.apps.len(), 2);
        assert_eq!(
            reg.find("chef").unwrap().status,
            AppInstanceStatus::Installed
        );
        assert_eq!(reg.live().count(), 1);
        // Wire spelling + back-compat defaults.
        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("\"status\":\"installed\""));
        let old: AppRegistryDoc = serde_json::from_str(r#"{"apps":[]}"#).unwrap();
        assert_eq!(old.version, 0);
    }

    #[test]
    fn resource_id_charset() {
        assert!(is_valid_resource_id("gene-report"));
        assert!(!is_valid_resource_id("-gene"));
        assert!(!is_valid_resource_id("Gene"));
        assert!(!is_valid_resource_id(""));
    }
}
