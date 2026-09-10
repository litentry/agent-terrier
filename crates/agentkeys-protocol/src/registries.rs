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
    /// The canonical memory namespace the item lives in (`memory:<ns>` is the
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
}

/// The `resource-registry` doc.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ResourceRegistryDoc {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub items: Vec<ResourceItemRow>,
}

impl ResourceRegistryDoc {
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
        }
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
