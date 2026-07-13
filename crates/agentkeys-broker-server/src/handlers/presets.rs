//! #428 (epic #425 S3/O3) — the broker-served preset catalog.
//!
//! Bundle sources live in the repo (`presets/<id>/`) and are **compiled in**
//! (`include_str!`, the chain-profile pattern) so the catalog is versioned
//! with the deployed ref: shipping a new/edited bundle is a broker redeploy,
//! never a client release (a marketplace later means new bundles server-side
//! under the same `agentkeys-protocol` wire shapes).
//!
//! **Content, never authority**: nothing here grants anything. The catalog is
//! static product content with no PII and no per-caller state, so the two GET
//! routes are UNAUTHENTICATED (the `/healthz` + OIDC-discovery posture) — the
//! spawn ceremony that consumes a preset stays J1+Touch-ID-gated, and the
//! suggestions in a manifest render as inert affordances until the operator
//! runs the explicit grant ceremony.
//!
//! Adding a bundle: create `presets/<id>/{preset.json,SOUL.md,skills/*.md}`,
//! add one [`BuiltinPreset`] row to [`BUILTINS`]. The tests below pin
//! id-uniqueness, manifest parseability, and manifest-id ↔ registry-id match.

use std::sync::OnceLock;

use agentkeys_protocol::{PresetBundle, PresetCatalogResponse, PresetSkillDoc, PresetSummary};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::Json;

/// One compiled-in bundle: the manifest JSON + persona + skills docs.
struct BuiltinPreset {
    manifest_json: &'static str,
    soul_md: &'static str,
    /// `(filename, content)` — the docs under `presets/<id>/skills/`.
    skills: &'static [(&'static str, &'static str)],
}

/// The v1 built-in catalog (#428 acceptance: the four household presets).
const BUILTINS: &[BuiltinPreset] = &[
    BuiltinPreset {
        manifest_json: include_str!("../../../../presets/default-assistant/preset.json"),
        soul_md: include_str!("../../../../presets/default-assistant/SOUL.md"),
        skills: &[(
            "TOOLS.md",
            include_str!("../../../../presets/default-assistant/skills/TOOLS.md"),
        )],
    },
    BuiltinPreset {
        manifest_json: include_str!("../../../../presets/health-master/preset.json"),
        soul_md: include_str!("../../../../presets/health-master/SOUL.md"),
        skills: &[(
            "TOOLS.md",
            include_str!("../../../../presets/health-master/skills/TOOLS.md"),
        )],
    },
    BuiltinPreset {
        manifest_json: include_str!("../../../../presets/kid-bestie/preset.json"),
        soul_md: include_str!("../../../../presets/kid-bestie/SOUL.md"),
        skills: &[(
            "TOOLS.md",
            include_str!("../../../../presets/kid-bestie/skills/TOOLS.md"),
        )],
    },
    BuiltinPreset {
        manifest_json: include_str!("../../../../presets/watchdog/preset.json"),
        soul_md: include_str!("../../../../presets/watchdog/SOUL.md"),
        skills: &[(
            "TOOLS.md",
            include_str!("../../../../presets/watchdog/skills/TOOLS.md"),
        )],
    },
];

/// The deployed ref the bundles were compiled from: an explicit build-time
/// `AGENTKEYS_BUILD_REF` (set by the host build when available) else the crate
/// version — never a runtime env read (the catalog is a compile-time artifact).
fn catalog_version() -> &'static str {
    option_env!("AGENTKEYS_BUILD_REF").unwrap_or(env!("CARGO_PKG_VERSION"))
}

/// Parse-once registry. A malformed compiled-in manifest is a programming
/// error caught by the tests below; at runtime it surfaces as a loud 500 on
/// first access rather than a boot crash (the catalog must never take the
/// cap-mint plane down with it).
fn registry() -> &'static Result<Vec<(PresetSummary, &'static BuiltinPreset)>, String> {
    static REGISTRY: OnceLock<Result<Vec<(PresetSummary, &'static BuiltinPreset)>, String>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut rows = Vec::with_capacity(BUILTINS.len());
        for b in BUILTINS {
            let summary: PresetSummary = serde_json::from_str(b.manifest_json)
                .map_err(|e| format!("compiled-in preset manifest failed to parse: {e}"))?;
            rows.push((summary, b));
        }
        Ok(rows)
    })
}

fn bundle_for(summary: &PresetSummary, b: &BuiltinPreset) -> PresetBundle {
    PresetBundle {
        manifest: summary.clone(),
        soul_md: b.soul_md.to_string(),
        skills: b
            .skills
            .iter()
            .map(|(filename, content)| PresetSkillDoc {
                filename: (*filename).to_string(),
                content: (*content).to_string(),
            })
            .collect(),
    }
}

/// `GET /v1/presets` — the catalog summaries.
pub async fn list_presets(
) -> Result<Json<PresetCatalogResponse>, (StatusCode, Json<serde_json::Value>)> {
    match registry() {
        Ok(rows) => Ok(Json(PresetCatalogResponse {
            catalog_version: catalog_version().to_string(),
            presets: rows.iter().map(|(s, _)| s.clone()).collect(),
        })),
        Err(e) => Err(crate::handlers::accept::aerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("preset catalog unavailable: {e}"),
        )),
    }
}

/// `GET /v1/presets/:id` — one full bundle.
pub async fn get_preset(
    Path(id): Path<String>,
) -> Result<Json<PresetBundle>, (StatusCode, Json<serde_json::Value>)> {
    match registry() {
        Ok(rows) => rows
            .iter()
            .find(|(s, _)| s.id == id)
            .map(|(s, b)| Json(bundle_for(s, b)))
            .ok_or_else(|| {
                crate::handlers::accept::aerr(
                    StatusCode::NOT_FOUND,
                    format!("unknown preset '{id}' — GET /v1/presets lists the catalog"),
                )
            }),
        Err(e) => Err(crate::handlers::accept::aerr(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("preset catalog unavailable: {e}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_manifest_parses_and_ids_are_unique() {
        let rows = registry()
            .as_ref()
            .expect("all compiled-in manifests parse");
        assert_eq!(rows.len(), BUILTINS.len());
        let mut ids: Vec<&str> = rows.iter().map(|(s, _)| s.id.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before, "duplicate preset id in BUILTINS");
        // The v1 catalog (#428 acceptance).
        for want in [
            "default-assistant",
            "health-master",
            "kid-bestie",
            "watchdog",
        ] {
            assert!(ids.contains(&want), "missing v1 built-in {want}");
        }
    }

    #[test]
    fn bundles_carry_persona_and_skills() {
        for (summary, b) in registry().as_ref().unwrap() {
            let bundle = bundle_for(summary, b);
            assert!(
                bundle.soul_md.contains("# Soul"),
                "{}: SOUL.md must be the persona layer",
                summary.id
            );
            assert!(
                !bundle.skills.is_empty() && !bundle.skills[0].content.trim().is_empty(),
                "{}: bundle must carry at least one non-empty skills doc",
                summary.id
            );
            assert!(!summary.version.trim().is_empty());
            assert!(
                !summary.name_zh.trim().is_empty(),
                "bilingual name required"
            );
        }
    }

    #[tokio::test]
    async fn catalog_lists_and_fetch_roundtrips_unknown_404s() {
        let catalog = list_presets().await.expect("catalog").0;
        assert_eq!(catalog.presets.len(), BUILTINS.len());
        assert!(!catalog.catalog_version.is_empty());

        let bundle = get_preset(Path("watchdog".to_string()))
            .await
            .expect("watchdog bundle")
            .0;
        assert_eq!(bundle.manifest.id, "watchdog");
        assert!(!bundle.manifest.schedule.is_empty());

        let err = get_preset(Path("nope".to_string())).await.unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}
