//! Bundled default taxonomy presets — config-init entry point **A** (#207 item 1A).
//!
//! These are the **BUNDLED catalog defaults**: ~10 role-oriented preset taxonomies
//! a fresh master can adopt with one click to author a real `config/memory-taxonomy.enc`
//! ([`DataClass::Config`], #201). This is the deterministic, no-model bootstrap path —
//! distinct from entry point **B** (NL → COMPILE, #207 item 1B, deferred) and from the
//! **test-only** `plant` seed (which *derives* a taxonomy from whatever memory was
//! planted rather than authoring one).
//!
//! Distribution today is bundled-only; the registry / community catalog overlays
//! (#207 R2, the `ClearSigningCatalog` shape, arch.md §22) extend this set later
//! WITHOUT changing the consumer — the daemon just reads a longer list. Presets are a
//! single source of truth here per the no-hardcoded-values policy (a named constant
//! module, the sanctioned shape for bundled defaults).
//!
//! The shipped DEFAULT is the rich adult-household profile from the #207 resolved
//! decisions: *an adult with kids, runs a business, has IoT home appliances, in a
//! relationship (wife, parents), does investment* — so the out-of-the-box taxonomy
//! spans `{personal, family, kids, health, finance, business, smart-home, travel}`.

/// One bundled default taxonomy preset. `categories` is the authored
/// `(namespace, display-label)` tree — the namespaces become the memory
/// data class's category axis (`memory:<ns>`), exactly like a planted namespace,
/// but authored up front instead of derived from content.
pub struct ConfigPreset {
    /// Stable id the onboarding UI POSTs back to apply this preset.
    pub id: &'static str,
    /// Human label for the preset picker.
    pub label: &'static str,
    /// One-line description of who the preset fits.
    pub description: &'static str,
    /// `(namespace, label)` pairs — the authored category tree this preset writes.
    pub categories: &'static [(&'static str, &'static str)],
}

/// The shipped default preset id (#207 resolved decision 1 — the rich
/// adult-household profile). Used when the init request omits `preset_id`.
pub const DEFAULT_PRESET_ID: &str = "adult-household";

/// The bundled preset set. Role-oriented; region overlays arrive via the
/// catalog (#207 R2). The first entry is the [`DEFAULT_PRESET_ID`] profile.
pub fn bundled_presets() -> &'static [ConfigPreset] {
    PRESETS
}

/// Look up a preset by id, falling back to [`DEFAULT_PRESET_ID`] when the id is
/// empty (the UI sent no explicit choice). Returns `None` only for a non-empty
/// id that doesn't exist, so the caller can 400 on a genuinely bad id.
pub fn resolve_preset(id: &str) -> Option<&'static ConfigPreset> {
    let want = if id.is_empty() { DEFAULT_PRESET_ID } else { id };
    PRESETS.iter().find(|p| p.id == want)
}

static PRESETS: &[ConfigPreset] = &[
    ConfigPreset {
        id: "adult-household",
        label: "Adult household (default)",
        description:
            "An adult with kids, a business, IoT home appliances, a partner and parents, and investments.",
        categories: &[
            ("personal", "Personal"),
            ("family", "Family & Relationships"),
            ("kids", "Kids"),
            ("health", "Health"),
            ("finance", "Finance & Investment"),
            ("business", "Business"),
            ("smart-home", "Smart Home"),
            ("travel", "Travel"),
        ],
    },
    ConfigPreset {
        id: "single-professional",
        label: "Single professional",
        description: "Career-focused; finances, work, health and the occasional trip.",
        categories: &[
            ("personal", "Personal"),
            ("work", "Work"),
            ("finance", "Finance"),
            ("health", "Health"),
            ("productivity", "Productivity"),
            ("travel", "Travel"),
        ],
    },
    ConfigPreset {
        id: "student",
        label: "Student",
        description: "Studies, social life, a tight budget and getting around.",
        categories: &[
            ("personal", "Personal"),
            ("study", "Study"),
            ("finance", "Finance"),
            ("health", "Health"),
            ("social", "Social"),
            ("travel", "Travel"),
        ],
    },
    ConfigPreset {
        id: "parent-family",
        label: "Parent / family",
        description: "Raising kids: family logistics, schooling, health and the household.",
        categories: &[
            ("family", "Family"),
            ("kids", "Kids"),
            ("education", "Education"),
            ("health", "Health"),
            ("household", "Household"),
            ("finance", "Finance"),
        ],
    },
    ConfigPreset {
        id: "small-business-owner",
        label: "Small-business owner",
        description: "Running a business: customers, suppliers, people and the books.",
        categories: &[
            ("business", "Business"),
            ("finance", "Finance"),
            ("customers", "Customers"),
            ("suppliers", "Suppliers"),
            ("team", "Team"),
            ("marketing", "Marketing"),
        ],
    },
    ConfigPreset {
        id: "creator",
        label: "Creator",
        description: "Audience, projects and brand alongside the personal and the practical.",
        categories: &[
            ("personal", "Personal"),
            ("projects", "Projects"),
            ("audience", "Audience"),
            ("brand", "Brand"),
            ("finance", "Finance"),
            ("travel", "Travel"),
        ],
    },
    ConfigPreset {
        id: "investor",
        label: "Investor",
        description: "Markets, portfolio, taxes and the businesses behind them.",
        categories: &[
            ("finance", "Finance"),
            ("investment", "Investment"),
            ("markets", "Markets"),
            ("real-estate", "Real Estate"),
            ("taxes", "Taxes"),
            ("business", "Business"),
        ],
    },
    ConfigPreset {
        id: "smart-home-enthusiast",
        label: "Smart-home enthusiast",
        description: "A connected home: devices, energy, security and media.",
        categories: &[
            ("smart-home", "Smart Home"),
            ("devices", "Devices"),
            ("energy", "Energy"),
            ("security", "Security"),
            ("media", "Media"),
            ("personal", "Personal"),
        ],
    },
    ConfigPreset {
        id: "retiree",
        label: "Retiree",
        description: "Health, family, hobbies and a steady budget with time to travel.",
        categories: &[
            ("personal", "Personal"),
            ("health", "Health"),
            ("family", "Family"),
            ("finance", "Finance"),
            ("hobbies", "Hobbies"),
            ("travel", "Travel"),
        ],
    },
    ConfigPreset {
        id: "developer",
        label: "Developer",
        description: "Projects, infrastructure and continual learning.",
        categories: &[
            ("personal", "Personal"),
            ("projects", "Projects"),
            ("infra", "Infrastructure"),
            ("learning", "Learning"),
            ("finance", "Finance"),
            ("productivity", "Productivity"),
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ships_about_ten_presets() {
        // #207 resolved decision 1 — ~10 role/region presets.
        assert!(
            (9..=12).contains(&bundled_presets().len()),
            "expected ~10 presets, got {}",
            bundled_presets().len()
        );
    }

    #[test]
    fn default_is_the_rich_adult_profile() {
        // The shipped DEFAULT must be the adult-household profile spanning the
        // five life areas the #207 decision names.
        let def = resolve_preset("").expect("empty id resolves to default");
        assert_eq!(def.id, DEFAULT_PRESET_ID);
        let ns: Vec<&str> = def.categories.iter().map(|(n, _)| *n).collect();
        for required in ["kids", "business", "smart-home", "finance", "family"] {
            assert!(ns.contains(&required), "default preset missing {required}");
        }
    }

    #[test]
    fn every_preset_has_unique_nonempty_namespaces() {
        for p in bundled_presets() {
            assert!(!p.categories.is_empty(), "{} has no categories", p.id);
            let mut seen = std::collections::BTreeSet::new();
            for (ns, label) in p.categories {
                assert!(!ns.is_empty() && !label.is_empty(), "{} blank entry", p.id);
                assert!(seen.insert(*ns), "{} duplicate ns {ns}", p.id);
            }
        }
    }

    #[test]
    fn preset_ids_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for p in bundled_presets() {
            assert!(seen.insert(p.id), "duplicate preset id {}", p.id);
        }
    }

    #[test]
    fn unknown_nonempty_id_is_none() {
        assert!(resolve_preset("does-not-exist").is_none());
    }
}
