//! The category catalog (#207 item 6 / #178 §8.1) — a shared, versioned
//! lookup table mapping well-known **entities** (credential services, device
//! ids, memory keywords) → **categories**, each carrying a **sensitivity** tier.
//!
//! It is the deterministic **tier-0** of the classify cascade (catalog → … →
//! LLM → deny+ask): the catalog handles the bulk for free + auditably, and the
//! genuinely-novel tail is what a model would eventually cover. **Catalog ≠
//! policy**: it carries categories ("stripe is payments"), never a tenant's
//! grants — so it is generic, PII-free, and safe to bundle / open-source.
//!
//! ## Distribution (ClearSigningCatalog shape, arch.md §22)
//! `bundled defaults → registry fetch → community`. Today: **bundled** + a
//! **signed vendor-overlay** load path. A vendor overlay is a per-vendor
//! `{entity → category}` table an agent vendor ships at connect (#207 R2). It is
//! **signed** (vendor P-256 key) AND **bounded by the catalog's sensitivity
//! floor**: an overlay may RAISE a category's sensitivity but can NEVER lower it.
//! So a vendor mislabeling a door-lock "safe" cannot self-grant —
//! `access-control` is sensitivity-gated regardless of the vendor's label.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Sensitivity tier of a category. Drives the auto-distribute gate (#207 item 5):
/// `Safe` → auto-confirm + daily review; `Sensitive` → explicit per-grant K11.
/// Ordered `Safe < Sensitive` so the floor is a simple `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum Sensitivity {
    Safe,
    Sensitive,
}

impl Sensitivity {
    /// The stricter of two tiers (`Sensitive` wins). The sensitivity-floor rule.
    pub fn max(self, other: Sensitivity) -> Sensitivity {
        if self == Sensitivity::Sensitive || other == Sensitivity::Sensitive {
            Sensitivity::Sensitive
        } else {
            Sensitivity::Safe
        }
    }
}

/// The result of a TAG: the entity's category, its sensitivity, and a confidence
/// in `[0,1]`. A catalog hit is high-confidence; an unknown entity is the
/// `unknown()` deny-by-default (confidence 0, `Sensitive`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classification {
    pub category: String,
    pub sensitivity: Sensitivity,
    pub confidence: f32,
    /// `catalog` (bundled), `overlay:<vendor>` (signed vendor overlay), or
    /// `unknown` (no hit → deny-by-default).
    pub source: String,
}

impl Classification {
    /// Deny-by-default for an entity no catalog tier resolved: `unknown`
    /// category, `Sensitive`, confidence 0. The gate treats this as "not in
    /// scope + sensitive" → never auto-granted (#178 §6 deny-by-default).
    pub fn unknown() -> Self {
        Classification {
            category: "unknown".into(),
            sensitivity: Sensitivity::Sensitive,
            confidence: 0.0,
            source: "unknown".into(),
        }
    }
}

/// A signed vendor overlay (#207 R2). `entries` maps `entity → category`;
/// `sensitivities` optionally proposes a tier per category (clamped UP to the
/// floor on apply). Verified against a registered vendor pubkey before merge.
#[derive(Debug, Clone, Deserialize)]
pub struct VendorOverlay {
    pub vendor: String,
    #[serde(default)]
    pub entries: BTreeMap<String, String>,
    #[serde(default)]
    pub sensitivities: BTreeMap<String, Sensitivity>,
}

/// One catalog entry: the category an entity maps to (sensitivity is resolved
/// from the category floor at lookup, so an overlay can't smuggle a lower tier).
#[derive(Debug, Clone)]
struct Entry {
    category: String,
    source: String,
}

/// The catalog: `entity → Entry` + `category → sensitivity floor`. Lookups are
/// O(1); the floor map is the security backstop for overlays.
#[derive(Debug, Clone)]
pub struct Catalog {
    pub version: u32,
    entities: BTreeMap<String, Entry>,
    floors: BTreeMap<String, Sensitivity>,
}

impl Catalog {
    /// The bundled default catalog. Real, well-known services + a conservative
    /// sensitivity floor. Extended by signed overlays (#207 R2) and, later, a
    /// registry fetch.
    pub fn bundled() -> Self {
        let mut entities = BTreeMap::new();
        let mut floors = BTreeMap::new();

        // Category sensitivity floors. Sensitive = money, access, identity,
        // health, infra (per #207 spec §3); everything else Safe. A category not
        // listed here defaults to Sensitive at lookup (conservative — a vendor
        // can't introduce a "safe" category the catalog doesn't vouch for).
        for c in [
            "ai-services",
            "productivity",
            "communication",
            "developer",
            "media",
            "social",
            "shopping",
            "travel",
            "news",
        ] {
            floors.insert(c.to_string(), Sensitivity::Safe);
        }
        for c in [
            "payments",
            "exchange",
            "financial",
            "banking",
            "access-control",
            "health",
            "cloud-infra",
            "identity",
            "credentials",
        ] {
            floors.insert(c.to_string(), Sensitivity::Sensitive);
        }

        // entity → category (bundled). Lowercased keys; lookups lowercase too.
        let bundled: &[(&str, &str)] = &[
            // AI / model services (Safe)
            ("openrouter", "ai-services"),
            ("openai", "ai-services"),
            ("anthropic", "ai-services"),
            ("groq", "ai-services"),
            ("together", "ai-services"),
            ("huggingface", "ai-services"),
            // Developer tools (Safe)
            ("github", "developer"),
            ("gitlab", "developer"),
            ("vercel", "developer"),
            ("netlify", "developer"),
            ("npm", "developer"),
            // Productivity (Safe)
            ("notion", "productivity"),
            ("linear", "productivity"),
            ("asana", "productivity"),
            ("trello", "productivity"),
            ("airtable", "productivity"),
            // Communication (Safe)
            ("slack", "communication"),
            ("discord", "communication"),
            ("twilio", "communication"),
            ("sendgrid", "communication"),
            // Media (Safe)
            ("spotify", "media"),
            ("youtube", "media"),
            ("netflix", "media"),
            // Shopping (Safe)
            ("amazon", "shopping"),
            ("shopify", "shopping"),
            // Payments / money (Sensitive)
            ("stripe", "payments"),
            ("paypal", "payments"),
            ("square", "payments"),
            ("plaid", "financial"),
            ("wise", "financial"),
            // Exchanges / crypto (Sensitive)
            ("binance", "exchange"),
            ("coinbase", "exchange"),
            ("kraken", "exchange"),
            // Banking (Sensitive)
            ("chase", "banking"),
            // Cloud infra (Sensitive)
            ("aws", "cloud-infra"),
            ("gcp", "cloud-infra"),
            ("azure", "cloud-infra"),
            ("cloudflare", "cloud-infra"),
            // Identity / access (Sensitive)
            ("auth0", "identity"),
            ("okta", "identity"),
            ("august-lock", "access-control"),
            ("yale-lock", "access-control"),
            ("ring", "access-control"),
            // Health (Sensitive)
            ("epic", "health"),
            ("fitbit", "health"),
        ];
        for (entity, category) in bundled {
            entities.insert(
                entity.to_string(),
                Entry {
                    category: category.to_string(),
                    source: "catalog".into(),
                },
            );
        }

        Catalog {
            version: 1,
            entities,
            floors,
        }
    }

    /// The sensitivity FLOOR for a category — the minimum tier it can ever be.
    /// Unknown categories default to `Sensitive` (conservative).
    pub fn floor(&self, category: &str) -> Sensitivity {
        self.floors
            .get(category)
            .copied()
            .unwrap_or(Sensitivity::Sensitive)
    }

    /// Whether the catalog vouches for this category (has a floor for it). Used
    /// by COMPILE to tell a real category name from an unmatched token.
    pub fn has_category(&self, category: &str) -> bool {
        self.floors.contains_key(category)
    }

    /// Classify a MEMORY namespace (#207 item 8 — agent memory inheritance). A
    /// memory namespace IS the memory data class's category axis, so its
    /// sensitivity is the category FLOOR (`travel` → Safe, `health`/`finance` →
    /// Sensitive), NOT a service-entity lookup. A namespace the catalog doesn't
    /// vouch for defaults to `Sensitive` → the master must explicitly pick it
    /// (the "sensitive namespaces explicit pick" rule).
    pub fn classify_namespace(&self, ns: &str) -> Classification {
        let key = ns.trim().to_lowercase();
        let known = self.has_category(&key);
        Classification {
            sensitivity: self.floor(&key),
            confidence: if known { 0.9 } else { 0.5 },
            category: key,
            source: "catalog".into(),
        }
    }

    /// TAG an entity → its `Classification`. Catalog hit → high confidence; a
    /// miss → `Classification::unknown()` (deny-by-default). The sensitivity is
    /// ALWAYS resolved from the category floor (never from caller input), so an
    /// overlay can't smuggle a lower tier.
    pub fn tag(&self, entity: &str) -> Classification {
        let key = entity.trim().to_lowercase();
        match self.entities.get(&key) {
            Some(e) => Classification {
                category: e.category.clone(),
                sensitivity: self.floor(&e.category),
                confidence: if e.source == "catalog" { 0.95 } else { 0.85 },
                source: e.source.clone(),
            },
            None => Classification::unknown(),
        }
    }

    /// Apply a vendor overlay (#207 R2), enforcing the sensitivity floor: an
    /// overlay-proposed tier is clamped UP to the floor (`max`), never down, and
    /// a category the overlay introduces inherits the conservative default floor.
    /// The signature MUST already be verified ([`apply_signed_overlay`]).
    pub fn apply_overlay(&mut self, overlay: &VendorOverlay) {
        let src = format!("overlay:{}", overlay.vendor);
        // A vendor-proposed sensitivity may only RAISE the floor, never lower it.
        for (category, proposed) in &overlay.sensitivities {
            let floor = self.floor(category);
            self.floors.insert(category.clone(), floor.max(*proposed));
        }
        for (entity, category) in &overlay.entries {
            // Ensure the category has a floor (new categories default Sensitive).
            self.floors
                .entry(category.clone())
                .or_insert(Sensitivity::Sensitive);
            entities_insert(&mut self.entities, entity, category, &src);
        }
        self.version = self.version.saturating_add(1);
    }

    /// Verify a vendor overlay's P-256 signature over `Sha256(canonical json)`
    /// against a registered vendor pubkey, then [`apply_overlay`]. Returns the
    /// vendor id on success. The signature gate is what makes "vendor overlays
    /// signed" real; the floor in `apply_overlay` is what makes them bounded.
    pub fn apply_signed_overlay(
        &mut self,
        overlay_json: &[u8],
        sig_b64url: &str,
        vendor_pubkey_pem: &str,
    ) -> Result<String, OverlayError> {
        verify_overlay_sig(overlay_json, sig_b64url, vendor_pubkey_pem)?;
        let overlay: VendorOverlay =
            serde_json::from_slice(overlay_json).map_err(|e| OverlayError::Parse(e.to_string()))?;
        let vendor = overlay.vendor.clone();
        self.apply_overlay(&overlay);
        Ok(vendor)
    }
}

fn entities_insert(
    entities: &mut BTreeMap<String, Entry>,
    entity: &str,
    category: &str,
    source: &str,
) {
    entities.insert(
        entity.trim().to_lowercase(),
        Entry {
            category: category.to_string(),
            source: source.to_string(),
        },
    );
}

#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    #[error("vendor pubkey parse: {0}")]
    Key(String),
    #[error("overlay signature decode: {0}")]
    SigDecode(String),
    #[error("overlay signature invalid")]
    SigInvalid,
    #[error("overlay json parse: {0}")]
    Parse(String),
}

fn verify_overlay_sig(
    overlay_json: &[u8],
    sig_b64url: &str,
    vendor_pubkey_pem: &str,
) -> Result<(), OverlayError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use sha2::{Digest, Sha256};

    let mut h = Sha256::new();
    h.update(overlay_json);
    let digest = h.finalize();
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64url)
        .map_err(|e| OverlayError::SigDecode(e.to_string()))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| OverlayError::SigDecode(e.to_string()))?;
    let vk = VerifyingKey::from_public_key_pem(vendor_pubkey_pem)
        .map_err(|e| OverlayError::Key(e.to_string()))?;
    vk.verify(&digest, &sig)
        .map_err(|_| OverlayError::SigInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_tags_known_services_with_floor_sensitivity() {
        let cat = Catalog::bundled();
        let stripe = cat.tag("stripe");
        assert_eq!(stripe.category, "payments");
        assert_eq!(stripe.sensitivity, Sensitivity::Sensitive);
        assert!(stripe.confidence > 0.9);

        let notion = cat.tag("Notion"); // case-insensitive
        assert_eq!(notion.category, "productivity");
        assert_eq!(notion.sensitivity, Sensitivity::Safe);
    }

    #[test]
    fn unknown_entity_is_deny_by_default() {
        let cat = Catalog::bundled();
        let u = cat.tag("some-never-seen-service-xyz");
        assert_eq!(u.category, "unknown");
        assert_eq!(u.sensitivity, Sensitivity::Sensitive);
        assert_eq!(u.confidence, 0.0);
    }

    #[test]
    fn overlay_cannot_lower_sensitivity_below_floor() {
        // A vendor maliciously labels its lock "safe". The floor for
        // access-control is Sensitive — the overlay must NOT be able to lower it.
        let mut cat = Catalog::bundled();
        let overlay = VendorOverlay {
            vendor: "evil-vendor".into(),
            entries: BTreeMap::from([("sketchy-lock".to_string(), "access-control".to_string())]),
            sensitivities: BTreeMap::from([("access-control".to_string(), Sensitivity::Safe)]),
        };
        cat.apply_overlay(&overlay);
        let tag = cat.tag("sketchy-lock");
        assert_eq!(tag.category, "access-control");
        assert_eq!(
            tag.sensitivity,
            Sensitivity::Sensitive,
            "floor must win over a vendor's Safe label"
        );
        assert!(tag.source.starts_with("overlay:"));
    }

    #[test]
    fn overlay_may_raise_sensitivity() {
        // A vendor flags a normally-Safe category as Sensitive for its context —
        // raising IS allowed (the floor is a minimum, not a fixed value).
        let mut cat = Catalog::bundled();
        let overlay = VendorOverlay {
            vendor: "cautious-vendor".into(),
            entries: BTreeMap::from([("vendor-notes".to_string(), "productivity".to_string())]),
            sensitivities: BTreeMap::from([("productivity".to_string(), Sensitivity::Sensitive)]),
        };
        cat.apply_overlay(&overlay);
        assert_eq!(cat.floor("productivity"), Sensitivity::Sensitive);
        assert_eq!(cat.tag("vendor-notes").sensitivity, Sensitivity::Sensitive);
    }

    #[test]
    fn overlay_new_category_defaults_sensitive() {
        let mut cat = Catalog::bundled();
        let overlay = VendorOverlay {
            vendor: "v".into(),
            entries: BTreeMap::from([("widget".to_string(), "brand-new-cat".to_string())]),
            sensitivities: BTreeMap::new(),
        };
        cat.apply_overlay(&overlay);
        assert_eq!(cat.tag("widget").sensitivity, Sensitivity::Sensitive);
    }

    #[test]
    fn signed_overlay_rejects_bad_signature() {
        let mut cat = Catalog::bundled();
        // A well-formed PEM but the signature won't match (random).
        let (_sk, pk_pem) = test_keypair();
        let overlay_json = br#"{"vendor":"v","entries":{"x":"media"}}"#;
        let err = cat
            .apply_signed_overlay(overlay_json, "AAAA", &pk_pem)
            .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::SigInvalid | OverlayError::SigDecode(_)
        ));
    }

    #[test]
    fn signed_overlay_applies_with_valid_signature() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use p256::ecdsa::{signature::Signer, Signature};
        use sha2::{Digest, Sha256};
        let (sk, pk_pem) = test_keypair();
        let overlay_json = br#"{"vendor":"acme","entries":{"acme-widget":"media"}}"#;
        let mut h = Sha256::new();
        h.update(overlay_json);
        let sig: Signature = sk.sign(&h.finalize());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let mut cat = Catalog::bundled();
        let vendor = cat
            .apply_signed_overlay(overlay_json, &sig_b64, &pk_pem)
            .expect("valid sig applies");
        assert_eq!(vendor, "acme");
        assert_eq!(cat.tag("acme-widget").category, "media");
    }

    fn test_keypair() -> (p256::ecdsa::SigningKey, String) {
        use p256::pkcs8::EncodePublicKey;
        // Deterministic test key (not for production) — fixed 32-byte scalar.
        let sk = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let vk = sk.verifying_key();
        let pem = vk.to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap();
        (sk, pem)
    }
}
