//! COMPILE + TAG (#178 §1 P2, §5) over the deterministic catalog tier-0.
//!
//! **The determinism guardrail (load-bearing, #178 §5):** these emit **tags +
//! proposed policy, never allow/deny**. The gate downstream decides by
//! set-membership; nothing here authorizes. A miss is `unknown` → deny-by-default.
//!
//! TAG is fully catalog-backed (entity → category). COMPILE is the deterministic
//! **tier-0** of the NL→policy compiler: it scans a sentence for known catalog
//! entities + category keywords and proposes the matched categories. The
//! LLM-backed COMPILE (richer NL coverage) is the deferred enhancement (#178
//! P2 engine / #207 item 1B) — this is the rules floor that ships first.

use crate::catalog::{Catalog, Classification};

// The COMPILE result types now live in `agentkeys-catalog` (the ONE definition,
// shared with the dataset validator) — re-exported so `crate::classify::CompileResult`
// keeps resolving for the worker's HTTP handlers.
pub use crate::catalog::{CompileResult, ProposedCategory};

/// TAG one entity → its classification (catalog lookup). The `data_class` is the
/// authorization context (bound to the cap); the lookup itself is unified by
/// entity, so this is a single O(1) hashmap hit.
pub fn tag(catalog: &Catalog, entity: &str) -> Classification {
    catalog.tag(entity)
}

/// Deterministic COMPILE tier-0: tokenize, map each known catalog entity OR
/// category keyword to a category, dedupe. Honest minimal NL→policy — it covers
/// the "sentence names known services/categories" case; the open-vocabulary tail
/// is the deferred LLM engine.
pub fn compile(catalog: &Catalog, sentence: &str) -> CompileResult {
    let mut seen = std::collections::BTreeSet::new();
    let mut categories: Vec<ProposedCategory> = Vec::new();
    let mut unmatched: Vec<String> = Vec::new();

    for raw in sentence.split(|c: char| !c.is_alphanumeric() && c != '-') {
        let token = raw.trim().to_lowercase();
        if token.len() < 3 {
            continue;
        }
        // 1) the token IS a known entity → its category.
        let c = catalog.tag(&token);
        if c.confidence > 0.0 {
            if seen.insert(c.category.clone()) {
                categories.push(ProposedCategory {
                    category: c.category,
                    sensitivity: c.sensitivity,
                    matched: token,
                });
            }
            continue;
        }
        // 2) the token IS a category name the catalog vouches for (floor known).
        if catalog.has_category(&token) {
            if seen.insert(token.clone()) {
                categories.push(ProposedCategory {
                    sensitivity: catalog.floor(&token),
                    category: token.clone(),
                    matched: token,
                });
            }
            continue;
        }
        // 3) a common keyword → category (a tiny rules layer over the catalog).
        if let Some(cat) = keyword_category(&token) {
            if seen.insert(cat.to_string()) {
                categories.push(ProposedCategory {
                    sensitivity: catalog.floor(cat),
                    category: cat.to_string(),
                    matched: token,
                });
            }
            continue;
        }
        if seen.insert(format!("__um__{token}")) {
            unmatched.push(token);
        }
    }

    CompileResult {
        categories,
        unmatched,
        engine: "catalog-rules".into(),
    }
}

/// A tiny keyword→category rules layer over the catalog, for COMPILE only — the
/// words a person uses in a sentence that aren't service ids ("invest" →
/// financial, "kids" → family). Kept deliberately small + deterministic; the
/// open vocabulary is the deferred LLM engine.
fn keyword_category(token: &str) -> Option<&'static str> {
    let c = match token {
        "invest" | "investment" | "investing" | "stocks" | "portfolio" => "financial",
        "pay" | "payment" | "payments" | "spend" | "spending" => "payments",
        "crypto" | "trading" | "exchange" => "exchange",
        "kid" | "kids" | "child" | "children" | "family" => "family",
        "health" | "fitness" | "medical" | "doctor" => "health",
        "work" | "business" | "company" => "business",
        "home" | "smart-home" | "iot" | "device" | "devices" => "smart-home",
        "travel" | "trip" | "flight" | "hotel" => "travel",
        "code" | "coding" | "dev" | "developer" | "programming" => "developer",
        _ => return None,
    };
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Sensitivity;

    #[test]
    fn tag_known_service() {
        let cat = Catalog::bundled();
        assert_eq!(tag(&cat, "stripe").category, "payments");
    }

    #[test]
    fn compile_extracts_known_services_and_keywords() {
        let cat = Catalog::bundled();
        let r = compile(
            &cat,
            "I use stripe to get paid, invest on the side, and have kids.",
        );
        let cats: Vec<&str> = r.categories.iter().map(|c| c.category.as_str()).collect();
        assert!(cats.contains(&"payments")); // from "stripe"
        assert!(cats.contains(&"financial")); // from "invest"
        assert!(cats.contains(&"family")); // from "kids"
    }

    #[test]
    fn compile_flags_sensitive_categories() {
        let cat = Catalog::bundled();
        let r = compile(&cat, "binance trading");
        let exch = r
            .categories
            .iter()
            .find(|c| c.category == "exchange")
            .unwrap();
        assert_eq!(exch.sensitivity, Sensitivity::Sensitive);
    }

    #[test]
    fn compile_collects_unmatched_tokens() {
        let cat = Catalog::bundled();
        let r = compile(&cat, "flibbertigibbet wamboozle");
        assert!(!r.unmatched.is_empty());
        assert!(r.categories.is_empty());
    }
}
