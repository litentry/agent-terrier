//! Pluggable memory-engine seam — plan `docs/plan/agentkeys-memory-design.md`
//! §6a, arch.md §22 "Memory engine" axis.
//!
//! The engine runs CALLER-SIDE over already-gate-authorized memory lines —
//! never inside the worker, never with an LLM in the gate. `select` is the
//! load-bearing call: passive `pre_llm_call` injection passes `query = None`
//! plus a budget (which lines to inject when a namespace grows large); a
//! future `memory.search` tool passes `query = Some(..)`.
//!
//! External engines (OpenViking, Holographic, mem0-self-hosted, …) implement
//! this same trait — that is the compatibility seam (plan §6a.4): swap the
//! engine, hold store + gate + delivery constant. The two engines shipped
//! here are deterministic and need no external service.

use std::collections::HashSet;

/// One unit the engine ranks/selects over. In the v0 single-blob store a line
/// is a `\n`-split segment of a namespace blob; under the future per-line store
/// (plan M1) it maps 1:1 to a stored line. `seq` is blob position — higher is
/// later, treated as more recent for recency ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLine {
    pub text: String,
    pub seq: usize,
}

impl MemoryLine {
    pub fn from_blob(blob: &str) -> Vec<MemoryLine> {
        blob.lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .enumerate()
            .map(|(seq, text)| MemoryLine {
                text: text.to_string(),
                seq,
            })
            .collect()
    }
}

/// Upper bounds on what gets injected. Unbounded (both `None`) means the engine
/// is an identity passthrough — preserving today's full-blob injection.
#[derive(Debug, Clone, Default)]
pub struct SelectionBudget {
    pub max_lines: Option<usize>,
    pub max_bytes: Option<usize>,
}

impl SelectionBudget {
    pub fn is_unbounded(&self) -> bool {
        self.max_lines.is_none() && self.max_bytes.is_none()
    }

    pub fn from_env() -> SelectionBudget {
        SelectionBudget {
            max_lines: env_usize("AGENTKEYS_MEMORY_MAX_LINES"),
            max_bytes: env_usize("AGENTKEYS_MEMORY_MAX_BYTES"),
        }
    }
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key)
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
}

/// The pluggable engine. Input is gate-authorized lines; output is the ordered
/// subset to inject. Implementations MUST be pure (no LLM, no I/O in the gate
/// path) so the selection stays deterministic and auditable.
pub trait MemoryEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn select(
        &self,
        query: Option<&str>,
        lines: Vec<MemoryLine>,
        budget: &SelectionBudget,
    ) -> Vec<MemoryLine>;
}

/// Keep a prefix of a priority-ordered list within the budget.
fn apply_budget(ordered: Vec<MemoryLine>, budget: &SelectionBudget) -> Vec<MemoryLine> {
    let line_capped = match budget.max_lines {
        Some(max) => ordered.into_iter().take(max).collect(),
        None => ordered,
    };
    let Some(max_bytes) = budget.max_bytes else {
        return line_capped;
    };
    let mut used = 0usize;
    let mut kept = Vec::new();
    for line in line_capped {
        let cost = line.text.len() + 1;
        if used + cost > max_bytes && !kept.is_empty() {
            break;
        }
        used += cost;
        kept.push(line);
    }
    kept
}

/// Identity engine — preserves the current behavior. Unbounded budget returns
/// every line untouched; a bounded budget keeps the most recent lines.
pub struct PassthroughEngine;

impl MemoryEngine for PassthroughEngine {
    fn name(&self) -> &'static str {
        "passthrough"
    }

    fn select(
        &self,
        _query: Option<&str>,
        lines: Vec<MemoryLine>,
        budget: &SelectionBudget,
    ) -> Vec<MemoryLine> {
        if budget.is_unbounded() {
            return lines;
        }
        let mut by_recency = lines;
        by_recency.sort_by_key(|line| std::cmp::Reverse(line.seq));
        apply_budget(by_recency, budget)
    }
}

/// Deterministic lexical engine. With a query it ranks by term overlap (recency
/// breaks ties); without a query it falls back to pure recency. No LLM, no
/// embeddings, no external service — a real reference engine for the seam.
pub struct LexicalEngine;

const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "did", "do", "does", "for", "from",
    "had", "has", "have", "in", "is", "it", "my", "of", "on", "or", "the", "to", "was", "what",
    "when", "where", "which", "who", "will", "with", "you", "your",
];

fn tokenize(text: &str) -> HashSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| token.len() > 1 && !STOPWORDS.contains(token))
        .map(|token| token.to_string())
        .collect()
}

impl MemoryEngine for LexicalEngine {
    fn name(&self) -> &'static str {
        "lexical"
    }

    fn select(
        &self,
        query: Option<&str>,
        lines: Vec<MemoryLine>,
        budget: &SelectionBudget,
    ) -> Vec<MemoryLine> {
        let query_terms = query.map(tokenize).unwrap_or_default();
        let mut scored: Vec<(i64, usize, MemoryLine)> = lines
            .into_iter()
            .map(|line| {
                let score = if query_terms.is_empty() {
                    0
                } else {
                    let line_terms = tokenize(&line.text);
                    query_terms
                        .iter()
                        .filter(|term| line_terms.contains(*term))
                        .count() as i64
                };
                (score, line.seq, line)
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
        let ordered = scored.into_iter().map(|(_, _, line)| line).collect();
        apply_budget(ordered, budget)
    }
}

pub fn engine_from_name(name: &str) -> Box<dyn MemoryEngine> {
    match name.trim().to_lowercase().as_str() {
        "lexical" => Box::new(LexicalEngine),
        _ => Box::new(PassthroughEngine),
    }
}

pub fn engine_from_env() -> Box<dyn MemoryEngine> {
    engine_from_name(&std::env::var("AGENTKEYS_MEMORY_ENGINE").unwrap_or_default())
}

/// Apply an engine to one namespace blob and return the injection-ready text.
/// Selected lines are re-sorted to chronological (`seq`) order so the injected
/// block reads naturally regardless of how the engine ranked internally. This
/// `blob -> blob` contract is the seam: swapping the engine never changes the
/// signature, only the selected subset.
pub fn select_blob(
    engine: &dyn MemoryEngine,
    query: Option<&str>,
    blob: &str,
    budget: &SelectionBudget,
) -> String {
    let lines = MemoryLine::from_blob(blob);
    if lines.is_empty() {
        return blob.trim().to_string();
    }
    let mut selected = engine.select(query, lines, budget);
    selected.sort_by_key(|line| line.seq);
    selected
        .into_iter()
        .map(|line| line.text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB: &str = "\
Chengdu trip — Apr 12 to 16, hotpot at Yulin.
Allergic to peanuts.
Prefers window seats on flights.
Tokyo conference in March, stayed in Shibuya.";

    fn budget(max_lines: Option<usize>) -> SelectionBudget {
        SelectionBudget {
            max_lines,
            max_bytes: None,
        }
    }

    #[test]
    fn passthrough_unbounded_is_identity() {
        let lines = MemoryLine::from_blob(BLOB);
        let out = PassthroughEngine.select(None, lines.clone(), &SelectionBudget::default());
        assert_eq!(out, lines);
    }

    #[test]
    fn passthrough_budget_keeps_most_recent() {
        let out = select_blob(&PassthroughEngine, None, BLOB, &budget(Some(2)));
        // most-recent two lines, re-sorted chronologically
        assert_eq!(
            out,
            "Prefers window seats on flights.\nTokyo conference in March, stayed in Shibuya."
        );
    }

    #[test]
    fn lexical_with_query_selects_relevant_line() {
        let out = select_blob(
            &LexicalEngine,
            Some("where did I go in Chengdu"),
            BLOB,
            &budget(Some(1)),
        );
        assert_eq!(out, "Chengdu trip — Apr 12 to 16, hotpot at Yulin.");
    }

    #[test]
    fn lexical_without_query_is_recency() {
        let out = select_blob(&LexicalEngine, None, BLOB, &budget(Some(1)));
        assert_eq!(out, "Tokyo conference in March, stayed in Shibuya.");
    }

    #[test]
    fn single_line_blob_unchanged_across_engines() {
        let single = "Chengdu trip — Apr 12 to 16, hotpot at Yulin.";
        let unbounded = SelectionBudget::default();
        assert_eq!(
            select_blob(&PassthroughEngine, None, single, &unbounded),
            single
        );
        assert_eq!(
            select_blob(&LexicalEngine, Some("chengdu"), single, &unbounded),
            single
        );
    }

    #[test]
    fn conformance_swap_engine_same_contract_different_selection() {
        // The seam definition (plan §6a.5): same blob + budget + query, swap
        // only the engine. The String->String contract holds for both; the
        // engine is the sole variable, so the selected subset differs.
        let query = Some("peanuts allergic");
        let b = budget(Some(1));
        let passthrough = select_blob(&PassthroughEngine, query, BLOB, &b);
        let lexical = select_blob(&LexicalEngine, query, BLOB, &b);
        assert_eq!(passthrough, "Tokyo conference in March, stayed in Shibuya."); // recency
        assert_eq!(lexical, "Allergic to peanuts."); // relevance
        assert_ne!(passthrough, lexical);
    }

    #[test]
    fn from_name_defaults_to_passthrough() {
        assert_eq!(engine_from_name("lexical").name(), "lexical");
        assert_eq!(engine_from_name("passthrough").name(), "passthrough");
        assert_eq!(engine_from_name("nonsense").name(), "passthrough");
        assert_eq!(engine_from_name("").name(), "passthrough");
    }

    #[test]
    fn empty_blob_stays_empty() {
        assert_eq!(
            select_blob(&PassthroughEngine, None, "   ", &SelectionBudget::default()),
            ""
        );
        assert_eq!(
            select_blob(&LexicalEngine, Some("x"), "", &SelectionBudget::default()),
            ""
        );
    }
}
