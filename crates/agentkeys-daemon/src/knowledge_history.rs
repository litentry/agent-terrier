//! #695 step G — history. Before an item's body is replaced or removed on
//! origin, what is there is kept: the body as the keyed memory object
//! `versions/<key>/<slot>` and one line in `versions/<key>/index`, both under
//! the item's own `knowledge:<ns>` grant (the #594 object mechanism — same cap,
//! same creds as the namespace blob). The slots form a RING of `keep` entries
//! (`slot = n % keep`): the newest version overwrites the oldest, so the bound
//! is a hard storage bound and needs no delete (the memory worker has none).
//! The console's History tab lists the index (newest first) and diffs a chosen
//! version against the current text; "restore" is an ordinary edit that saves
//! the old text as the next version — nothing here rewinds silently.

use serde::{Deserialize, Serialize};

/// Versions kept per item by default.
pub const DEFAULT_KEEP: u32 = 20;
/// The ceiling an operator may raise the ring to.
pub const MAX_KEEP: u32 = 100;
/// Operator knob: how many previous versions each item keeps.
pub const KEEP_ENV: &str = "AGENTKEYS_KNOWLEDGE_HISTORY_KEEP";

/// Parse the knob; unset / unparsable = the default, always within `1..=MAX_KEEP`.
pub fn keep_from(raw: Option<&str>) -> u32 {
    raw.and_then(|s| s.trim().parse::<u32>().ok())
        .map(|n| n.clamp(1, MAX_KEEP))
        .unwrap_or(DEFAULT_KEEP)
}

/// The ring size for this process (read once per write — the knob is read-only).
pub fn history_keep() -> u32 {
    keep_from(std::env::var(KEEP_ENV).ok().as_deref())
}

/// The index object of one item.
pub fn index_key(key: &str) -> String {
    format!("versions/{key}/index")
}

/// The body object of one stored version.
pub fn slot_key(key: &str, slot: u32) -> String {
    format!("versions/{key}/{slot}")
}

/// One stored previous version of an item (an index line).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct KnowledgeVersion {
    /// 1-based and monotonic per key — the commit number.
    pub n: u32,
    /// The ring slot holding the body (`versions/<key>/<slot>`).
    pub slot: u32,
    /// When it was stored (unix seconds) — the moment it stopped being current.
    #[ts(type = "number")]
    pub ts: u64,
    #[ts(type = "number")]
    pub bytes: u64,
    /// `content_hash_for(ns, key, body)` of the stored body.
    pub content_hash: String,
    /// What replaced it: `edit` · `remove` · `merge:<delegate>` · `plant`.
    pub by: String,
    /// The version label it carried while current (`v3`).
    pub label: String,
}

/// `versions/<key>/index` — the ring's table of contents, oldest first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionIndex {
    #[serde(default)]
    pub next: u32,
    #[serde(default)]
    pub versions: Vec<KnowledgeVersion>,
}

impl VersionIndex {
    /// The newest stored version, if any.
    pub fn newest(&self) -> Option<&KnowledgeVersion> {
        self.versions.last()
    }

    /// Record one more version: the next commit number takes slot `n % keep`,
    /// evicting whatever that slot held (its body is overwritten by the
    /// caller's put), and the table never lists more than `keep` lines.
    pub fn record(
        &mut self,
        keep: u32,
        ts: u64,
        bytes: u64,
        content_hash: String,
        by: &str,
        label: &str,
    ) -> KnowledgeVersion {
        let keep = keep.max(1);
        let n = self.next.max(1);
        let slot = n % keep;
        self.versions.retain(|v| v.slot != slot);
        let v = KnowledgeVersion {
            n,
            slot,
            ts,
            bytes,
            content_hash,
            by: by.to_string(),
            label: label.to_string(),
        };
        self.versions.push(v.clone());
        while self.versions.len() as u32 > keep {
            self.versions.remove(0);
        }
        self.next = n + 1;
        v
    }
}

/// `GET /v1/master/knowledge/history` — an item's stored versions, newest first.
#[derive(Debug, Clone, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct KnowledgeHistory {
    pub ns: String,
    pub key: String,
    /// The ring size — how many versions this item keeps at most.
    pub keep: u32,
    /// `durable` = read from the memory plane; `ram` = no durable plane on
    /// this daemon, history is not kept.
    pub storage: String,
    pub versions: Vec<KnowledgeVersion>,
}

/// `GET /v1/master/knowledge/history/version` — one stored version's text.
#[derive(Debug, Clone, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct KnowledgeVersionBody {
    pub version: KnowledgeVersion,
    pub body: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_is_parsed_and_clamped() {
        assert_eq!(keep_from(None), DEFAULT_KEEP);
        assert_eq!(keep_from(Some("")), DEFAULT_KEEP);
        assert_eq!(keep_from(Some("x")), DEFAULT_KEEP);
        assert_eq!(keep_from(Some(" 7 ")), 7);
        assert_eq!(keep_from(Some("0")), 1);
        assert_eq!(keep_from(Some("100000")), MAX_KEEP);
    }

    #[test]
    fn object_keys_are_valid_worker_keys() {
        // the worker accepts [a-z0-9._-] segments joined by '/'
        assert_eq!(index_key("food-prefs"), "versions/food-prefs/index");
        assert_eq!(slot_key("food-prefs", 3), "versions/food-prefs/3");
    }

    #[test]
    fn the_ring_wraps_and_the_index_never_exceeds_keep() {
        let mut ix = VersionIndex::default();
        for n in 1..=7u32 {
            let v = ix.record(
                3,
                100 + n as u64,
                10,
                format!("h{n}"),
                "edit",
                &format!("v{n}"),
            );
            assert_eq!(v.n, n);
            assert_eq!(v.slot, n % 3);
            assert!(ix.versions.len() <= 3, "keep bound at n={n}");
        }
        let ns: Vec<u32> = ix.versions.iter().map(|v| v.n).collect();
        assert_eq!(ns, vec![5, 6, 7], "the three newest survive, oldest first");
        assert_eq!(ix.next, 8);
        // slot 1 (n=7) evicted n=4; slot 2 (n=5) evicted n=2; slot 0 (n=6) evicted n=3
        assert_eq!(
            ix.versions.iter().find(|v| v.slot == 1).map(|v| v.n),
            Some(7)
        );
        assert_eq!(ix.newest().map(|v| v.label.as_str()), Some("v7"));
    }

    #[test]
    fn a_smaller_keep_trims_and_a_shared_slot_evicts_the_older_line() {
        let mut ix = VersionIndex::default();
        for n in 1..=5u32 {
            ix.record(10, 0, 1, format!("h{n}"), "plant", "v1");
        }
        assert_eq!(ix.versions.len(), 5);
        // the operator lowered the ring to 2: n=6 → slot 0, which evicts nothing
        // listed (slots were 1..5 under keep=10); the trim keeps the two newest.
        let v = ix.record(2, 0, 1, "h6".into(), "edit", "v2");
        assert_eq!(v.slot, 0);
        let ns: Vec<u32> = ix.versions.iter().map(|v| v.n).collect();
        assert_eq!(ns, vec![5, 6]);
        // n=7 takes slot 1 (n=5 sat in slot 5, so the trim drops it); n=8 takes
        // slot 0 and evicts n=6 by slot.
        ix.record(2, 0, 1, "h7".into(), "edit", "v3");
        let v8 = ix.record(2, 0, 1, "h8".into(), "edit", "v4");
        assert_eq!(v8.slot, 0);
        let ns: Vec<u32> = ix.versions.iter().map(|v| v.n).collect();
        assert_eq!(ns, vec![7, 8]);
    }

    #[test]
    fn the_index_round_trips_and_tolerates_an_empty_object() {
        let empty: VersionIndex = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.next, 0);
        assert!(empty.versions.is_empty());
        let mut ix = VersionIndex::default();
        ix.record(20, 1, 2, "h".into(), "merge:0xabcd…1234", "v1");
        let json = serde_json::to_string(&ix).unwrap();
        let back: VersionIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.versions, ix.versions);
        assert_eq!(back.next, 2);
    }
}
