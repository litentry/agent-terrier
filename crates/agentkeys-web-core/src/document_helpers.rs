use agentkeys_protocol::{
    console::{default_stored_version, MemoryCategory, ScopeGating, StoredMemoryEntry},
    web_api::ApiMemoryEntry,
    ContextKind,
};

pub fn content_hash_for(ns: &str, key: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ns.as_bytes());
    h.update(b"\x1f");
    h.update(key.as_bytes());
    h.update(b"\x1f");
    h.update(body.as_bytes());
    hex::encode(h.finalize())
}

pub trait ApiMemoryEntryExt: Sized {
    fn compute_hash(&self) -> String;
    /// The on-disk form stored inside the per-namespace JSON array (#201 Phase 4).
    fn to_stored(&self) -> StoredMemoryEntry;
    /// Rehydrate a UI entry from a stored array element decrypted out of
    /// `knowledge:<ns>.enc`. `version`/`preview` are derived (not stored) and
    /// `content_hash` is left empty (the read path doesn't dedup).
    fn from_stored(ns: &str, s: StoredMemoryEntry) -> Self;
}

impl ApiMemoryEntryExt for ApiMemoryEntry {
    fn compute_hash(&self) -> String {
        content_hash_for(&self.ns, &self.key, &self.body)
    }

    fn to_stored(&self) -> StoredMemoryEntry {
        StoredMemoryEntry {
            key: self.key.clone(),
            title: self.title.clone(),
            body: self.body.clone(),
            updated: self.updated.clone(),
            bytes: self.bytes,
            version: self.version.clone(),
            kind: self.kind,
        }
    }

    fn from_stored(ns: &str, s: StoredMemoryEntry) -> Self {
        let preview = s.body.chars().take(80).collect();
        ApiMemoryEntry {
            ns: ns.to_string(),
            key: s.key,
            title: s.title,
            bytes: s.bytes,
            version: s.version,
            updated: s.updated,
            preview,
            body: s.body,
            content_hash: String::new(),
            kind: s.kind,
        }
    }
}

pub fn merge_categories(
    existing: Vec<MemoryCategory>,
    incoming: &[MemoryCategory],
) -> Vec<MemoryCategory> {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut out: Vec<MemoryCategory> = Vec::new();
    for c in existing {
        if seen.insert(c.ns.clone()) {
            out.push(c);
        }
    }
    for c in incoming {
        if seen.insert(c.ns.clone()) {
            out.push(c.clone());
        }
    }
    out.sort_by(|a, b| a.ns.cmp(&b.ns));
    out
}

/// Parse a decrypted `knowledge:<ns>` blob into its entries, tolerating BOTH the
/// new per-namespace JSON array (#201 Phase 4) and a legacy single-body blob
/// (pre-#201 / agent-written) — the latter becomes a one-element array keyed by
/// the namespace, so the read path never breaks on an old blob.
pub fn parse_stored_blob(plaintext: &str, ns: &str) -> Vec<StoredMemoryEntry> {
    let trimmed = plaintext.trim_start();
    if trimmed.starts_with('[') {
        if let Ok(entries) = serde_json::from_str::<Vec<StoredMemoryEntry>>(plaintext) {
            return entries;
        }
    }
    vec![StoredMemoryEntry {
        key: ns.to_string(),
        title: ns.to_string(),
        body: plaintext.to_string(),
        updated: String::new(),
        bytes: plaintext.len() as u64,
        version: default_stored_version(),
        kind: ContextKind::Knowledge,
    }]
}

/// Merge the DURABLE entries already stored in a namespace with the newly
/// planted entries, deduped by content hash (ns‖key‖body). Durable entries are
/// ALWAYS preserved (codex finding 1 — a plant must never drop already-stored
/// memory); a new entry whose content matches an existing one is a no-op,
/// otherwise it is appended. Sorted by key for a stable on-disk blob. Returns
/// the merged array plus the count of entries that were genuinely new to the
/// durable set (for the plant's `planted`/`skipped` accounting).
pub fn merge_stored_entries(
    ns: &str,
    durable: Vec<StoredMemoryEntry>,
    incoming: &[ApiMemoryEntry],
) -> (Vec<StoredMemoryEntry>, usize) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<StoredMemoryEntry> = Vec::new();
    for d in durable {
        if seen.insert(content_hash_for(ns, &d.key, &d.body)) {
            out.push(d);
        }
    }
    // D-K5 (`plan/knowledge-repository.md` §6) — identity = key: the same
    // content under a key is a no-op (an idempotent re-plant); a DIFFERENT body
    // under an existing key REPLACES it — a file has one current version.
    let mut newly_added = 0usize;
    for e in incoming {
        let hash = content_hash_for(ns, &e.key, &e.body);
        if seen.contains(&hash) {
            continue;
        }
        let (keep, replaced): (Vec<StoredMemoryEntry>, Vec<StoredMemoryEntry>) =
            out.drain(..).partition(|d| d.key != e.key);
        out = keep;
        for d in replaced {
            seen.remove(&content_hash_for(ns, &d.key, &d.body));
        }
        seen.insert(hash);
        out.push(e.to_stored());
        newly_added += 1;
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    (out, newly_added)
}

/// The first `<key>-N` (N ≥ 2) no durable entry uses — a "keep both" merge.
pub fn free_key(durable: &[StoredMemoryEntry], key: &str) -> String {
    (2..)
        .map(|n| format!("{key}-{n}"))
        .find(|k| !durable.iter().any(|d| &d.key == k))
        .unwrap_or_else(|| format!("{key}-2"))
}

/// The compare-and-swap base of a namespace blob (D-K5): the keccak-256 of the
/// plaintext exactly as the worker returned it.
pub fn blob_hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(agentkeys_device_core::keccak256(bytes)))
}

pub fn valid_history_coords(ns: &str, key: &str) -> bool {
    let ok = |s: &str, extra: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(c))
    };
    ok(ns, "-_") && ok(key, "-_.")
}

pub fn label_for_ns(ns: &str) -> String {
    let mut chars = ns.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

pub fn validate_delegate_omni(omni: &str) -> Result<(), String> {
    let hex = omni
        .strip_prefix("0x")
        .or_else(|| omni.strip_prefix("0X"))
        .unwrap_or(omni);
    if hex.len() >= 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "delegate_omni must be a 0x-hex actor omni (≥8 hex chars), got `{omni}`"
        ))
    }
}

pub fn normalize_data_class(s: &str) -> Result<&'static str, String> {
    match s.trim().to_lowercase().as_str() {
        "" | "credentials" | "cred" => Ok("credentials"),
        "memory" => Ok("memory"),
        "config" => Ok("config"),
        other => Err(format!("unknown data_class: {other}")),
    }
}

/// The auto-distribute gating tier for a category's sensitivity (#207 §3 inv. 2):
/// Safe → `auto` (auto-confirm + daily review); Sensitive → `k11` (explicit confirm).
/// The tier comes from the CATALOG floor, so a vendor/telemetry prior can't downgrade it.
pub fn gating_for(s: agentkeys_catalog::Sensitivity) -> ScopeGating {
    match s {
        agentkeys_catalog::Sensitivity::Safe => ScopeGating::Auto,
        agentkeys_catalog::Sensitivity::Sensitive => ScopeGating::K11,
    }
}

/// The signed `service` string a scope grant would be over: memory → `knowledge:<ns>`,
/// credentials/other → the lowercased entity (service id). Matches the cap layer.
pub fn service_for(data_class: &str, entity: &str) -> String {
    match data_class {
        "memory" => format!("knowledge:{}", entity.trim().to_lowercase()),
        _ => entity.trim().to_lowercase(),
    }
}

pub fn date_utc(now_unix_seconds: u64) -> String {
    let days = (now_unix_seconds / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn register_note_entries(
    reg: &mut agentkeys_protocol::ResourceRegistryDoc,
    entries: &[ApiMemoryEntry],
    now: u64,
) -> usize {
    use agentkeys_catalog::Sensitivity;
    use agentkeys_protocol::{ResourceItemRow, ResourceKind};
    let mut added = 0usize;
    let mut refreshed = 0usize;
    for e in entries {
        if e.kind != agentkeys_protocol::ContextKind::Knowledge
            || !agentkeys_protocol::is_valid_resource_id(&e.key)
        {
            continue;
        }
        let hash = content_hash_for(&e.ns, &e.key, &e.body);
        if let Some(row) = reg.items.iter_mut().find(|r| r.id == e.key) {
            // D-K5 — identity = key: the plant REPLACED this row's entry; the
            // row keeps its type and follows the content (next version).
            if row.ns == e.ns && row.content_hash != hash {
                row.content_hash = hash;
                row.bytes = e.body.len() as u64;
                row.updated_at = now;
                row.version += 1;
                refreshed += 1;
            }
            continue;
        }
        reg.upsert(ResourceItemRow {
            id: e.key.clone(),
            name: if e.title.trim().is_empty() {
                e.key.clone()
            } else {
                e.title.clone()
            },
            name_zh: String::new(),
            ns: e.ns.clone(),
            object_key: e.key.clone(),
            kind: ResourceKind::Note,
            tags: Vec::new(),
            sensitivity: Sensitivity::Safe,
            version: 0,
            content_hash: hash,
            bytes: e.body.len() as u64,
            created_at: now,
            updated_at: now,
            filename: String::new(),
            content_type: String::new(),
            raw_object_key: String::new(),
            raw_bytes: 0,
        });
        added += 1;
    }
    added + refreshed
}
