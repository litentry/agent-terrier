use crate::{
    audit::AuditEnvelope,
    broker::BrokerClient,
    chain::{chain_word, decode_word},
    console::{broker_error, invalid},
    data::{DataClient, DataError, DataSession},
};
use agentkeys_device_core::keccak256;
use agentkeys_protocol::{
    console::{ApiAnchorBatch, ApiAnchorStatus, ApiAuditEvent},
    console_audit::*,
    console_chain::ConsoleConfig,
};
use serde_json::{json, Value};

pub const AUDIT_EVENTS: [&str; 4] = [
    "AuditAppended(bytes32,bytes32,bytes32,uint8,uint256,bytes32)",
    "AuditRootAppended(bytes32,bytes32,uint256,uint64)",
    "AuditAppendedV2(bytes32,bytes32,uint8,bytes32)",
    "AuditRootAppendedV2(bytes32,bytes32,bytes32,uint64)",
];
pub const AUDIT_DEFAULT_LIMIT: usize = 100;
pub const AUDIT_MAX_LIMIT: usize = 500;

pub fn audit_topics() -> Vec<String> {
    AUDIT_EVENTS
        .iter()
        .map(|name| format!("0x{}", hex::encode(keccak256(name.as_bytes()))))
        .collect()
}
pub fn hex_integer(value: &Value) -> Result<u64, String> {
    let raw = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or("chain integer is not hex")?;
    u64::from_str_radix(raw, 16).map_err(|_| "chain integer overflow".into())
}
fn uint(raw: &[u8], index: usize) -> Result<u64, String> {
    let word = chain_word(raw, index)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err("audit integer overflow".into());
    }
    Ok(u64::from_be_bytes(
        word[24..].try_into().map_err(|_| "audit integer")?,
    ))
}
pub fn audit_cursor(cursor: &str) -> Result<(u64, u64), String> {
    let (block, index) = cursor.split_once('-').ok_or("invalid audit cursor")?;
    Ok((
        block.parse().map_err(|_| "invalid audit cursor block")?,
        index.parse().map_err(|_| "invalid audit cursor index")?,
    ))
}
pub fn decode_log(
    log: &Value,
    contract: &str,
    operator: &str,
    timestamp: u64,
) -> Result<ConsoleAuditRecord, String> {
    if log.get("removed").and_then(Value::as_bool) == Some(true) {
        return Err("audit log was removed by a reorganization".into());
    }
    if !log
        .get("address")
        .and_then(Value::as_str)
        .is_some_and(|address| address.eq_ignore_ascii_case(contract))
    {
        return Err("audit log belongs to another contract".into());
    }
    let topics: Vec<String> =
        serde_json::from_value(log.get("topics").cloned().ok_or("audit topics missing")?)
            .map_err(|error| error.to_string())?;
    let operator_word = decode_word(operator)?;
    if topics.get(1).map(|value| decode_word(value)).transpose()? != Some(operator_word) {
        return Err("audit log belongs to another operator".into());
    }
    let signatures = audit_topics();
    let kind = signatures
        .iter()
        .position(|signature| {
            topics
                .first()
                .is_some_and(|topic| topic.eq_ignore_ascii_case(signature))
        })
        .ok_or("unknown audit event")?;
    let data = log
        .get("data")
        .and_then(Value::as_str)
        .ok_or("audit data missing")?;
    let raw = hex::decode(data.strip_prefix("0x").ok_or("audit data is not hex")?)
        .map_err(|error| error.to_string())?;
    let expected_topics = if kind == 0 || kind == 2 { 4 } else { 3 };
    let expected_words = if kind == 0 {
        3
    } else if kind == 2 {
        1
    } else {
        2
    };
    if topics.len() != expected_topics || raw.len() != expected_words * 32 {
        return Err("invalid audit event layout".into());
    }
    for topic in &topics {
        decode_word(topic)?;
    }
    let block_number = hex_integer(log.get("blockNumber").ok_or("audit block missing")?)?;
    let log_index = hex_integer(log.get("logIndex").ok_or("audit log index missing")?)?;
    let tx_hash = log
        .get("transactionHash")
        .and_then(Value::as_str)
        .ok_or("audit transaction hash missing")?;
    decode_word(tx_hash)?;
    let actor_omni = matches!(kind, 0 | 2).then(|| topics[2].clone());
    let envelope_hash = (kind == 2).then(|| format!("0x{}", hex::encode(&raw)));
    let merkle_root = matches!(kind, 1 | 3).then(|| topics[2].clone());
    let entry_count = if merkle_root.is_some() {
        Some(uint(&raw, 1)?)
    } else {
        None
    };
    let op_kind = if kind == 2 {
        Some(
            u8::try_from(uint(&decode_word(&topics[3])?, 0)?)
                .map_err(|_| "audit op kind overflow")?,
        )
    } else {
        None
    };
    let label = op_kind
        .and_then(crate::audit::AuditOpKind::from_u8)
        .map(|kind| kind.label().to_string())
        .unwrap_or_else(|| {
            if merkle_root.is_some() {
                "anchor.batch".into()
            } else {
                "audit.append".into()
            }
        });
    let time = chrono::DateTime::from_timestamp(
        i64::try_from(timestamp).map_err(|_| "audit timestamp overflow")?,
        0,
    )
    .ok_or("invalid audit timestamp")?
    .to_rfc3339();
    let actor = actor_omni.as_deref().unwrap_or(operator);
    let detail = if let Some(root) = &merkle_root {
        format!(
            "{} entries committed in root {root}",
            entry_count.unwrap_or(0)
        )
    } else if let Some(hash) = &envelope_hash {
        format!("Envelope {hash} committed on chain")
    } else {
        format!(
            "Credential audit entry {} committed on chain",
            uint(&raw, 1)?
        )
    };
    let event = ApiAuditEvent {
        id: format!("{block_number}-{log_index}"),
        ts: time,
        actor_id: if decode_word(actor)? == operator_word {
            "master".into()
        } else {
            actor.into()
        },
        actor: actor.into(),
        kind: label,
        detail,
        chip: "audit".into(),
        sev: "ok".into(),
        tx_hash: Some(tx_hash.into()),
        audit_envelope_hashes: envelope_hash.clone().map(|hash| vec![hash]),
    };
    Ok(ConsoleAuditRecord {
        event,
        operator_omni: format!("0x{}", hex::encode(operator_word)),
        actor_omni,
        block_number,
        log_index,
        timestamp,
        topics,
        data: data.into(),
        envelope_hash,
        merkle_root,
        entry_count,
        op_kind,
    })
}

pub fn decode_committed_envelope(
    record: &ConsoleAuditRecord,
    operator: &str,
    bytes: &[u8],
) -> Result<Value, DataError> {
    let hash = record
        .envelope_hash
        .as_ref()
        .ok_or_else(|| invalid("event does not contain an envelope commitment"))?;
    if decode_word(hash).map_err(invalid)? != keccak256(bytes) {
        return Err(invalid("stored audit envelope hash mismatch"));
    }
    let decoded = AuditEnvelope::from_canonical_cbor(bytes).map_err(invalid)?;
    if decoded.operator_omni != decode_word(operator).map_err(invalid)?
        || decoded.operator_omni != decode_word(&record.operator_omni).map_err(invalid)?
        || Some(decoded.op_kind) != record.op_kind
        || record
            .actor_omni
            .as_ref()
            .map(|actor| decode_word(actor))
            .transpose()
            .map_err(invalid)?
            != Some(decoded.actor_omni)
    {
        return Err(invalid(
            "stored audit envelope differs from chain commitment",
        ));
    }
    let mut value = decoded.to_json();
    value["canonical_cbor"] = json!(format!("0x{}", hex::encode(bytes)));
    Ok(value)
}

pub struct ConsoleAudit {
    broker: BrokerClient,
    data: DataClient,
    config: ConsoleConfig,
}
impl ConsoleAudit {
    pub fn new(broker: BrokerClient, data: DataClient, config: ConsoleConfig) -> Self {
        Self {
            broker,
            data,
            config,
        }
    }
    pub async fn page(
        &self,
        session: &DataSession<'_>,
        query: &str,
    ) -> Result<ConsoleAuditPage, DataError> {
        let page: ConsoleAuditPage = self
            .broker
            .get_json(&format!("/v1/console/audit{query}"), Some(session.bearer))
            .await
            .map_err(broker_error)?;
        if decode_word(&page.operator_omni).map_err(invalid)?
            != decode_word(session.operator_omni).map_err(invalid)?
        {
            return Err(invalid("audit page belongs to another operator"));
        }
        Ok(page)
    }
    pub async fn recent(
        &self,
        session: &DataSession<'_>,
        actor_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ApiAuditEvent>, DataError> {
        if limit == 0 || limit > AUDIT_MAX_LIMIT {
            return Err(invalid("audit limit is out of range"));
        }
        let mut query = format!("?limit={limit}");
        if let Some(actor) = actor_id {
            let actor = if actor == "master" {
                session.operator_omni
            } else {
                actor
            };
            decode_word(actor).map_err(invalid)?;
            query.push_str(&format!("&actor_id={actor}"));
        }
        Ok(self
            .page(session, &query)
            .await?
            .records
            .into_iter()
            .map(|record| record.event)
            .collect())
    }
    pub async fn decode(&self, session: &DataSession<'_>, id: &str) -> Result<Value, DataError> {
        let (block, index) = audit_cursor(id).map_err(invalid)?;
        let cursor = format!(
            "{block}-{}",
            index
                .checked_add(1)
                .ok_or_else(|| invalid("audit index overflow"))?
        );
        let record = self
            .page(session, &format!("?cursor={cursor}&limit=1"))
            .await?
            .records
            .into_iter()
            .next()
            .filter(|record| record.event.id == id)
            .ok_or_else(|| invalid("audit event not found"))?;
        let mut envelope = None;
        if let Some(hash) = &record.envelope_hash {
            let bytes = self.data.audit_fetch(hash).await?;
            envelope = Some(decode_committed_envelope(
                &record,
                session.operator_omni,
                &bytes,
            )?);
        }
        let contract = self
            .config
            .chain
            .contracts
            .iter()
            .find(|contract| contract.name == "CredentialAudit")
            .ok_or_else(|| invalid("CredentialAudit is not configured"))?;
        Ok(
            json!({"id":id,"kind":record.event.kind,"tier":"tier-2","tier_label":"committed on-chain","synthesized":false,
            "provenance":"CredentialAudit event and hash-verified stored envelope; event claims are not signer authentication",
            "envelope":envelope,"tx_hash":record.event.tx_hash,"tx":{"to_contract":"CredentialAudit","to_address":contract.address,"explorer_url":contract.explorer_url,
                "decoded":{"event_topics":record.topics,"event_data":record.data,"block_number":record.block_number,"log_index":record.log_index}},
            "root":record.merkle_root,"entry_count":record.entry_count}),
        )
    }
    pub async fn anchors(&self, session: &DataSession<'_>) -> Result<ApiAnchorStatus, DataError> {
        let page = self.page(session, "?roots_only=true&limit=20").await?;
        let last_anchor_at = page
            .records
            .first()
            .map(|record| record.timestamp)
            .unwrap_or(0);
        let recent = page
            .records
            .into_iter()
            .map(|record| ApiAnchorBatch {
                ts: record.event.ts,
                root: record.merkle_root.unwrap_or_default(),
                count: record.entry_count.unwrap_or(0),
                txn: record.event.tx_hash.unwrap_or_default(),
                conf: page.latest_block.saturating_sub(record.block_number) + 1,
            })
            .collect();
        Ok(ApiAnchorStatus {
            last_anchor_at,
            next_anchor_in: 0,
            recent,
        })
    }
    pub async fn request(
        &self,
        session: &DataSession<'_>,
        method: &str,
        path: &str,
    ) -> Result<Option<Value>, DataError> {
        if method != "GET" {
            return Ok(None);
        }
        if path.starts_with("/v1/audit/recent") {
            let query = path.strip_prefix("/v1/audit/recent").unwrap_or_default();
            if !query.is_empty() && !query.starts_with('?') {
                return Ok(None);
            }
            let page = self.page(session, query).await?;
            return Ok(Some(
                serde_json::to_value(ApiAuditPage {
                    events: page
                        .records
                        .into_iter()
                        .map(|record| record.event)
                        .collect(),
                    next_cursor: page.next_cursor,
                })
                .map_err(invalid)?,
            ));
        }
        if path == "/v1/anchor/status" {
            return Ok(Some(
                serde_json::to_value(self.anchors(session).await?).map_err(invalid)?,
            ));
        }
        if let Some(id) = path
            .strip_prefix("/v1/audit/")
            .and_then(|path| path.strip_suffix("/decode"))
        {
            return self.decode(session, id).await.map(Some);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn word(value: u64) -> String {
        format!("{value:064x}")
    }
    fn fixture(kind: usize) -> Value {
        let mut topics = vec![
            audit_topics()[kind].clone(),
            format!("0x{}", "11".repeat(32)),
            format!("0x{}", "22".repeat(32)),
        ];
        if kind == 0 {
            topics.push(format!("0x{}", "33".repeat(32)));
        }
        if kind == 2 {
            topics.push(format!("0x{}", word(1)));
        }
        let data = match kind {
            0 => format!("0x{}{}{}", word(1), word(4), "44".repeat(32)),
            2 => format!("0x{}", "44".repeat(32)),
            _ => format!("0x{}{}", word(2), word(7)),
        };
        json!({"address":format!("0x{}","aa".repeat(20)),"topics":topics,"data":data,"blockNumber":"0xa","logIndex":"0x2","transactionHash":format!("0x{}","bb".repeat(32)),"removed":false})
    }
    fn parse(log: &Value) -> Result<ConsoleAuditRecord, String> {
        decode_log(
            log,
            &format!("0x{}", "aa".repeat(20)),
            &format!("0x{}", "11".repeat(32)),
            1700000000,
        )
    }
    #[test]
    fn decodes_real_abi_layouts_for_entries_and_roots() {
        for kind in 0..4 {
            let record = parse(&fixture(kind)).unwrap();
            assert_eq!(record.event.id, "10-2");
            assert_eq!(record.block_number, 10);
            assert_eq!(record.merkle_root.is_some(), matches!(kind, 1 | 3));
            assert_eq!(record.envelope_hash.is_some(), kind == 2);
            if matches!(kind, 1 | 3) {
                assert_eq!(record.entry_count, Some(7));
            }
        }
    }
    #[test]
    fn rejects_foreign_operator_contract_malformed_removed_and_overflow_logs() {
        for (path, value) in [
            ("address", json!(format!("0x{}", "cc".repeat(20)))),
            ("data", json!("0x01")),
            ("removed", json!(true)),
            ("blockNumber", json!("0x10000000000000000")),
        ] {
            let mut log = fixture(2);
            log[path] = value;
            assert!(parse(&log).is_err());
        }
        let mut log = fixture(2);
        log["topics"][1] = json!(format!("0x{}", "cc".repeat(32)));
        assert!(parse(&log).is_err());
        let mut log = fixture(2);
        log["topics"][3] = json!(format!("0x{}", word(256)));
        assert!(parse(&log).is_err());
    }
    #[test]
    fn verifies_envelope_hash_operator_actor_and_kind_before_decode() {
        let envelope = crate::audit::envelope_for(
            [0x22; 32],
            [0x11; 32],
            crate::audit::AuditOpKind::CredStore,
            json!({"service":"test"}),
            crate::audit::AuditResult::Success,
            None,
            None,
        )
        .unwrap();
        let bytes = envelope.to_canonical_cbor().unwrap();
        let mut log = fixture(2);
        log["data"] = json!(format!("0x{}", hex::encode(keccak256(&bytes))));
        log["topics"][3] = json!(format!("0x{}", word(envelope.op_kind.into())));
        let record = parse(&log).unwrap();
        let operator = &record.operator_omni;
        assert!(decode_committed_envelope(&record, operator, &bytes).is_ok());
        assert!(
            decode_committed_envelope(&record, &format!("0x{}", "ff".repeat(32)), &bytes).is_err()
        );
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(decode_committed_envelope(&record, operator, &changed).is_err());
        let mut changed = record.clone();
        changed.actor_omni = Some(format!("0x{}", "ff".repeat(32)));
        assert!(decode_committed_envelope(&changed, operator, &bytes).is_err());
        let mut changed = record.clone();
        changed.op_kind = Some(255);
        assert!(decode_committed_envelope(&changed, operator, &bytes).is_err());
    }
    #[test]
    fn pagination_cursor_is_url_path_safe_and_preserves_same_block_order() {
        assert_eq!(audit_cursor("10-2").unwrap(), (10, 2));
        assert!(audit_cursor("10-3").unwrap() > audit_cursor("10-2").unwrap());
        for raw in ["10:2", "10--2", "10-", "18446744073709551616-1"] {
            assert!(audit_cursor(raw).is_err());
        }
    }
}
