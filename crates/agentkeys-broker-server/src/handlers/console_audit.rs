use crate::{error::BrokerError, state::SharedState};
use agentkeys_protocol::console_audit::{ConsoleAuditPage, ConsoleAuditQuery};
use agentkeys_web_core::{
    chain::decode_word,
    console_audit::{
        audit_cursor, audit_topics, decode_log, hex_integer, AUDIT_DEFAULT_LIMIT, AUDIT_MAX_LIMIT,
    },
};
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use futures_util::{stream, StreamExt, TryStreamExt};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

const AUDIT_QUERY_BLOCKS: u64 = 2048;
const AUDIT_BLOCK_READ_CONCURRENCY: usize = 8;

fn invalid(error: impl std::fmt::Display) -> BrokerError {
    BrokerError::BadRequest(error.to_string())
}
fn upstream(error: impl std::fmt::Display) -> BrokerError {
    BrokerError::BackendUnreachable(error.to_string())
}
async fn rpc(
    http: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value, BrokerError> {
    let body: Value = http
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .map_err(upstream)?
        .error_for_status()
        .map_err(upstream)?
        .json()
        .await
        .map_err(upstream)?;
    if let Some(error) = body.get("error") {
        return Err(upstream(format!("audit chain read: {error}")));
    }
    body.get("result")
        .cloned()
        .ok_or_else(|| upstream("audit RPC result missing"))
}
struct AuditSelection {
    limit: usize,
    cursor: Option<(u64, u64)>,
    actor: Option<String>,
}
fn validate_query(
    query: &ConsoleAuditQuery,
    operator: &str,
) -> Result<AuditSelection, BrokerError> {
    let limit = query.limit.unwrap_or(AUDIT_DEFAULT_LIMIT);
    if limit == 0 || limit > AUDIT_MAX_LIMIT {
        return Err(invalid("audit limit is out of range"));
    }
    let cursor = query
        .cursor
        .as_deref()
        .map(audit_cursor)
        .transpose()
        .map_err(invalid)?;
    let actor = query
        .actor_id
        .as_deref()
        .map(|actor| if actor == "master" { operator } else { actor })
        .map(|actor| decode_word(actor).map(|word| format!("0x{}", hex::encode(word))))
        .transpose()
        .map_err(invalid)?;
    if query.roots_only == Some(true) && actor.is_some() {
        return Err(invalid("audit root query cannot filter an actor"));
    }
    Ok(AuditSelection {
        limit,
        cursor,
        actor,
    })
}
pub async fn recent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<ConsoleAuditQuery>,
) -> Result<Json<ConsoleAuditPage>, BrokerError> {
    let claims = super::wallet::require_master_session(&headers, &state)?;
    if !matches!(claims.agentkeys.identity_type.as_str(), "evm" | "passkey") {
        return Err(BrokerError::Unauthorized(
            "verified master session required".into(),
        ));
    }
    state
        .config
        .login_access
        .require_omni(&state, &claims.agentkeys.omni_account)
        .await?;
    let operator = format!(
        "0x{}",
        hex::encode(decode_word(&claims.agentkeys.omni_account).map_err(invalid)?)
    );
    let (url, registry) = super::accept::load_chain_read_config().map_err(upstream)?;
    let contract = super::anchor::audit_contract_for_registry(&registry)
        .map(|address| format!("0x{}", hex::encode(address)))
        .ok_or_else(|| upstream("CredentialAudit is not configured for this stack"))?;
    read_page(&state.http, &url, &contract, &operator, &query)
        .await
        .map(Json)
}

async fn read_page(
    http: &reqwest::Client,
    url: &str,
    contract: &str,
    operator: &str,
    query: &ConsoleAuditQuery,
) -> Result<ConsoleAuditPage, BrokerError> {
    let AuditSelection {
        limit,
        cursor,
        actor,
    } = validate_query(query, operator)?;
    let latest_block =
        hex_integer(&rpc(http, url, "eth_blockNumber", json!([])).await?).map_err(upstream)?;
    let before_block = cursor
        .map(|(block, _)| block)
        .unwrap_or(latest_block)
        .min(latest_block);
    let first_block = before_block.saturating_sub(AUDIT_QUERY_BLOCKS - 1);
    let signatures = audit_topics();
    let selected = if query.roots_only == Some(true) {
        vec![signatures[1].clone(), signatures[3].clone()]
    } else if actor.is_some() {
        vec![signatures[0].clone(), signatures[2].clone()]
    } else {
        signatures
    };
    let mut topics = vec![json!(selected), json!(operator)];
    if let Some(actor) = actor {
        topics.push(json!(actor));
    }
    let response=rpc(http,url,"eth_getLogs",json!([{"address":contract,"fromBlock":format!("0x{first_block:x}"),"toBlock":format!("0x{before_block:x}"),"topics":topics}])).await?;
    let logs = response
        .as_array()
        .ok_or_else(|| upstream("audit logs result is not an array"))?;
    let mut ordered = Vec::with_capacity(logs.len());
    for log in logs {
        let position = (
            hex_integer(
                log.get("blockNumber")
                    .ok_or_else(|| upstream("audit block missing"))?,
            )
            .map_err(upstream)?,
            hex_integer(
                log.get("logIndex")
                    .ok_or_else(|| upstream("audit index missing"))?,
            )
            .map_err(upstream)?,
        );
        if position.0 < first_block || position.0 > before_block {
            return Err(upstream(
                "audit RPC returned a block outside the requested page",
            ));
        }
        if cursor.is_none_or(|cursor| position < cursor) {
            ordered.push((position, log));
        }
    }
    ordered.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    let more = ordered.len() > limit;
    ordered.truncate(limit);
    let block_hashes = ordered
        .iter()
        .map(|(_, log)| {
            let hash = log
                .get("blockHash")
                .and_then(Value::as_str)
                .ok_or_else(|| upstream("audit block hash missing"))?;
            decode_word(hash).map_err(upstream)?;
            Ok(hash.to_owned())
        })
        .collect::<Result<BTreeSet<_>, BrokerError>>()?;
    let timestamps: HashMap<_, _> = stream::iter(block_hashes)
        .map(|block_hash| async move {
            let block = rpc(http, url, "eth_getBlockByHash", json!([block_hash, false])).await?;
            if !block
                .get("hash")
                .and_then(Value::as_str)
                .is_some_and(|hash| hash.eq_ignore_ascii_case(&block_hash))
            {
                return Err(upstream("audit block hash mismatch"));
            }
            let timestamp = hex_integer(
                block
                    .get("timestamp")
                    .ok_or_else(|| upstream("audit block timestamp missing"))?,
            )
            .map_err(upstream)?;
            Ok((block_hash, timestamp))
        })
        .buffer_unordered(AUDIT_BLOCK_READ_CONCURRENCY)
        .try_collect()
        .await?;
    let records = ordered
        .into_iter()
        .map(|(_, log)| {
            let block_hash = log
                .get("blockHash")
                .and_then(Value::as_str)
                .ok_or_else(|| upstream("audit block hash missing"))?;
            let timestamp = timestamps
                .get(block_hash)
                .ok_or_else(|| upstream("audit block timestamp missing"))?;
            decode_log(log, contract, operator, *timestamp).map_err(upstream)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if more {
        records.last().map(|record| record.event.id.clone())
    } else if first_block > 0 {
        Some(format!("{first_block}-0"))
    } else {
        None
    };
    Ok(ConsoleAuditPage {
        operator_omni: operator.into(),
        latest_block,
        records,
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "read-only live audit probe; requires explicit RPC, audit contract and test operator"]
    async fn live_audit_page() {
        let url = std::env::var("AGENTKEYS_CHAIN_RPC_HTTP").expect("set the selected stack RPC");
        let contract = std::env::var("CREDENTIAL_AUDIT_ADDRESS")
            .expect("set the selected stack audit contract");
        let operator =
            std::env::var("AGENTKEYS_TEST_OPERATOR_OMNI").expect("set the existing test operator");
        let started = std::time::Instant::now();
        let page = read_page(
            &reqwest::Client::new(),
            &url,
            &contract,
            &operator,
            &ConsoleAuditQuery {
                limit: Some(2),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(page.operator_omni, operator);
        assert!(page.records.len() <= 2);
        println!(
            "audit_records={} has_older_history={} elapsed_ms={}",
            page.records.len(),
            page.next_cursor.is_some(),
            started.elapsed().as_millis()
        );
    }

    #[tokio::test]
    async fn bounded_pages_preserve_same_block_order_and_continue_through_empty_history() {
        use axum::{routing::post, Router};
        use std::future::IntoFuture;
        fn log(block: u64, index: u64) -> Value {
            json!({
                "address":format!("0x{}", "ab".repeat(20)),
                "blockNumber":format!("0x{block:x}"), "logIndex":format!("0x{index:x}"),
                "blockHash":format!("0x{block:064x}"), "transactionHash":format!("0x{index:064x}"),
                "topics":[audit_topics()[2], format!("0x{}", "01".repeat(32)), format!("0x{}", "02".repeat(32)), format!("0x{:064x}", 1)],
                "data":format!("0x{}", "03".repeat(32))
            })
        }
        async fn serve(Json(body): Json<Value>) -> Json<Value> {
            let result = match body["method"].as_str().unwrap() {
                "eth_blockNumber" => json!("0x1004"),
                "eth_getLogs" => {
                    let filter = &body["params"][0];
                    let first = hex_integer(&filter["fromBlock"]).unwrap();
                    let last = hex_integer(&filter["toBlock"]).unwrap();
                    assert!(last - first < AUDIT_QUERY_BLOCKS);
                    assert_eq!(filter["address"], format!("0x{}", "ab".repeat(20)));
                    assert_eq!(filter["topics"][1], format!("0x{}", "01".repeat(32)));
                    json!([(4098, 1), (4097, 0), (2048, 0), (4098, 2)]
                        .into_iter()
                        .filter(|(block, _)| *block >= first && *block <= last)
                        .map(|(block, index)| log(block, index))
                        .collect::<Vec<_>>())
                }
                "eth_getBlockByHash" => json!({"hash":body["params"][0], "timestamp":"0x1000"}),
                method => panic!("unexpected method {method}"),
            };
            Json(json!({"jsonrpc":"2.0", "id":body["id"], "result":result}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(
            axum::serve(listener, Router::new().route("/", post(serve))).into_future(),
        );
        let mut query = ConsoleAuditQuery {
            limit: Some(2),
            ..Default::default()
        };
        let mut ids = Vec::new();
        let mut pages = 0;
        loop {
            let page = read_page(
                &reqwest::Client::new(),
                &url,
                &format!("0x{}", "ab".repeat(20)),
                &format!("0x{}", "01".repeat(32)),
                &query,
            )
            .await
            .unwrap();
            pages += 1;
            assert!(pages <= 5, "pagination stopped making progress");
            ids.extend(page.records.into_iter().map(|record| record.event.id));
            if page.next_cursor.is_none() {
                break;
            }
            assert_ne!(query.cursor, page.next_cursor);
            query.cursor = page.next_cursor;
        }
        server.abort();
        assert_eq!(ids, ["4098-2", "4098-1", "4097-0", "2048-0"]);
        assert!(pages > 2);
    }

    #[test]
    fn rejects_unknown_authority_and_invalid_pagination() {
        assert!(
            serde_json::from_value::<ConsoleAuditQuery>(json!({"operator_omni":"evil"})).is_err()
        );
        assert!(serde_json::from_value::<ConsoleAuditQuery>(json!({"rpc":"evil"})).is_err());
        let operator = format!("0x{}", "11".repeat(32));
        for query in [
            ConsoleAuditQuery {
                limit: Some(0),
                ..Default::default()
            },
            ConsoleAuditQuery {
                limit: Some(AUDIT_MAX_LIMIT + 1),
                ..Default::default()
            },
            ConsoleAuditQuery {
                cursor: Some("1:bad".into()),
                ..Default::default()
            },
            ConsoleAuditQuery {
                actor_id: Some("bad".into()),
                ..Default::default()
            },
        ] {
            assert!(validate_query(&query, &operator).is_err());
        }
        let query = ConsoleAuditQuery {
            actor_id: Some("master".into()),
            ..Default::default()
        };
        assert_eq!(
            validate_query(&query, &operator).unwrap().actor,
            Some(operator)
        );
    }
}
