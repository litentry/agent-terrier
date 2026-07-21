//! #541 — cap-derived storage credentials: the worker exchanges the Channel
//! cap it just verified for short-lived, owner-scoped creds at the broker's
//! `/v1/cap/channel-sts`, instead of falling back to ambient credentials
//! (EC2 instance profile on AWS — the retired backdoor; nothing on VE, which
//! made every storage call fail). See arch.md §22e "storage credentials are
//! cap-derived, never ambient" and `handlers/channel_sts.rs` on the broker.
//!
//! Creds are cached per `(owner, channel)` until ~60 s before expiry so the
//! NRT long-poll (§14.12 — a poll re-lists at least twice per held request)
//! does not mint per call.

use std::collections::HashMap;

use tokio::sync::Mutex;

use agentkeys_protocol::ChannelStsCreds;
use agentkeys_worker_creds::aws_creds::StsCreds;
use agentkeys_worker_creds::errors::{err_502, ApiError};
use agentkeys_worker_creds::verify::CapToken;

/// Re-mint when fewer than this many seconds remain on the cached creds.
const EXPIRY_MARGIN_SECONDS: i64 = 60;

pub struct ChannelStsMinter {
    broker_url: String,
    bearer: String,
    http: reqwest::Client,
    cache: Mutex<HashMap<String, (StsCreds, i64)>>,
}

impl ChannelStsMinter {
    /// Both halves (`AGENTKEYS_BROKER_URL` + `AGENTKEYS_CHANNEL_STS_TOKEN`,
    /// written by `setup-broker-host.sh`) or `None` — the worker then serves
    /// header-relayed requests only and fails LOUDLY on the rest (never a
    /// silent ambient fallback).
    pub fn from_env(http: reqwest::Client) -> Option<Self> {
        let broker_url = std::env::var("AGENTKEYS_BROKER_URL").ok()?;
        let bearer = std::env::var("AGENTKEYS_CHANNEL_STS_TOKEN").ok()?;
        if broker_url.trim().is_empty() || bearer.trim().is_empty() {
            return None;
        }
        Some(Self::new(broker_url, bearer, http))
    }

    pub fn new(broker_url: String, bearer: String, http: reqwest::Client) -> Self {
        Self {
            broker_url: broker_url.trim_end_matches('/').to_string(),
            bearer,
            http,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Owner-scoped creds for `cap`'s channel — cached, minted on miss.
    pub async fn creds_for(
        &self,
        cap: &CapToken,
        owner: &str,
        channel_id: &str,
    ) -> Result<StsCreds, ApiError> {
        let key = format!("{owner}|{channel_id}");
        let now = unix_now();
        if let Some((creds, expiry)) = self.cache.lock().await.get(&key) {
            if now + EXPIRY_MARGIN_SECONDS < *expiry {
                return Ok(creds.clone());
            }
        }

        let url = format!("{}/v1/cap/channel-sts", self.broker_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.bearer)
            .json(&serde_json::json!({ "cap": cap }))
            .send()
            .await
            .map_err(|e| err_502(format!("channel-sts mint unreachable: {e}"), "sts_mint"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let body = body.chars().take(300).collect::<String>();
            return Err(err_502(
                format!("channel-sts mint HTTP {status}: {body}"),
                "sts_mint",
            ));
        }
        let minted: ChannelStsCreds = resp
            .json()
            .await
            .map_err(|e| err_502(format!("channel-sts mint bad body: {e}"), "sts_mint"))?;

        let creds = StsCreds {
            access_key_id: minted.access_key_id,
            secret_access_key: minted.secret_access_key,
            session_token: minted.session_token,
        };
        self.cache
            .lock()
            .await
            .insert(key, (creds.clone(), minted.expiration));
        Ok(creds)
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{routing::post, Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn dummy_cap() -> CapToken {
        serde_json::from_value(serde_json::json!({
            "payload": {
                "operator_omni": "0xabc",
                "actor_omni": "0xdef",
                "service": "channel-pub:opchat-test1",
                "op": "channel_publish",
                "data_class": "channel",
                "device_key_hash": "0x00",
                "k3_epoch": 1,
                "issued_at": 1,
                "expires_at": 0,
                "nonce": "n-1"
            },
            "broker_sig": "sig"
        }))
        .expect("worker CapToken accepts the broker wire shape")
    }

    async fn spawn_stub(hits: Arc<AtomicUsize>, expiration: i64) -> String {
        let app = Router::new().route(
            "/v1/cap/channel-sts",
            post(move |_body: Json<serde_json::Value>| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({
                        "access_key_id": "AKIA_TEST",
                        "secret_access_key": "secret",
                        "session_token": "token",
                        "expiration": expiration,
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn mints_once_and_serves_the_second_call_from_cache() {
        let hits = Arc::new(AtomicUsize::new(0));
        let url = spawn_stub(hits.clone(), unix_now() + 900).await;
        let minter = ChannelStsMinter::new(url, "bearer".into(), reqwest::Client::new());
        let cap = dummy_cap();
        let a = minter.creds_for(&cap, "abc", "opchat-test1").await.unwrap();
        let b = minter.creds_for(&cap, "abc", "opchat-test1").await.unwrap();
        assert_eq!(a.access_key_id, "AKIA_TEST");
        assert_eq!(b.access_key_id, "AKIA_TEST");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "second call must hit the cache"
        );
        // A DIFFERENT channel is a different scope — must mint fresh.
        let _ = minter
            .creds_for(&cap, "abc", "other-channel")
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn near_expiry_creds_are_re_minted() {
        let hits = Arc::new(AtomicUsize::new(0));
        // Expires inside the 60 s margin ⇒ every call re-mints.
        let url = spawn_stub(hits.clone(), unix_now() + 30).await;
        let minter = ChannelStsMinter::new(url, "bearer".into(), reqwest::Client::new());
        let cap = dummy_cap();
        let _ = minter.creds_for(&cap, "abc", "opchat-test1").await.unwrap();
        let _ = minter.creds_for(&cap, "abc", "opchat-test1").await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn broker_error_is_a_loud_502_never_a_fallback() {
        let minter = ChannelStsMinter::new(
            "http://127.0.0.1:1".into(), // nothing listens here
            "bearer".into(),
            reqwest::Client::new(),
        );
        let err = minter
            .creds_for(&dummy_cap(), "abc", "opchat-test1")
            .await
            .expect_err("unreachable broker must surface an error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("sts_mint"),
            "error carries the sts_mint reason: {msg}"
        );
    }
}
