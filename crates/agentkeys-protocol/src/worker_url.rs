//! Worker URLs are DERIVED from the broker host, never a pre-composed env
//! (AGENTS.md "Worker URLs are DERIVED"). This is the ONE owner of that
//! derivation, wasm-safe so the browser device client (`agentkeys-web-core`)
//! and the daemon (`ui_bridge::derive_worker_url`, which delegates here) agree
//! byte-for-byte: `derive_worker_url("https://broker.agentterrier.cn", "channel")`
//! = `https://channel.agentterrier.cn`; the per-stack prefix maps
//! `broker.` → ``, `test-broker.` → `-test`, `broker-<x>.` → `-<x>`.

/// `https://<worker><stack-suffix>.<zone>` for the broker at `broker_url`, or
/// `None` when the host is not a recognised broker name (a bare IP, a
/// loopback dev broker, a host without a zone).
pub fn derive_worker_url(broker_url: &str, worker: &str) -> Option<String> {
    let host = broker_url
        .rsplit("://")
        .next()
        .unwrap_or(broker_url)
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let (first, zone) = host.split_once('.')?;
    if zone.is_empty() {
        return None;
    }
    let suffix = match first {
        "broker" => String::new(),
        "test-broker" => "-test".to_string(),
        other => match other.strip_prefix("broker-") {
            Some(rest) if !rest.is_empty() => format!("-{rest}"),
            _ => return None,
        },
    };
    Some(format!("https://{worker}{suffix}.{zone}"))
}

fn url_host(u: &str) -> String {
    u.rsplit("://")
        .next()
        .unwrap_or(u)
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Whether an explicit `AGENTKEYS_WORKER_<X>_URL` override may stand next to
/// `broker_url`: a loopback / `localhost` host always (a worker running on the
/// operator's machine), otherwise only a host on the SAME zone as the broker.
/// A foreign-zone override is almost always an inherited stack env — the
/// #571 leak class: on 2026-09-10 an AWS test-env `weixin-test.litentry.org`
/// rode into the VE console's daemon and pinned its Contacts page onto a host
/// that does not exist (and is not the 备案 domain WeChat needs). Callers log
/// the refusal and derive from the broker instead.
pub fn worker_override_matches_broker(override_url: &str, broker_url: &str) -> bool {
    let o = url_host(override_url);
    if o.is_empty() {
        return false;
    }
    if o == "localhost" || o == "::1" || o == "[::1]" || o.starts_with("127.") {
        return true;
    }
    let b = url_host(broker_url);
    match (o.split_once('.'), b.split_once('.')) {
        (Some((_, oz)), Some((_, bz))) => !oz.is_empty() && oz == bz,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_worker_url, worker_override_matches_broker};

    #[test]
    fn overrides_stand_only_on_loopback_or_the_broker_zone() {
        let ve = "https://broker.agentterrier.cn";
        assert!(worker_override_matches_broker(
            "https://weixin.agentterrier.cn",
            ve
        ));
        assert!(worker_override_matches_broker(
            "https://weixin-test.agentterrier.cn/",
            "https://test-broker.agentterrier.cn"
        ));
        assert!(worker_override_matches_broker("http://127.0.0.1:9101", ve));
        assert!(worker_override_matches_broker("http://localhost:9101/", ve));
        // the 2026-09-10 leak: an AWS test host next to the VE broker
        assert!(!worker_override_matches_broker(
            "https://weixin-test.litentry.org",
            ve
        ));
        assert!(!worker_override_matches_broker(
            "https://weixin.agentterrier.cn",
            "http://127.0.0.1:8091"
        ));
        assert!(!worker_override_matches_broker("", ve));
        assert!(!worker_override_matches_broker("https://weixin", ve));
    }

    #[test]
    fn prod_test_and_named_stacks_derive_their_worker_hosts() {
        assert_eq!(
            derive_worker_url("https://broker.agentterrier.cn", "channel").as_deref(),
            Some("https://channel.agentterrier.cn")
        );
        assert_eq!(
            derive_worker_url("https://test-broker.agentterrier.cn/", "channel").as_deref(),
            Some("https://channel-test.agentterrier.cn")
        );
        assert_eq!(
            derive_worker_url("https://broker-base.litentry.org:443/v1", "memory").as_deref(),
            Some("https://memory-base.litentry.org")
        );
    }

    #[test]
    fn unrecognised_hosts_derive_nothing() {
        assert_eq!(derive_worker_url("http://127.0.0.1:8091", "channel"), None);
        assert_eq!(derive_worker_url("http://localhost:3113", "channel"), None);
        assert_eq!(
            derive_worker_url("https://api.example.test", "channel"),
            None
        );
        assert_eq!(
            derive_worker_url("https://broker-.example.test", "channel"),
            None
        );
    }
}
