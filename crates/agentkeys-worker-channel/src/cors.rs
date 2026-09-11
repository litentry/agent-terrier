//! Browser origins (#675) — a device-mode web app (`apps/device-display`, a
//! shared kitchen tablet acting as its OWN device actor) calls this service
//! cross-origin from a browser, so the service must answer the browser's CORS
//! preflight. Off by default; an explicit operator allowlist
//! (`AGENTKEYS_BROWSER_ORIGINS`, comma-separated `http(s)://host[:port]` origins), never a
//! wildcard and never credentials-by-cookie (the device authenticates with
//! its bearer / cap, both sent as headers or body).

use axum::http::{header, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// The origins an operator listed: trimmed, trailing slash dropped, only
/// absolute `http(s)://` origins kept, `*` refused (an allowlist, by design).
pub fn parse_browser_origins(spec: &str) -> Vec<String> {
    spec.split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| {
            !s.is_empty()
                && (s.starts_with("http://") || s.starts_with("https://"))
                && !s.contains('*')
                && !s[s.find("://").unwrap_or(0) + 3..].contains('/')
        })
        .map(str::to_string)
        .collect()
}

/// The layer for `spec`, or `None` when nothing is listed (= no CORS headers,
/// the pre-#675 behaviour). GET/POST/OPTIONS with `content-type` +
/// `authorization`, preflight cached 10 min.
pub fn browser_cors_layer(spec: &str) -> Option<CorsLayer> {
    let origins: Vec<HeaderValue> = parse_browser_origins(spec)
        .into_iter()
        .filter_map(|o| HeaderValue::from_str(&o).ok())
        .collect();
    if origins.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
            .max_age(std::time::Duration::from_secs(600)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;

    #[test]
    fn the_allowlist_is_parsed_strictly() {
        assert_eq!(
            parse_browser_origins(" https://display.example.test/, http://localhost:3119 ,,"),
            vec!["https://display.example.test", "http://localhost:3119"]
        );
        assert!(parse_browser_origins("*").is_empty());
        assert!(parse_browser_origins("https://*.example.test").is_empty());
        assert!(parse_browser_origins("display.example.test").is_empty());
        assert!(parse_browser_origins("https://a.test/path").is_empty());
        assert!(parse_browser_origins("").is_empty());
        assert!(browser_cors_layer("").is_none());
        assert!(browser_cors_layer(" , ").is_none());
    }

    fn app(spec: &str) -> Router {
        let r = Router::new().route("/ping", get(|| async { "pong" }));
        match browser_cors_layer(spec) {
            Some(l) => r.layer(l),
            None => r,
        }
    }

    #[tokio::test]
    async fn a_listed_origin_gets_preflight_and_response_headers() {
        let app = app("http://localhost:3119, https://display.example.test");
        let pre = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/ping")
                    .header("origin", "https://display.example.test")
                    .header("access-control-request-method", "POST")
                    .header(
                        "access-control-request-headers",
                        "content-type,authorization",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(pre.status().is_success(), "{}", pre.status());
        let h = pre.headers();
        assert_eq!(
            h["access-control-allow-origin"],
            "https://display.example.test"
        );
        let methods = h["access-control-allow-methods"]
            .to_str()
            .unwrap()
            .to_uppercase();
        assert!(
            methods.contains("POST") && methods.contains("GET"),
            "{methods}"
        );
        let headers = h["access-control-allow-headers"]
            .to_str()
            .unwrap()
            .to_lowercase();
        assert!(
            headers.contains("authorization") && headers.contains("content-type"),
            "{headers}"
        );
        assert_eq!(h["access-control-max-age"], "600");

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("origin", "http://localhost:3119")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()["access-control-allow-origin"],
            "http://localhost:3119"
        );
    }

    #[tokio::test]
    async fn an_unlisted_origin_and_the_default_get_no_cors_headers() {
        let resp = app("http://localhost:3119")
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("origin", "https://evil.example.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.headers().get("access-control-allow-origin").is_none());
        let resp = app("")
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("origin", "http://localhost:3119")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.headers().get("access-control-allow-origin").is_none());
        assert_eq!(resp.status(), 200);
    }
}
