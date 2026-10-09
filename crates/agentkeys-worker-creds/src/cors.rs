use axum::http::{HeaderName, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

pub fn browser_cors_layer(spec: &str) -> CorsLayer {
    let origins = agentkeys_protocol::browser_origins::parse_browser_origins(spec)
        .into_iter()
        .filter_map(|origin| HeaderValue::from_str(&origin).ok())
        .collect::<Vec<_>>();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(
            agentkeys_protocol::browser_origins::WORKER_CORS_HEADERS
                .iter()
                .map(|header| HeaderName::from_static(header))
                .collect::<Vec<_>>(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::post, Router};
    use tower::ServiceExt;
    #[tokio::test]
    async fn preflight_allows_exact_origin_and_sts_headers_only() {
        let app = Router::new()
            .route("/data", post(|| async { "ok" }))
            .layer(browser_cors_layer("https://console.example.test"));
        for (origin, allowed) in [
            ("https://console.example.test", true),
            ("https://evil.example.test", false),
        ] {
            let response = app.clone().oneshot(Request::builder().method("OPTIONS").uri("/data")
                .header("origin", origin).header("access-control-request-method", "POST")
                .header("access-control-request-headers", "content-type,authorization,x-aws-access-key-id,x-aws-secret-access-key,x-aws-session-token")
                .body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(
                response
                    .headers()
                    .contains_key("access-control-allow-origin"),
                allowed
            );
            assert!(!response
                .headers()
                .contains_key("access-control-allow-credentials"));
            if allowed {
                let headers = response.headers()["access-control-allow-headers"]
                    .to_str()
                    .unwrap();
                for name in agentkeys_protocol::browser_origins::WORKER_CORS_HEADERS {
                    assert!(headers.contains(name));
                }
                assert!(!headers.contains('*'));
            }
        }
    }
}
