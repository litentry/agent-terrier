use crate::errors::{err_400, ApiError};
use aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder;

pub fn conditional_put(
    request: PutObjectFluentBuilder,
    expected_revision: Option<&str>,
) -> Result<PutObjectFluentBuilder, ApiError> {
    match expected_revision {
        None => Ok(request),
        Some("") => Ok(request.if_none_match("*")),
        Some(revision)
            if revision.trim().is_empty()
                || revision.contains('*')
                || revision.chars().any(char::is_control) =>
        {
            Err(err_400("invalid storage revision", "invalid_revision"))
        }
        Some(revision) => Ok(request.if_match(revision)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> PutObjectFluentBuilder {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("test"))
            .build();
        aws_sdk_s3::Client::from_conf(config).put_object()
    }
    #[test]
    fn create_and_replace_are_atomic_storage_preconditions() {
        let create = conditional_put(request(), Some("")).unwrap();
        assert_eq!(create.as_input().get_if_none_match().as_deref(), Some("*"));
        assert_eq!(create.as_input().get_if_match().as_deref(), None);
        let replace = conditional_put(request(), Some("\"revision\"")).unwrap();
        assert_eq!(
            replace.as_input().get_if_match().as_deref(),
            Some("\"revision\"")
        );
        assert_eq!(replace.as_input().get_if_none_match().as_deref(), None);
        assert!(conditional_put(request(), Some("*")).is_err());
    }
    #[tokio::test]
    async fn storage_wire_precondition_allows_only_one_writer_from_the_same_revision() {
        use axum::{
            extract::State,
            http::{HeaderMap, StatusCode},
            routing::put,
            Router,
        };
        use std::sync::{Arc, Mutex};
        let revision = Arc::new(Mutex::new(String::from("\"original\"")));
        async fn write(
            State(revision): State<Arc<Mutex<String>>>,
            headers: HeaderMap,
        ) -> (StatusCode, HeaderMap, &'static str) {
            let mut stored = revision.lock().unwrap();
            let expected = headers
                .get("if-match")
                .and_then(|value| value.to_str().ok());
            if expected != Some(stored.as_str()) {
                return (
                    StatusCode::PRECONDITION_FAILED,
                    HeaderMap::new(),
                    "<Error><Code>PreconditionFailed</Code><Message>stale</Message></Error>",
                );
            }
            *stored = "\"changed\"".into();
            let mut headers = HeaderMap::new();
            headers.insert("etag", stored.parse().unwrap());
            (StatusCode::OK, headers, "")
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/bucket/object", put(write))
            .with_state(revision);
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("test"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(format!("http://{address}"))
            .force_path_style(true)
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);
        let write_request = || {
            conditional_put(
                client.put_object().bucket("bucket").key("object"),
                Some("\"original\""),
            )
            .unwrap()
            .send()
        };
        let (first, second) = tokio::join!(write_request(), write_request());
        assert_ne!(first.is_ok(), second.is_ok());
        let failure = first.err().or_else(|| second.err()).unwrap();
        assert_eq!(failure.raw_response().unwrap().status().as_u16(), 412);
        server.abort();
    }
}
