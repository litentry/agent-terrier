pub fn extract_bearer_token(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ")
}
