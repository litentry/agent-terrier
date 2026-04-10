pub struct MockHttpClient {
    pub base_url: String,
}

impl MockHttpClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base_url: base_url.into() }
    }
}
