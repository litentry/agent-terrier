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
