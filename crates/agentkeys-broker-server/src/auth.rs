pub fn extract_bearer_token(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ")
}

pub(crate) fn constant_time_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bearer_compare_is_exact() {
        assert!(constant_time_str_eq("synthetic", "synthetic"));
        assert!(!constant_time_str_eq("synthetic", "synthetix"));
        assert!(!constant_time_str_eq("synthetic", "syntheti"));
        assert!(!constant_time_str_eq("", "x"));
    }
}
