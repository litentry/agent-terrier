use serde_json::Value;
use url::Url;

pub fn local_recipe() -> &'static Value {
    static RECIPE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    RECIPE.get_or_init(|| {
        serde_json::from_str(include_str!("../../../presets/local-models.json"))
            .expect("checked-in model recipe")
    })
}

pub fn default_base_url() -> &'static str {
    local_recipe()["base_url"].as_str().expect("model endpoint")
}

pub fn default_chat_model() -> &'static str {
    local_recipe()["chat"]["model"]
        .as_str()
        .expect("chat model")
}

pub fn default_embedding_model() -> &'static str {
    local_recipe()["embedding"]["model"]
        .as_str()
        .expect("embedding model")
}

pub fn default_embedding_dimension() -> u32 {
    local_recipe()["embedding"]["dimension"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .expect("embedding dimension")
}

pub fn base_url(value: &str) -> Result<Url, &'static str> {
    let url = Url::parse(value).map_err(|_| "invalid model endpoint URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "model endpoint must be HTTP(S), without embedded credentials, query or fragment",
        );
    }
    Ok(url)
}

pub fn require_local_endpoint(value: &str) -> Result<(), &'static str> {
    let url = base_url(value)?;
    let host = url.host_str().unwrap_or_default();
    let local = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "http" || !local {
        return Err("local model qualification requires a loopback HTTP endpoint");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_recipe_is_complete_and_endpoint_rules_fail_closed() {
        assert!(require_local_endpoint(default_base_url()).is_ok());
        assert!(!default_chat_model().is_empty());
        assert!(!default_embedding_model().is_empty());
        assert!(default_embedding_dimension() > 0);
        for endpoint in ["http://localhost:11434/v1", "http://[::1]:1234/v1"] {
            assert!(require_local_endpoint(endpoint).is_ok());
        }
        for endpoint in [
            "https://models.example/v1",
            "http://127.0.0.1.example/v1",
            "https://localhost/v1",
        ] {
            assert!(base_url(endpoint).is_ok());
            assert!(require_local_endpoint(endpoint).is_err());
        }
        for endpoint in [
            "file:///tmp/model",
            "http://user:secret@localhost/v1",
            "http://localhost/v1?key=secret",
            "http://localhost/v1#secret",
        ] {
            let error = base_url(endpoint).unwrap_err();
            assert!(!error.contains("secret"));
        }
    }
}
