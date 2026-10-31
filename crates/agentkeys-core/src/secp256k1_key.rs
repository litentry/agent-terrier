use anyhow::{Context, Result};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

pub fn parse(encoded: &str) -> Result<SigningKey> {
    let bytes = Zeroizing::new(
        hex::decode(encoded.trim().trim_start_matches("0x"))
            .context("signing key must contain hexadecimal bytes")?,
    );
    SigningKey::from_slice(&bytes).context("invalid secp256k1 signing key")
}

pub fn read(path: &str) -> Result<SigningKey> {
    parse(&crate::protected_file::read_text(path)?)
}

pub fn create(path: &str) -> Result<SigningKey> {
    let key = SigningKey::random(&mut rand_core::OsRng);
    let encoded = Zeroizing::new(format!("0x{}", hex::encode(key.to_bytes())));
    crate::protected_file::write(path, encoded.as_bytes(), true)?;
    Ok(key)
}

pub fn from_sources(inline: Option<String>, file: Option<String>) -> Result<Option<SigningKey>> {
    match (inline.map(Zeroizing::new), file) {
        (None, None) => Ok(None),
        (Some(value), None) => parse(&value).map(Some),
        (None, Some(path)) => read(&path).map(Some),
        (Some(_), Some(_)) => anyhow::bail!("choose one signing-key source"),
    }
}
