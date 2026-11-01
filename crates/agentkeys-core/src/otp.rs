use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn derive_otp(nonce: &[u8], canonical_request: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(nonce).expect("HMAC accepts any key length");
    mac.update(canonical_request);
    let result = mac.finalize().into_bytes();
    let truncated = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
    let six_digits = truncated % 1_000_000;
    format!("{:06}", six_digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism() {
        let nonce = b"test-nonce-12345";
        let canonical = b"canonical-request-bytes";
        let otp1 = derive_otp(nonce, canonical);
        let otp2 = derive_otp(nonce, canonical);
        assert_eq!(otp1, otp2);
        assert_eq!(otp1.len(), 6);
        assert!(otp1.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn different_requests_different_otps() {
        let nonce = b"same-nonce";
        let canonical_a = b"request-type-pair";
        let canonical_b = b"request-type-recover";
        let otp_a = derive_otp(nonce, canonical_a);
        let otp_b = derive_otp(nonce, canonical_b);
        assert_ne!(otp_a, otp_b);
    }
}
