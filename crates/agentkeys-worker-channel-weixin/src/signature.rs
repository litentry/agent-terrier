//! WeChat 公众号 callback signature verification.
//!
//! The platform signs each callback with `sha1(sort([token, timestamp, nonce]))`
//! hex-lowercase. We recompute and constant-time-compare. This is the transport
//! authenticity check (the message really came from WeChat); the CONTACT
//! authenticity (which human) is the openid → registry resolution downstream.

use sha1::{Digest, Sha1};

/// Verify a WeChat callback signature. `token` is the 公众号 verification token
/// (custodied); `signature`/`timestamp`/`nonce` are the query params WeChat sends.
pub fn verify(token: &str, signature: &str, timestamp: &str, nonce: &str) -> bool {
    let expected = compute(token, timestamp, nonce);
    constant_time_eq(
        expected.as_bytes(),
        signature.trim().to_lowercase().as_bytes(),
    )
}

/// The signature WeChat computes — exposed so the mock e2e can craft a valid
/// callback without a real WeChat (it knows the test token).
pub fn compute(token: &str, timestamp: &str, nonce: &str) -> String {
    let mut parts = [token, timestamp, nonce];
    parts.sort_unstable();
    let joined = parts.concat();
    let digest = Sha1::digest(joined.as_bytes());
    hex::encode(digest)
}

/// Length-independent constant-time comparison (avoid a timing oracle on the
/// signature — cheap defense, the gate is on the public internet).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_roundtrips_and_is_order_independent() {
        let token = "agentkeys-test-token";
        let ts = "1700000000";
        let nonce = "abc123";
        let sig = compute(token, ts, nonce);
        assert!(
            verify(token, &sig, ts, nonce),
            "self-computed sig must verify"
        );
        // Case-insensitive on the incoming signature.
        assert!(verify(token, &sig.to_uppercase(), ts, nonce));
        // Wrong token / tampered params fail.
        assert!(!verify("wrong-token", &sig, ts, nonce));
        assert!(!verify(token, &sig, "1700000001", nonce));
        assert!(!verify(token, "deadbeef", ts, nonce));
    }
}
