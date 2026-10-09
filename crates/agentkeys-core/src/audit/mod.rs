pub use agentkeys_web_core::audit::*;
pub mod client;
pub use client::{AppendV2Response, AuditClient};

#[cfg(test)]
mod tests {
    #[test]
    fn commitment_matches_clear_signing() {
        let intent = "Approve 1 USDC";
        let digest = [0xde; 32];
        assert_eq!(
            super::commit_intent(intent, &digest),
            crate::clear_signing::commit_intent(intent, &digest)
        );
    }
}
