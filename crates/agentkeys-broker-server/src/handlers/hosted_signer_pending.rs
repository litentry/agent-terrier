use agentkeys_protocol::hosted_signer::{
    HostedSignerApproval, HostedSignerRequest, HOSTED_SIGNER_TTL_SECONDS,
};
use std::{collections::HashMap, sync::RwLock};

const MAX_PENDING_PER_OPERATOR: usize = 4;
const MAX_PENDING_REQUESTS: usize = 1024;
pub(crate) const MAX_PUBLIC_REQUEST_BYTES: usize = 16 * 1024;
pub(crate) fn check_size(approval: &HostedSignerApproval) -> Result<(), String> {
    if serde_json::to_vec(approval)
        .map_err(|error| error.to_string())?
        .len()
        > MAX_PUBLIC_REQUEST_BYTES
    {
        return Err("browser request is too large".into());
    }
    Ok(())
}
struct PendingRequest {
    operator: [u8; 32],
    request: HostedSignerRequest,
    expires_at: u64,
    dismissed: bool,
}
#[derive(Default)]
pub struct HostedSignerRequestStore {
    rows: RwLock<HashMap<String, PendingRequest>>,
}
impl HostedSignerRequestStore {
    pub fn publish(
        &self,
        operator: [u8; 32],
        approval: HostedSignerApproval,
        now: u64,
    ) -> Result<HostedSignerRequest, String> {
        check_size(&approval)?;
        let expires_at = approval.enrollment.intent.expires_at;
        if expires_at <= now || expires_at.saturating_sub(now) > HOSTED_SIGNER_TTL_SECONDS {
            return Err("browser request expired or exceeds the permitted lifetime".into());
        }
        let id = approval.enrollment.challenge.clone();
        let mut rows = self
            .rows
            .write()
            .map_err(|_| "browser request lock poisoned")?;
        rows.retain(|_, row| row.expires_at > now);
        if let Some(row) = rows.get(&id) {
            if row.operator != operator || row.dismissed {
                return Err("browser request already closed".into());
            }
            if serde_json::to_vec(&row.request.approval).map_err(|error| error.to_string())?
                != serde_json::to_vec(&approval).map_err(|error| error.to_string())?
            {
                return Err("browser request changed".into());
            }
            return Ok(row.request.clone());
        }
        if rows.len() >= MAX_PENDING_REQUESTS
            || rows.values().filter(|row| row.operator == operator).count()
                >= MAX_PENDING_PER_OPERATOR
        {
            return Err("too many browser requests; wait for an existing request to expire".into());
        }
        for row in rows.values_mut().filter(|row| row.operator == operator) {
            if row.request.approval.enrollment.intent.credential_id
                == approval.enrollment.intent.credential_id
                && row.request.approval.enrollment.intent.device_key_hash
                    == approval.enrollment.intent.device_key_hash
            {
                row.dismissed = true;
            }
        }
        let request = HostedSignerRequest {
            id: id.clone(),
            approval,
        };
        rows.insert(
            id,
            PendingRequest {
                operator,
                request: request.clone(),
                expires_at,
                dismissed: false,
            },
        );
        Ok(request)
    }
    pub fn pending(
        &self,
        operator: [u8; 32],
        now: u64,
    ) -> Result<Vec<HostedSignerRequest>, String> {
        let mut rows = self
            .rows
            .write()
            .map_err(|_| "browser request lock poisoned")?;
        rows.retain(|_, row| row.expires_at > now);
        let mut requests: Vec<_> = rows
            .values()
            .filter(|row| row.operator == operator && !row.dismissed)
            .map(|row| row.request.clone())
            .collect();
        requests.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(requests)
    }
    pub fn dismiss(&self, operator: [u8; 32], id: &str, now: u64) -> Result<(), String> {
        let mut rows = self
            .rows
            .write()
            .map_err(|_| "browser request lock poisoned")?;
        rows.retain(|_, row| row.expires_at > now);
        let row = rows
            .get_mut(id)
            .filter(|row| row.operator == operator)
            .ok_or("browser request expired or not found")?;
        row.dismissed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_protocol::hosted_signer::*;
    fn request(id: usize, expires_at: u64) -> HostedSignerApproval {
        HostedSignerApproval {
            enrollment: HostedSignerChallenge {
                intent: HostedSignerIntent {
                    operator_omni: "operator".into(),
                    account: "account".into(),
                    chain_id: 1,
                    credential_id: "credential".into(),
                    public_key_x: "x".into(),
                    public_key_y: "y".into(),
                    origin: "https://console.test".into(),
                    rp_id: "console.test".into(),
                    device_key_hash: "device".into(),
                    operator_nonce: "nonce".into(),
                    expires_at,
                },
                challenge: format!("request-{id}"),
                recovery_challenge: "recovery".into(),
                attesting_device_key_hash: "attester".into(),
            },
            proof: BrowserAssertion {
                authenticator_data: "public".into(),
                client_data_json: "public".into(),
                signature: "public".into(),
                credential_id: "credential".into(),
            },
            device_proof: "public".into(),
        }
    }
    #[test]
    fn isolates_operators_expires_and_prevents_republication_after_dismiss() {
        let store = HostedSignerRequestStore::default();
        let approval = request(1, 150);
        let row = store.publish([1; 32], approval.clone(), 100).unwrap();
        assert!(store.pending([2; 32], 100).unwrap().is_empty());
        assert!(store.dismiss([2; 32], &row.id, 100).is_err());
        assert_eq!(store.pending([1; 32], 100).unwrap().len(), 1);
        store.dismiss([1; 32], &row.id, 100).unwrap();
        assert!(store.pending([1; 32], 100).unwrap().is_empty());
        assert!(store.publish([1; 32], approval.clone(), 100).is_err());
        assert!(store.publish([1; 32], approval, 151).is_err());
        assert!(store.pending([1; 32], 151).unwrap().is_empty());
    }
    #[test]
    fn bounds_requests_and_rejects_mutation_of_same_id() {
        let store = HostedSignerRequestStore::default();
        let mut oversized = request(999, 150);
        oversized.device_proof = "x".repeat(MAX_PUBLIC_REQUEST_BYTES);
        assert!(store.publish([1; 32], oversized, 100).is_err());
        let approval = request(0, 150);
        store.publish([1; 32], approval.clone(), 100).unwrap();
        assert!(store.publish([1; 32], approval.clone(), 100).is_ok());
        let mut changed = approval;
        changed.device_proof = "changed".into();
        assert!(store.publish([1; 32], changed, 100).is_err());
        for index in 1..MAX_PENDING_PER_OPERATOR {
            store.publish([1; 32], request(index, 150), 100).unwrap();
        }
        assert!(store
            .publish([1; 32], request(MAX_PENDING_PER_OPERATOR, 150), 100)
            .is_err());
        assert!(store
            .publish(
                [2; 32],
                request(999, 100 + HOSTED_SIGNER_TTL_SECONDS + 1),
                100
            )
            .is_err());
        assert!(store.publish([1; 32], request(1000, 250), 151).is_ok());
    }
}
