use agentkeys_backend_client::protocol::{BuildAcceptUserOpResponse, WireUserOp};
use agentkeys_core::chain_profile::{is_loopback_http_endpoint, ChainProfile};
use anyhow::{anyhow, bail, Result};

#[derive(Debug)]
pub struct DevelopmentSigning {
    chain_id: u64,
    entry_point: Option<[u8; 20]>,
}

impl DevelopmentSigning {
    pub fn new(profile: &ChainProfile, enabled: bool, rpc_override: Option<&str>) -> Result<Self> {
        profile.require_local_development(enabled, rpc_override)?;
        let entry_point = profile
            .contract("EntryPoint")
            .map(|contract| parse_address(&contract.address))
            .transpose()?;
        Ok(Self {
            chain_id: profile.chain_id,
            entry_point,
        })
    }

    pub fn require_local_service(&self, endpoint: &str) -> Result<()> {
        if !is_loopback_http_endpoint(endpoint) {
            bail!("development signing requires a loopback HTTP service endpoint");
        }
        Ok(())
    }

    pub fn verify_build(
        &self,
        user_op: &WireUserOp,
        user_op_hash: &str,
        entry_point: &str,
        chain_id: u64,
    ) -> Result<()> {
        let expected_entry_point = self.entry_point.ok_or_else(|| {
            anyhow!("development signing requires a deployed EntryPoint in the local profile")
        })?;
        if chain_id != self.chain_id || parse_address(entry_point)? != expected_entry_point {
            bail!("development operation targets a different chain or EntryPoint");
        }
        let packed =
            agentkeys_core::erc4337::wire_to_packed(user_op).map_err(anyhow::Error::msg)?;
        let expected_hash = packed.user_op_hash(&expected_entry_point, self.chain_id);
        let claimed_hash = hex::decode(user_op_hash.trim_start_matches("0x"))?;
        if claimed_hash.as_slice() != expected_hash {
            bail!("development operation hash does not match its local chain and payload");
        }
        Ok(())
    }

    pub fn verify_build_value(&self, value: &serde_json::Value) -> Result<()> {
        let build: BuildAcceptUserOpResponse = serde_json::from_value(value.clone())?;
        self.verify_build(
            &build.user_op,
            &build.user_op_hash,
            &build.entry_point,
            build.chain_id,
        )
    }
}

fn parse_address(value: &str) -> Result<[u8; 20]> {
    hex::decode(value.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| anyhow!("EntryPoint must be a 20-byte address"))
}
