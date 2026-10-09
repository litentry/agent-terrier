use crate::{BrokerCapRequest, CapToken};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassifyCapRequest {
    #[serde(flatten)]
    pub request: BrokerCapRequest,
    pub data_class: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassifyTagBody<Cap = CapToken, Class = String> {
    pub cap: Cap,
    pub data_class: Class,
    pub entity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassifyTagResponse {
    pub ok: bool,
    pub classification: agentkeys_catalog::Classification,
}
