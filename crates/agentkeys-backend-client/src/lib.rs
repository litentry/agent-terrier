//! Native capability and worker client; wire types are owned by agentkeys-protocol.

pub mod client;
pub mod fixtures;
pub use agentkeys_protocol as protocol;

pub use client::{BackendClient, BackendError, Delegation, RemoteCapPop};
pub use protocol::{
    normalize_omni_0x, service_knowledge, AuditAppendInput, AuditAppendResult, AuditAppendV2,
    AuditAppendV2Resp, BrokerCapRequest, CapMintOp, CapMintRequest, CapToken, ConfigGetBody,
    ConfigGetResp, ConfigPutBody, CredFetchBody, CredFetchInput, CredFetchResp, CredFetchResult,
    CredStoreBody, CredStoreInput, CredStoreResp, CredStoreResult, MemoryGetBody, MemoryGetInput,
    MemoryGetResp, MemoryGetResult, MemoryPutBody, MemoryPutInput, MemoryPutResp, MemoryPutResult,
    RevokeResult, ENVELOPE_VERSION,
};
