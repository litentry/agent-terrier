//! Identity primitives for the pluggable broker.
//!
//! Per Stage 7 plan §3.5 and the port-vs-greenfield analysis: AgentKeys
//! is OmniAccount-first. Every authenticated identity (EVM wallet, email,
//! OAuth2 sub) hashes deterministically into an `OmniAccount` that becomes
//! the storage primary key for wallet bindings, grants, and audit rows.

pub mod omni_account;

pub use omni_account::{derive_omni_account, OmniAccount, AGENTKEYS_CLIENT_ID};
