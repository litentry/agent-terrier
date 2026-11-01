//! Host-agnostic master control-plane clients and ceremony builders.
//!
//! Native and browser WASM hosts share these types and operations. Hosts supply
//! endpoints, authentication and persistence; this crate owns no credential store.

pub mod broker;
pub mod device;

#[cfg(feature = "wasm")]
pub mod wasm;

pub mod session;

pub mod crypto;
pub mod data;

pub mod chain;

pub mod hosted_signer;
#[cfg(feature = "wasm")]
pub mod wasm_hosted_signer;

pub mod console_documents;
pub mod document_helpers;
pub mod persona;

pub mod console;

#[cfg(feature = "wasm")]
pub mod wasm_console;

pub mod audit;
pub mod console_audit;

pub mod console_apps;

pub mod console_runtime;

pub mod console_inbox;

pub mod console_registry;
