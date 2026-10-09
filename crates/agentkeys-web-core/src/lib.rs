//! agentkeys-web-core — the host-agnostic master-plane core.
//!
//! Compiles for **native** (daemon / CLI / mobile-via-UniFFI) AND **`wasm32`**
//! (the browser web host, via `wasm-pack build --features wasm`). It holds no
//! filesystem / clock / env state, so the same orchestration logic runs
//! unchanged in every host — the "consistency is structural" rule from
//! `docs/plan/web-flow/wire-real-paths.md` §0.5. The auth bearer + base URL are
//! always passed in by the host; this crate stores no secret.
//!
//! Today it holds the broker client (W0/X0). The WebAuthn-UserOp builder and the
//! ceremony state machines land here too as later slices, so the WASM
//! `CoreBackend`, the daemon ui-bridge, and the mobile shell share one impl.

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
