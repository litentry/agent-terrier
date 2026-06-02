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

#[cfg(feature = "wasm")]
pub mod wasm;
