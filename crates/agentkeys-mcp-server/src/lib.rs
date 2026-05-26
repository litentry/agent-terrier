//! AgentKeys MCP server — Phase 1 (issue #107).
//!
//! Thin adapter layer over the broker + worker RPCs. Exposes the
//! 7 active tools + 3 schema-only stubs that turn the Phase 0 backend
//! into something an MCP-speaking LLM host (xiaozhi-server, Volcano Ark)
//! can call.
//!
//! Library exports exist so integration tests (`tests/three_acts.rs`)
//! can build a `Server` with a mocked `Backend` and exercise the JSON-RPC
//! plumbing without standing up real HTTP listeners or external services.

pub mod auth;
pub mod backend;
pub mod config;
pub mod errors;
pub mod mcp;
pub mod policy;
pub mod server;
pub mod tools;
pub mod transport;

pub use config::Config;
pub use server::Server;
