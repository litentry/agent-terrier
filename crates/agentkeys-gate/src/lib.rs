//! `agentkeys-gate` — the thin **metered key-custody LLM-egress relay** (#384).
//!
//! The sandbox agent (Hermes) consumes its LLM as a generic OpenAI-compatible
//! provider; pointing that provider's `base_url` at this relay moves the vendor
//! inference key (Ark — Bearer-only, not IAM/STS-mintable) OUT of the sandbox:
//! the relay holds the one shared key, forwards each turn upstream, and meters
//! the response's `usage` field per #332.
//!
//! **Custody + metering ONLY.** This is NOT a control point: per arch.md §22d
//! the IAM guarantee for the agent path is hooks + data-plane caps. The relay
//! does no retry, no fallback, no caching, no orchestration, and never inspects
//! or rewrites the conversation (its only body mutations are the optional model
//! override and `stream_options.include_usage` on streamed turns).
//!
//! Attribution model (#384): every turn's tokens accumulate to **one user**
//! (the owning omni — budgets are per-user), with per-device and per-api-key
//! statistics that roll up into the user-facing summary (`GET /v1/usage`).
//! Each turn lands on the ledger as a `GateTurn` (op_kind 90) audit row.

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod meter;
pub mod openai;
pub mod relay;
pub mod server;
pub mod upstream;
