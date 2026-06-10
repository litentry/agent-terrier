//! #230 — the thin in-house ERC-4337 v0.7 bundler.
//!
//! Decouples UserOp **submission** from the broker: the broker relays a signed
//! UserOp here via the standard `eth_sendUserOperation` JSON-RPC, and this
//! service owns the submitter EOA, nonce, gas, and the `EntryPoint.handleOps`
//! broadcast. Swappable: the broker only speaks the canonical bundler RPC
//! (`eth_sendUserOperation` / `eth_getUserOperationReceipt` /
//! `eth_supportedEntryPoints`), so a self-hosted eth-infinitism bundler or a
//! 3rd-party (Pimlico / Alchemy) drops in with zero broker code change.
//!
//! Why in-house instead of a stock bundler (see `scripts/erc4337-bundler.sh` +
//! `docs/spec/heima-eth-gap.md`): Heima's Frontier RPC has no `debug` namespace
//! (stock bundlers need `debug_traceCall` for ERC-7562 validation),
//! `eth_estimateGas` REVERTS on `handleOps` (so the gas limit is pinned, not
//! estimated), and receipts carry no `mixHash` (alloy/ethers parsers crash —
//! all reads here are raw JSON). This bundler is PRIVATE: bound to loopback,
//! fed only by the broker — not a public alt-mempool.

pub mod legacy_tx;
pub mod server;
