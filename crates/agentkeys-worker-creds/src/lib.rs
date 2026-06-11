//! Credentials-service worker — arch.md §15.1 + §28.
//!
//! Workflow per cap-verify-then-encrypt:
//!   1. Receive `{cap_token, plaintext}` (store) or `{cap_token}` (fetch).
//!   2. Verify `broker_sig` over `Sha256(json(payload))` using the
//!      broker's P-256 public key (env-injected for stage 1; mTLS-
//!      attested key exchange in stage 2 via the signer enclave).
//!   3. Independently re-verify the on-chain scope via eth_call to
//!      AgentKeysScope.isServiceInScope (catches the broker-compromise
//!      threat per arch.md §15.1).
//!   4. Derive the per-actor AES-256-GCM KEK via mTLS call to the signer
//!      (stage 1 stub: env-injected `AGENTKEYS_WORKER_KEK_HEX`).
//!   5. AES-256-GCM encrypt/decrypt with `aad = sha256(operator_omni ||
//!      actor_omni || service || k3_epoch)`.
//!   6. S3 PUT/GET at `s3://$VAULT_BUCKET/bots/<actor_omni>/credentials/
//!      <service>.enc` via the worker's IAM identity.
//!
//! Stage-1 simplification: KEK is injected via env. Stage 2 (#90)
//! replaces with mTLS-derived KEK from the signer enclave.

pub mod audit;
pub mod aws_creds;
pub mod envelope;
pub mod errors;
pub mod handlers;
pub mod state;
pub mod verify;

pub use state::{WorkerConfig, WorkerState};
