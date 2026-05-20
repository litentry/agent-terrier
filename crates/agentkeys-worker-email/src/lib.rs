//! Email-service worker — outbound SES + per-actor inbound stub.
//!
//! Outbound (`POST /v1/email/send`): send an email via SES from a verified
//! sender on the operator's domain (configured per arch.md §15.1).
//!
//! Inbound (`GET /v1/email/inbox/:actor_omni`): list mail received by the
//! actor's per-actor inbox at `s3://$BUCKET/bots/<actor_omni_hex>/inbound/`.
//! The actual inbound routing is done by the SES routing Lambda from #83;
//! this worker only lists what's already been delivered.

pub mod handlers;
pub mod state;
