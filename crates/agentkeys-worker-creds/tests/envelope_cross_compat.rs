//! Cross-crate envelope compatibility test.
//!
//! Codex review finding #5: worker and CLI MUST produce byte-identical
//! AAD for the same (actor_omni, service, k3_epoch) inputs. This test
//! pins the AAD shape so a future refactor in either crate breaks
//! loudly instead of silently.

use agentkeys_worker_creds::envelope;

#[test]
fn worker_aad_matches_cli_format() {
    // Format must be: "agentkeys.cred.aad.v2|" || lowercase(actor_omni_no_0x) || "|" || service
    // (CLI's aad_for_v2 inlines the service.0.as_bytes() unchanged; we
    // match that exactly so a CLI-written blob decrypts in the worker.)
    let actor = "0xABCDEF12".to_string() + &"0".repeat(56);
    let computed = envelope::aad("ignored", &actor, "openrouter", 999);
    let expected_actor = "abcdef12".to_string() + &"0".repeat(56);
    let expected = format!("agentkeys.cred.aad.v2|{}|openrouter", expected_actor);
    assert_eq!(
        computed,
        expected.as_bytes(),
        "worker AAD bytes diverged from CLI's aad_for_v2 — round-trip will break"
    );
}

#[test]
fn aad_lowercase_actor_only() {
    // Tamper detection: if a future change lowercases the SERVICE name
    // before AAD construction, blobs written with uppercase service
    // names won't round-trip. Pin the behavior here.
    let actor = format!("0x{}", "a".repeat(64));
    let with_upper = envelope::aad("x", &actor, "OpenRouter", 0);
    let with_lower = envelope::aad("x", &actor, "openrouter", 0);
    assert_ne!(
        with_upper, with_lower,
        "AAD must preserve service casing — CLI's s3_backend.rs inlines service as-is"
    );
}

#[test]
fn envelope_known_kek_roundtrip() {
    // Deterministic-input round-trip: same key + same AAD + known plaintext
    // → encrypt to envelope, decrypt back to same plaintext. The nonce is
    // randomized internally (per AES-GCM), but the worker's decrypt path
    // pulls the nonce out of the envelope's leading bytes, so round-trip
    // always succeeds.
    let kek_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let actor = format!("0x{}", "1".repeat(64));
    let aad = envelope::aad("ignored", &actor, "openrouter", 1);
    let plaintext = b"sk-or-v1-DEMO";
    let env = envelope::encrypt(kek_hex, plaintext, &aad).unwrap();
    let recovered = envelope::decrypt(kek_hex, &env, &aad).unwrap();
    assert_eq!(recovered, plaintext);
}
