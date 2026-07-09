/* GENERATED from crates/agentkeys-device-core by cbindgen (issue #367) — DO NOT EDIT.
 * Regenerate with crates/agentkeys-device-core/gen-header.sh.
 * The secp256k1 / EIP-191 / keccak behind these calls is the SAME Rust the daemon
 * and broker use, compiled for the device — there is no second implementation. */


#ifndef AGENTKEYS_DEVICE_H
#define AGENTKEYS_DEVICE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Result codes returned across the C ABI.
typedef enum {
    AK_OK = 0,
    AK_NULL_PTR = -1,
    AK_BAD_KEY = -2,
    AK_BUFFER_TOO_SMALL = -3,
    AK_BAD_INPUT = -4,
    AK_SIGN_FAILED = -5,
} Ak;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Generate a K10 from 32 caller-supplied entropy bytes.
//
// `entropy`/`out_priv`: 32 bytes each (the validated scalar is copied to
// `out_priv` — the firmware stores it in encrypted NVS). `out_addr`: >= 43 bytes
// for the `0x`+40hex EVM address. Returns [`Ak::BadKey`] on the ~2^-128 chance
// the entropy is not a valid scalar (re-sample).
//
// # Safety
// `entropy` and `out_priv` must point to 32 readable/writable bytes; `out_addr`
// to `addr_cap` writable bytes.
Ak ak_device_keygen(const uint8_t *entropy, uint8_t *out_priv, char *out_addr, uintptr_t addr_cap);

// EVM address (`0x`+40hex) for the K10 already in `priv_` (32 bytes) — the load
// path (NVS → address) complementing [`ak_device_keygen`]. `out` >= 43 bytes.
//
// # Safety
// `priv_` must point to 32 readable bytes; `out` to `cap` writable bytes.
Ak ak_device_address(const uint8_t *priv_, char *out, uintptr_t cap);

// `device_key_hash` (`0x`+64hex) for an EVM address string. `out` >= 67 bytes.
//
// # Safety
// `addr` must be a valid C string; `out` must point to `cap` writable bytes.
Ak ak_device_key_hash(const char *addr, char *out, uintptr_t cap);

// EIP-191 agent proof-of-possession over the K10 in `priv_` (32 bytes):
// `eip191_sign(agent_pop_payload(device_key_hash(address)))`. `out` >= 133 bytes
// for the `0x`+130hex (`r||s||v`) signature the broker's §10.2 endpoints verify.
//
// # Safety
// `priv_` must point to 32 readable bytes; `out` to `cap` writable bytes.
Ak ak_device_pop_sig(const uint8_t *priv_, char *out, uintptr_t cap);

// EIP-191 device→sandbox delegation signature (issue #369) over the K10 in
// `priv_` (32 bytes): `eip191_sign(delegation_payload(device_key_hash(addr),
// sandbox_key, scope, expires_at))`. The device co-signs ONCE per sandbox spawn
// to authorize `sandbox_key` to mint caps on its behalf, bounded by `scope` +
// `expires_at`, WITHOUT ever exposing K10. `device_key_hash` is derived from
// THIS key internally, so the firmware cannot delegate under another device's
// hash. `out` >= 133 bytes for the `0x`+130hex (`r||s||v`) signature the worker
// re-verifies (cf. [`ak_device_pop_sig`]).
//
// # Safety
// `priv_` must point to 32 readable bytes; `sandbox_key`/`scope` must be valid
// C strings; `out` to `cap` writable bytes.
Ak ak_device_delegation_sig(const uint8_t *priv_,
                            const char *sandbox_key,
                            const char *scope,
                            uint64_t expires_at,
                            char *out,
                            uintptr_t cap);

// EIP-191 **cap-mint proof-of-possession** signature (issue #76) over the K10 in
// `priv_` (32 bytes): `eip191_sign(cap_pop_payload(operator, actor, service, op,
// data_class, client_nonce, client_ts))`. This is what lets a **device be a
// channel endpoint that mints its OWN caps** (#408): a camera signs a
// `channel-pub:<id>` PoP (op=`channel_publish`, data_class=`channel`), a display
// a `channel-sub:<id>` PoP — directly on-device, so the K10 never leaves NVS and
// the #369 delegation detour is not needed for a device acting for itself. The
// device signs **once per cap / per stream, not per frame** (secp256k1 is
// software on the ESP32-S3 — §6 camera row). `out` >= 133 bytes for the
// `0x`+130hex (`r||s||v`) signature the broker + worker re-verify (cf.
// [`ak_device_pop_sig`], which signs the *pairing* PoP).
//
// # Safety
// `priv_` must point to 32 readable bytes; the string args must be valid C
// strings; `out` to `cap` writable bytes.
Ak ak_device_cap_pop_sig(const uint8_t *priv_,
                         const char *operator_omni,
                         const char *actor_omni,
                         const char *service,
                         const char *op,
                         const char *data_class,
                         const char *client_nonce,
                         uint64_t client_ts,
                         char *out,
                         uintptr_t cap);

void rust_eh_personality(void);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* AGENTKEYS_DEVICE_H */
