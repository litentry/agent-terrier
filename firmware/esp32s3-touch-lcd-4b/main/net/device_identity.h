// K10 device identity (secp256k1) owned via the shared agentkeys-device-core FFI
// (issue #367). The key is generated ON the device from hardware entropy, stored
// in NVS, and never leaves — the broker only ever sees the address + a pop_sig,
// which it ecrecovers with the SAME Rust the device signed with.
//
// Call device_identity_init() once after nvs_flash_init() AND after WiFi is up:
// the ESP32-S3 RNG is only a CSPRNG while the RF subsystem (WiFi/BT) is active.
// Phase B (#367) feeds the §10.2 /v1/agent/pairing request/poll body from
// device_identity_pop_sig(), and shows device_identity_key_hash() on the pairing
// screen for the operator to compare against the master UI (#224).
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

// Buffer sizes for the FFI string outputs (incl. the NUL).
#define DEVICE_ID_ADDR_LEN 43  // "0x" + 40 hex + NUL
#define DEVICE_ID_HASH_LEN 67  // "0x" + 64 hex + NUL
#define DEVICE_ID_SIG_LEN  133 // "0x" + 130 hex (r||s||v) + NUL

// Load the K10 from NVS, or generate + persist one on first boot. Idempotent.
esp_err_t device_identity_init(void);

// The K10 EVM address ("0x"+40hex), or "" before a successful init. Stable pointer.
const char *device_identity_address(void);

// device_key_hash ("0x"+64hex) into out (cap >= DEVICE_ID_HASH_LEN).
esp_err_t device_identity_key_hash(char *out, size_t cap);

// Fresh EIP-191 agent pop_sig ("0x"+130hex) into out (cap >= DEVICE_ID_SIG_LEN).
esp_err_t device_identity_pop_sig(char *out, size_t cap);

// Fresh EIP-191 device->sandbox delegation co-signature (#369) into out
// (cap >= DEVICE_ID_SIG_LEN), authorizing sandbox_key (its OWN ephemeral key) to
// mint caps on this device's behalf, scoped to `scope` and expiring at
// `expires_at` (unix seconds). The K10 never leaves the device; the worker
// ecrecovers this sig and checks keccak(signer) == device_key_hash. Signed ONCE
// per sandbox spawn (the bootstrap), not per worker op.
esp_err_t device_identity_delegation_sig(const char *sandbox_key, const char *scope,
                                         uint64_t expires_at, char *out, size_t cap);

// Persist the §10.2 binding (paired=1 + the master/child omnis) to NVS on a
// successful claim. Survives reboot AND `idf.py flash` (the nvs partition is not
// erased); only `idf.py erase-flash` / a factory reset clears it. omnis may be NULL.
esp_err_t device_identity_save_binding(const char *master_omni, const char *child_omni);

// True if this device has a persisted pairing. When paired and master_out/cap are
// given, writes the master (operator) omni into master_out ("" if absent).
bool device_identity_paired(char *master_out, size_t cap);
