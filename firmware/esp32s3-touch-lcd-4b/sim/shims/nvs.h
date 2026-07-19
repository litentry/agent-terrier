#pragma once
// Sim shim for nvs.h / nvs_flash.h (#517) — the desktop's non-volatile store.
//
// This is what makes the mock device a DEVICE rather than a session: the K10
// private scalar, the paired flag and the master/child omnis persist here, so
// the mirror keeps its identity across restarts exactly as the ESP32 keeps
// them in flash. A pairing you did yesterday is still valid today.
//
// Backing store: ONE file per namespace under $AGENTKEYS_MOCK_DEVICE_DIR
// (default ~/.agentkeys/mock-device/), mode 0600 — it holds a private key.
// Format is a trivial line-oriented `key<TAB>type<TAB>hex-or-text` so an
// operator can inspect/delete it; it is NOT a compatible NVS partition image
// and is never meant to be flashed.
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef enum { NVS_READONLY = 0, NVS_READWRITE = 1 } nvs_open_mode_t;
typedef struct nvs_handle_impl *nvs_handle_t;

esp_err_t nvs_flash_init(void);
esp_err_t nvs_open(const char *ns, nvs_open_mode_t mode, nvs_handle_t *out);
void      nvs_close(nvs_handle_t h);
esp_err_t nvs_commit(nvs_handle_t h);

esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *val, size_t len);
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *len);
esp_err_t nvs_set_str(nvs_handle_t h, const char *key, const char *val);
esp_err_t nvs_get_str(nvs_handle_t h, const char *key, char *out, size_t *len);
esp_err_t nvs_set_u8(nvs_handle_t h, const char *key, uint8_t val);
esp_err_t nvs_get_u8(nvs_handle_t h, const char *key, uint8_t *out);

/// Absolute path of the backing file for `ns` (the mirror prints it at boot so
/// the operator knows where the device's identity lives, and can delete it to
/// factory-reset).
const char *nvs_sim_path(const char *ns);
