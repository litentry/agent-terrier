#pragma once
// Sim shim for esp_crt_bundle.h (#517).
//
// On-device this attaches ESP-IDF's baked CA bundle to the TLS config. On the
// desktop the HTTP shim runs on libcurl, which already validates against the
// SYSTEM trust store — so the attach is a no-op and TLS verification is NOT
// weakened (the shim never sets CURLOPT_SSL_VERIFYPEER=0; a mock device that
// skipped cert checks against a real broker would be worse than no mock).
#include "esp_err.h"

struct esp_http_client_config_t; // fwd — the config carries this callback

static inline esp_err_t esp_crt_bundle_attach(void *conf) {
    (void)conf;
    return ESP_OK;
}
