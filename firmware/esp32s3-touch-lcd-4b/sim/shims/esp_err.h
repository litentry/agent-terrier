#pragma once
// Sim shim for esp_err.h (#517). On-device this is ESP-IDF's error type; the
// desktop mirror needs it because we now compile the REAL net/*.c rather than
// mock_net.c, and those return esp_err_t throughout.
//
// Values match ESP-IDF's so firmware code comparing against them behaves the
// same; only the ones net/ actually uses are defined (add on demand rather than
// vendoring the whole table — an unused constant that drifts is worse than a
// missing one that fails to compile).
#include <stdint.h>

typedef int esp_err_t;

#define ESP_OK   0
#define ESP_FAIL -1

#define ESP_ERR_NO_MEM           0x101
#define ESP_ERR_INVALID_ARG      0x102
#define ESP_ERR_INVALID_STATE    0x103
#define ESP_ERR_INVALID_SIZE     0x104
#define ESP_ERR_NOT_FOUND        0x105
#define ESP_ERR_NOT_SUPPORTED    0x106
#define ESP_ERR_TIMEOUT          0x107
#define ESP_ERR_NVS_NOT_FOUND    0x1102

static inline const char *esp_err_to_name(esp_err_t e) {
    switch (e) {
    case ESP_OK:                return "ESP_OK";
    case ESP_FAIL:              return "ESP_FAIL";
    case ESP_ERR_NO_MEM:        return "ESP_ERR_NO_MEM";
    case ESP_ERR_INVALID_ARG:   return "ESP_ERR_INVALID_ARG";
    case ESP_ERR_INVALID_STATE: return "ESP_ERR_INVALID_STATE";
    case ESP_ERR_INVALID_SIZE:  return "ESP_ERR_INVALID_SIZE";
    case ESP_ERR_NOT_FOUND:     return "ESP_ERR_NOT_FOUND";
    case ESP_ERR_TIMEOUT:       return "ESP_ERR_TIMEOUT";
    case ESP_ERR_NVS_NOT_FOUND: return "ESP_ERR_NVS_NOT_FOUND";
    default:                    return "ESP_ERR_UNKNOWN";
    }
}
