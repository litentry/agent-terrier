#pragma once
// Sim shim for esp_log.h. On-device this is ESP-IDF's logger; in the browser/desktop
// simulator we just print to stderr so the SAME firmware code (ui.c) compiles unchanged.
#include <stdio.h>
#define ESP_LOGI(tag, fmt, ...) fprintf(stderr, "I (%s) " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) fprintf(stderr, "W (%s) " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGE(tag, fmt, ...) fprintf(stderr, "E (%s) " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) ((void)0)
