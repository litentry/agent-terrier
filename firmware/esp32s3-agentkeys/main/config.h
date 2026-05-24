// AgentKeys ESP32-S3 demo firmware — compile-time defaults
// Override per-device via NVS (preferred) or main/secrets.h (dev only).
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md

#pragma once

#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"

#ifndef PROJECT_VER
#define PROJECT_VER "0.1.0"
#endif

// --- Demo endpoint defaults (override via NVS or secrets.h) ---
#define DEFAULT_SANDBOX_URL  "https://demo.aiosandbox.litentry.org/v1/chat"
#define DEFAULT_ACTOR_TOKEN  "demo_token_O_demo_001_changeme"

// --- GPIO assignments (ESP32-S3-DevKitC-1) ---
#define BUTTON_GPIO   GPIO_NUM_0   // BOOT button on dev board
#define LED_GPIO      GPIO_NUM_48  // On-board RGB LED (WS2812 on DevKitC-1)

// --- Buffer sizes ---
#define MAX_QUERY_LEN    512
#define MAX_RESPONSE_LEN 4096

// --- HTTPS timeouts ---
#define HTTP_CONNECT_TIMEOUT_MS  10000
#define HTTP_REQUEST_TIMEOUT_MS  30000

// --- Try per-device secrets.h override (gitignored) ---
#if __has_include("secrets.h")
#include "secrets.h"
#endif

// --- Fallbacks if secrets.h didn't define ---
#ifndef WIFI_SSID
#define WIFI_SSID "your-wifi-ssid"
#endif
#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD "your-wifi-password"
#endif
#ifndef SANDBOX_URL
#define SANDBOX_URL DEFAULT_SANDBOX_URL
#endif
#ifndef ACTOR_TOKEN
#define ACTOR_TOKEN DEFAULT_ACTOR_TOKEN
#endif

// --- Shared FreeRTOS handles (defined in main.c) ---
extern EventGroupHandle_t g_app_events;
extern QueueHandle_t g_button_queue;

// --- Event bits on g_app_events ---
#define EVT_WIFI_CONNECTED  (1 << 0)
#define EVT_HTTP_IN_FLIGHT  (1 << 1)
#define EVT_HTTP_ERROR      (1 << 2)
#define EVT_HTTP_OK         (1 << 3)
