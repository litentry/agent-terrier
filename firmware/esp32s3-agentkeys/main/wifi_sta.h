// AgentKeys ESP32-S3 demo firmware — WiFi STA task
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md

#pragma once

// FreeRTOS task: connects to WiFi STA, reconnects on disconnect.
// Signals EVT_WIFI_CONNECTED on g_app_events when associated + got IP.
void wifi_sta_task(void *arg);
