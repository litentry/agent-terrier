// AgentKeys ESP32-S3 demo firmware — LED status task
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md

#pragma once

// FreeRTOS task: drives on-board status LED based on g_app_events bits.
// Idle = dim blue, processing = pulsing blue, error = flashing red.
// v0 stub: just blinks GPIO LED_GPIO once per second.
void led_status_task(void *arg);
