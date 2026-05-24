// AgentKeys ESP32-S3 demo firmware — button task
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md

#pragma once

// FreeRTOS task: installs GPIO interrupt on BUTTON_GPIO (boot button),
// debounces, emits press events on g_button_queue (one uint32_t per press).
void button_task(void *arg);
