// AgentKeys ESP32-S3 demo firmware — HTTPS chat task
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md

#pragma once

// FreeRTOS task: waits for button events on g_button_queue,
// prompts user over USB CDC, POSTs to SANDBOX_URL with Bearer ACTOR_TOKEN,
// parses JSON response, prints agent reply over USB CDC.
void https_chat_task(void *arg);
