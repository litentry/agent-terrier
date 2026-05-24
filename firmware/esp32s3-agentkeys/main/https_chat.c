// AgentKeys ESP32-S3 demo firmware — HTTPS chat task
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md
//
// v0 STUB: button press → read line from USB CDC → echo back ("[mock] you said: ...")
//
// TODO: implement actual POST to SANDBOX_URL using esp_http_client:
//   1. Wait for EVT_WIFI_CONNECTED
//   2. Wait for button event on g_button_queue
//   3. Read user input from stdin (USB CDC) up to MAX_QUERY_LEN
//   4. Build JSON body: {"query": "<user_input>"}
//   5. POST with header: Authorization: Bearer <ACTOR_TOKEN>
//   6. Parse response JSON, extract "response" field
//   7. Print to stdout
//
// Reference: esp-idf/examples/protocols/esp_http_client/main/esp_http_client_example.c

#include "https_chat.h"
#include "config.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"

static const char *TAG = "chat";

static void read_line_from_stdin(char *buf, size_t buflen)
{
    // Blocking read from USB CDC until newline or buffer full
    size_t pos = 0;
    while (pos < buflen - 1) {
        int c = getchar();
        if (c == EOF) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        if (c == '\n' || c == '\r') break;
        buf[pos++] = (char)c;
    }
    buf[pos] = '\0';
}

void https_chat_task(void *arg)
{
    char query_buf[MAX_QUERY_LEN];
    uint32_t btn_ts;

    ESP_LOGI(TAG, "waiting for WiFi");
    xEventGroupWaitBits(g_app_events, EVT_WIFI_CONNECTED, pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "wifi ready, target=%s", SANDBOX_URL);

    while (1) {
        // Wait for a button press
        if (xQueueReceive(g_button_queue, &btn_ts, portMAX_DELAY)) {
            printf("> ");
            fflush(stdout);

            read_line_from_stdin(query_buf, sizeof(query_buf));
            if (strlen(query_buf) == 0) {
                printf("[empty, skipping]\n");
                continue;
            }

            xEventGroupSetBits(g_app_events, EVT_HTTP_IN_FLIGHT);

            // TODO: replace stub with real esp_http_client POST.
            // For now: echo back so the foundation can be flashed and tested end-to-end.
            printf("agent: [mock] you said: %s\n", query_buf);
            ESP_LOGI(TAG, "stub responded to %zu-byte query", strlen(query_buf));

            xEventGroupClearBits(g_app_events, EVT_HTTP_IN_FLIGHT);
            xEventGroupSetBits(g_app_events, EVT_HTTP_OK);
        }
    }
}
