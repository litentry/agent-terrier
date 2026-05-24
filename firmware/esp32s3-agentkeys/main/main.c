// AgentKeys ESP32-S3 demo firmware — app_main entrypoint
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md
//
// Boot sequence:
//   1. Init NVS + default event loop
//   2. Spawn FreeRTOS tasks: led / wifi / button / chat
//   3. Tasks coordinate via g_app_events (event group) + g_button_queue (queue)

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"

#include "config.h"
#include "wifi_sta.h"
#include "https_chat.h"
#include "button.h"
#include "led_status.h"

static const char *TAG = "agentkeys";

// Shared FreeRTOS handles (declared extern in config.h)
EventGroupHandle_t g_app_events = NULL;
QueueHandle_t g_button_queue = NULL;

void app_main(void)
{
    ESP_LOGI(TAG, "booting (version %s)", PROJECT_VER);

    // --- Init NVS (config persistence) ---
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "nvs erasing + reinit");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // --- Init default event loop + IPC primitives ---
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    g_app_events = xEventGroupCreate();
    g_button_queue = xQueueCreate(4, sizeof(uint32_t));
    if (g_app_events == NULL || g_button_queue == NULL) {
        ESP_LOGE(TAG, "failed to create event group / queue");
        return;
    }

    // --- Spawn FreeRTOS tasks ---
    // Priority ordering: wifi (5) > button (4) > chat (3) > led (2)
    // WiFi needs highest priority for prompt reconnect; LED is just visual.
    xTaskCreate(led_status_task, "led",  2048, NULL, 2, NULL);
    xTaskCreate(wifi_sta_task,   "wifi", 4096, NULL, 5, NULL);
    xTaskCreate(button_task,     "btn",  2048, NULL, 4, NULL);
    xTaskCreate(https_chat_task, "chat", 8192, NULL, 3, NULL);

    ESP_LOGI(TAG, "ready (press BOOT button on GPIO %d to chat)", BUTTON_GPIO);
}
