// AgentKeys on-device firmware — Waveshare ESP32-S3-Touch-LCD-4B (issue #348).
// Boot: NVS + netif/event loop -> shared state -> board (I2C, display+LVGL) -> UI -> WiFi +
// agent health poll. The device is a thin voice client to its assigned hermes-sandbox agent.
#include <stdio.h>

#include "bsp/esp-bsp.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "agent_client.h"
#include "app_config.h"
#include "app_state.h"
#include "ui.h"
#include "wifi.h"

static const char *TAG = "app";

static void agent_health_task(void *arg)
{
    (void)arg;
    while (true) {
        conn_state_t conn = app_state_get_conn();
        if (conn == CONN_WIFI_OK || conn == CONN_AGENT_OK) {
            app_state_set_conn(agent_client_healthz() ? CONN_AGENT_OK : CONN_WIFI_OK);
        }
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "AgentKeys Touch-LCD-4B firmware v%s", PROJECT_VER);

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    app_state_init();
    app_state_append_message(ROLE_AGENT, "Hi! Hold TALK to speak with me.");
    agent_client_init(AGENT_BASE_URL, AGENT_BEARER);

    // Board bring-up: I2C (GT911 touch + ES8311 codec + TCA9554 expander) then the ST7701 RGB
    // display, which also starts the esp_lvgl_port LVGL task. Pins are owned by the BSP.
    ESP_ERROR_CHECK(bsp_i2c_init());
    lv_display_t *display = bsp_display_start();
    if (!display) {
        ESP_LOGE(TAG, "bsp_display_start failed");
        return;
    }

    ui_init();

    wifi_start(WIFI_SSID, WIFI_PASSWORD);
    xTaskCreate(agent_health_task, "agent_health", 4096, NULL, 3, NULL);

    // P3 adds ES8311 audio here: bsp_audio_init() + bsp_audio_codec_microphone_init() /
    // bsp_audio_codec_speaker_init() + bsp_audio_poweramp_enable(true), driving the TALK button.
    ESP_LOGI(TAG, "boot complete");
}
