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
#include "device_identity.h"
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

    // K10 device identity (issue #367): load from NVS, or generate-on-first-boot
    // via the SHARED agentkeys-device-core crate (the same secp256k1/keccak the
    // broker ecrecovers). After wifi_start() so the RNG has RF entropy. Phase B
    // (#367) feeds the §10.2 pairing request/poll from device_identity_pop_sig().
    if (device_identity_init() == ESP_OK) {
        char dkh[DEVICE_ID_HASH_LEN] = "";
        device_identity_key_hash(dkh, sizeof(dkh));
        ESP_LOGI(TAG, "device identity: addr=%s device_key_hash=%s", device_identity_address(), dkh);
        // Restore a persisted pairing so a reboot / reflash stays "✓ Paired" without a
        // re-claim (the binding lives in the nvs partition, not the app partition).
        char master[80];
        if (device_identity_paired(master, sizeof(master))) {
            app_state_set_pairing(PAIR_BOUND, "", "", dkh);
            ESP_LOGI(TAG, "restored paired state from NVS (master %s)", master);
        }

        // #369 bring-up self-check: produce a device->sandbox delegation co-signature
        // over a fixed dev sandbox key, proving the path links + the crypto worker has
        // stack for RFC6979 delegation signing on real hardware. The REAL sandbox key +
        // scope + TTL arrive over the broker relay once piece-2 (spawn-on-binding) lands;
        // until then this is the on-device proof the K10 can co-sign without ever leaving.
        char dsig[DEVICE_ID_SIG_LEN] = "";
        esp_err_t de = device_identity_delegation_sig(
            "0x1563915e194d8cfba1943570603f7606a3115508", "memory:get memory:put", 1767300000ULL,
            dsig, sizeof(dsig));
        ESP_LOGI(TAG, "delegation self-check (#369): %s sig=%.18s...",
                 de == ESP_OK ? "OK" : "FAIL", dsig);
    } else {
        ESP_LOGE(TAG, "device_identity_init failed");
    }

    xTaskCreate(agent_health_task, "agent_health", 4096, NULL, 3, NULL);

    // P3 adds ES8311 audio here: bsp_audio_init() + bsp_audio_codec_microphone_init() /
    // bsp_audio_codec_speaker_init() + bsp_audio_poweramp_enable(true), driving the TALK button.
    ESP_LOGI(TAG, "boot complete");
}
