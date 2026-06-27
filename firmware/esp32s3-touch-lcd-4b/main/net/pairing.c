#include "pairing.h"
#include "app_config.h"
#include "app_state.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// The device asks its agent for the pairing artifact, then polls until the web master claims it.
// These two endpoints front the daemon's --request-pairing / --retrieve-pairing inside the
// sandbox (PR #347 request_artifact: deep_link + pairing_code + device_key_hash). Exposing them
// on the bridge is the P2 dependency; until then a request surfaces PAIR_ERROR (never a fake QR).
#define PAIRING_REQUEST_PATH "/v1/pairing/request"
#define PAIRING_POLL_PATH    "/v1/pairing/poll"
#define PAIRING_POLL_TRIES   200
#define PAIRING_POLL_MS      3000

static const char *TAG = "pairing";
static volatile bool s_active;

static int http_get_json(const char *url, char *out, size_t out_len)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 1024,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    if (AGENT_BEARER[0]) {
        char auth[200];
        snprintf(auth, sizeof(auth), "Bearer %s", AGENT_BEARER);
        esp_http_client_set_header(client, "Authorization", auth);
    }
    if (esp_http_client_open(client, 0) != ESP_OK) {
        esp_http_client_cleanup(client);
        return -1;
    }
    esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    size_t pos = 0;
    while (pos < out_len - 1) {
        int read = esp_http_client_read(client, out + pos, (int)(out_len - 1 - pos));
        if (read <= 0) {
            break;
        }
        pos += (size_t)read;
    }
    out[pos] = '\0';
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return status;
}

static void pairing_task(void *arg)
{
    (void)arg;
    app_state_set_pairing(PAIR_REQUESTING, NULL, NULL, NULL);

    char url[APP_URL_MAXLEN + 32];
    char body[1024];
    snprintf(url, sizeof(url), "%s%s", AGENT_BASE_URL, PAIRING_REQUEST_PATH);
    int status = http_get_json(url, body, sizeof(body));
    if (status != 200) {
        ESP_LOGW(TAG, "pairing request -> %d (agent pairing endpoint is the P2 dependency)", status);
        app_state_set_pairing(PAIR_ERROR, "", "", "");
        s_active = false;
        vTaskDelete(NULL);
        return;
    }

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        app_state_set_pairing(PAIR_ERROR, "", "", "");
        s_active = false;
        vTaskDelete(NULL);
        return;
    }
    const cJSON *deep_link = cJSON_GetObjectItemCaseSensitive(root, "deep_link");
    const cJSON *code = cJSON_GetObjectItemCaseSensitive(root, "pairing_code");
    const cJSON *hash = cJSON_GetObjectItemCaseSensitive(root, "device_key_hash");
    app_state_set_pairing(PAIR_UNBOUND, cJSON_IsString(deep_link) ? deep_link->valuestring : "",
                          cJSON_IsString(code) ? code->valuestring : "",
                          cJSON_IsString(hash) ? hash->valuestring : "");
    cJSON_Delete(root);
    ESP_LOGI(TAG, "pairing artifact ready; polling for claim");

    snprintf(url, sizeof(url), "%s%s", AGENT_BASE_URL, PAIRING_POLL_PATH);
    for (int i = 0; i < PAIRING_POLL_TRIES; i++) {
        vTaskDelay(pdMS_TO_TICKS(PAIRING_POLL_MS));
        if (http_get_json(url, body, sizeof(body)) != 200) {
            continue;
        }
        cJSON *poll = cJSON_Parse(body);
        if (!poll) {
            continue;
        }
        const cJSON *bound = cJSON_GetObjectItemCaseSensitive(poll, "bound");
        bool is_bound = cJSON_IsTrue(bound);
        cJSON_Delete(poll);
        if (is_bound) {
            app_state_set_pairing(PAIR_BOUND, NULL, NULL, NULL);
            ESP_LOGI(TAG, "device bound");
            break;
        }
    }

    s_active = false;
    vTaskDelete(NULL);
}

void pairing_start(void)
{
    if (s_active) {
        return;
    }
    if (app_state_get_pairing(NULL, 0, NULL, 0, NULL, 0) == PAIR_BOUND) {
        return;
    }
    s_active = true;
    if (xTaskCreate(pairing_task, "pairing", 6144, NULL, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "failed to spawn pairing task");
        s_active = false;
    }
}
