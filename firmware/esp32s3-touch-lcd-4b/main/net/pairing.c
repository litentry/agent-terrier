#include "pairing.h"
#include "app_config.h"
#include "app_state.h"
#include "device_identity.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// §10.2 device-initiated pairing (arch.md), spoken DIRECTLY to the broker with the
// device's OWN K10 (device_identity) — pop_sig-authenticated, no bearer, no agent
// bridge in the path (issue #367 Phase B). The device opens an unbound pairing
// request, shows the canonical agentkeys-pair://claim QR for the master to claim in
// parent-control, then polls until the broker mints J1_agent (status "claimed") →
// bound. The broker's §10.2 endpoints already exist; this needs no server change.
#define PAIRING_REQUEST_PATH "/v1/agent/pairing/request"
#define PAIRING_POLL_PATH    "/v1/agent/pairing/poll"
#define PAIRING_POLL_TRIES   200
#define PAIRING_POLL_MS      3000

static const char *TAG = "pairing";
static volatile bool s_active;

// Off-stack scratch (one pairing task at a time, guarded by s_active): the HTTPS/
// mbedTLS handshake already needs most of the task stack, so keep these buffers in
// .bss rather than blowing the stack with a ~2 KB response buffer.
static char s_req[384];
static char s_body[2048];

// POST `req` (JSON) to `url`, read the JSON response into `out`. Returns the HTTP
// status, or -1 on a transport error. TLS validated against the bundled CA roots.
static int http_post_json(const char *url, const char *req, char *out, size_t out_len)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 1536,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    if (esp_http_client_open(client, strlen(req)) != ESP_OK) {
        esp_http_client_cleanup(client);
        return -1;
    }
    if (esp_http_client_write(client, req, strlen(req)) < 0) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return -1;
    }
    esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    size_t pos = 0;
    while (pos < out_len - 1) {
        int r = esp_http_client_read(client, out + pos, (int)(out_len - 1 - pos));
        if (r <= 0) {
            break;
        }
        pos += (size_t)r;
    }
    out[pos] = '\0';
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return status;
}

static void pairing_fail(void)
{
    app_state_set_pairing(PAIR_ERROR, "", "", "");
    s_active = false;
    vTaskDelete(NULL);
}

static void pairing_task(void *arg)
{
    (void)arg;
    app_state_set_pairing(PAIR_REQUESTING, NULL, NULL, NULL);

    const char *addr = device_identity_address();
    if (!addr[0]) {
        ESP_LOGE(TAG, "device identity not ready (K10 missing)");
        pairing_fail();
        return;
    }

    // The device's proof-of-possession over its K10. Deterministic (RFC6979), so a
    // single signature serves the request AND every poll. Computed on the device-
    // identity crypto task (big stack), not here.
    char pop[DEVICE_ID_SIG_LEN];
    if (device_identity_pop_sig(pop, sizeof(pop)) != ESP_OK) {
        ESP_LOGE(TAG, "pop_sig failed");
        pairing_fail();
        return;
    }

    char url[APP_URL_MAXLEN + 40];

    // 1. Open the UNBOUND pairing request at the broker.
    snprintf(url, sizeof(url), "%s%s", BROKER_URL, PAIRING_REQUEST_PATH);
    snprintf(s_req, sizeof(s_req), "{\"device_pubkey\":\"%s\",\"pop_sig\":\"%s\"}", addr, pop);
    int status = http_post_json(url, s_req, s_body, sizeof(s_body));
    if (status != 200) {
        ESP_LOGW(TAG, "pairing request -> %d (broker %s)", status, PAIRING_REQUEST_PATH);
        pairing_fail();
        return;
    }

    cJSON *root = cJSON_Parse(s_body);
    if (!root) {
        pairing_fail();
        return;
    }
    const cJSON *rid = cJSON_GetObjectItemCaseSensitive(root, "request_id");
    const cJSON *code = cJSON_GetObjectItemCaseSensitive(root, "pairing_code");
    const cJSON *hash = cJSON_GetObjectItemCaseSensitive(root, "device_key_hash");
    if (!cJSON_IsString(rid) || !cJSON_IsString(code)) {
        cJSON_Delete(root);
        pairing_fail();
        return;
    }

    // 2. Build the canonical claim deep-link the master scans in parent-control.
    //    pairing_code is b64url (URL-safe) and a broker URL carries no &/=/# so the
    //    query value needs no escaping.
    char deep_link[APP_DEEPLINK_MAXLEN];
    snprintf(deep_link, sizeof(deep_link), "agentkeys-pair://claim?code=%s&broker=%s",
             code->valuestring, BROKER_URL);
    app_state_set_pairing(PAIR_UNBOUND, deep_link, code->valuestring,
                          cJSON_IsString(hash) ? hash->valuestring : "");

    // Echo the claim secrets to the monitor for easy debugging (the on-screen QR
    // encodes the same deep-link). Logged BEFORE the JSON is freed.
    ESP_LOGI(TAG, "pairing opened — claim this in parent-control:");
    ESP_LOGI(TAG, "  code:      %s", code->valuestring);
    ESP_LOGI(TAG, "  deep-link: %s", deep_link);
    if (cJSON_IsString(hash)) {
        ESP_LOGI(TAG, "  device-key-hash: %s", hash->valuestring);
    }

    // request_id is the SECRET retrieval ticket — keep it (out of the JSON) to poll.
    char request_id[96];
    strncpy(request_id, rid->valuestring, sizeof(request_id) - 1);
    request_id[sizeof(request_id) - 1] = '\0';
    cJSON_Delete(root);
    ESP_LOGI(TAG, "polling for the master's claim...");

    // 3. Poll until claimed (broker mints J1_agent) → bound.
    snprintf(url, sizeof(url), "%s%s", BROKER_URL, PAIRING_POLL_PATH);
    snprintf(s_req, sizeof(s_req),
             "{\"request_id\":\"%s\",\"device_pubkey\":\"%s\",\"pop_sig\":\"%s\"}", request_id,
             addr, pop);
    for (int i = 0; i < PAIRING_POLL_TRIES; i++) {
        vTaskDelay(pdMS_TO_TICKS(PAIRING_POLL_MS));
        int s = http_post_json(url, s_req, s_body, sizeof(s_body));
        if (s == 401 || s == 410) {
            ESP_LOGW(TAG, "pairing poll -> %d (request expired / unknown)", s);
            app_state_set_pairing(PAIR_ERROR, "", "", "");
            break;
        }
        if (s != 200) {
            continue; // transient; keep polling
        }
        cJSON *poll = cJSON_Parse(s_body);
        if (!poll) {
            continue;
        }
        const cJSON *st = cJSON_GetObjectItemCaseSensitive(poll, "status");
        const cJSON *op = cJSON_GetObjectItemCaseSensitive(poll, "operator_omni");
        const cJSON *child = cJSON_GetObjectItemCaseSensitive(poll, "child_omni");
        bool claimed = cJSON_IsString(st) && strcmp(st->valuestring, "claimed") == 0;
        if (claimed) {
            // Persist the binding BEFORE freeing the JSON, so a reboot / reflash stays
            // paired (the master need not re-claim).
            device_identity_save_binding(cJSON_IsString(op) ? op->valuestring : NULL,
                                         cJSON_IsString(child) ? child->valuestring : NULL);
            if (cJSON_IsString(op)) {
                ESP_LOGI(TAG, "claimed by master omni %s", op->valuestring);
            }
        }
        cJSON_Delete(poll);
        if (claimed) {
            app_state_set_pairing(PAIR_BOUND, NULL, NULL, NULL); // keep the shown hash
            ESP_LOGI(TAG, "device bound + persisted");
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
    // 8 KB: the HTTPS/mbedTLS handshake is the stack hog; the K10 pop_sig runs on
    // device_identity's own large-stack task, so it costs nothing here.
    if (xTaskCreate(pairing_task, "pairing", 8192, NULL, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "failed to spawn pairing task");
        s_active = false;
    }
}
