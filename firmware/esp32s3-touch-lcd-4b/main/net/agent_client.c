#include "agent_client.h"
#include "app_config.h"
#include "app_state.h"

#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "agent";

static char s_base[APP_URL_MAXLEN];
static char s_bearer[200];
static volatile bool s_in_flight;

void agent_client_init(const char *base_url, const char *bearer)
{
    strncpy(s_base, base_url ? base_url : "", sizeof(s_base) - 1);
    s_base[sizeof(s_base) - 1] = '\0';
    strncpy(s_bearer, bearer ? bearer : "", sizeof(s_bearer) - 1);
    s_bearer[sizeof(s_bearer) - 1] = '\0';
}

static void set_auth(esp_http_client_handle_t client)
{
    esp_http_client_set_header(client, "Content-Type", "application/json");
    if (s_bearer[0]) {
        char auth[sizeof(s_bearer) + 8];
        snprintf(auth, sizeof(auth), "Bearer %s", s_bearer);
        esp_http_client_set_header(client, "Authorization", auth);
    }
}

// One SSE `data:` payload from the bridge: {type: token|tool_start|tool|done|error, ...}.
static void handle_event(const char *json)
{
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        return;
    }
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
    if (cJSON_IsString(type)) {
        if (strcmp(type->valuestring, "token") == 0) {
            const cJSON *text = cJSON_GetObjectItemCaseSensitive(root, "text");
            if (cJSON_IsString(text)) {
                app_state_append_to_last_agent(text->valuestring);
            }
        } else if (strcmp(type->valuestring, "error") == 0) {
            const cJSON *err = cJSON_GetObjectItemCaseSensitive(root, "error");
            app_state_append_to_last_agent("\n[agent error] ");
            app_state_append_to_last_agent(cJSON_IsString(err) ? err->valuestring : "unknown");
        }
        // tool_start / tool / done carry no reply text — nothing to render
    }
    cJSON_Delete(root);
}

static esp_err_t stream_turn(const char *text)
{
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "text", text);
    cJSON_AddBoolToObject(body, "stream", true);
    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        return ESP_ERR_NO_MEM;
    }

    char url[APP_URL_MAXLEN + 16];
    snprintf(url, sizeof(url), "%s/v1/chat", s_base);
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 30000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = APP_HTTP_RX_CHUNK,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    set_auth(client);

    esp_err_t result = ESP_OK;
    int body_len = (int)strlen(body_str);
    esp_err_t err = esp_http_client_open(client, body_len);
    if (err != ESP_OK) {
        app_state_append_to_last_agent("[agent unreachable]");
        free(body_str);
        esp_http_client_cleanup(client);
        return err;
    }
    int written = esp_http_client_write(client, body_str, body_len);
    free(body_str);
    if (written < 0) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }
    esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    if (status != 200) {
        char note[40];
        snprintf(note, sizeof(note), "[agent error] HTTP %d", status);
        app_state_append_to_last_agent(note);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    char buf[APP_HTTP_RX_CHUNK];
    char line[APP_MSG_MAXLEN + 64];
    size_t line_len = 0;
    while (true) {
        int read = esp_http_client_read(client, buf, sizeof(buf));
        if (read <= 0) {
            break;
        }
        for (int i = 0; i < read; i++) {
            char ch = buf[i];
            if (ch == '\n') {
                if (line_len && line[line_len - 1] == '\r') {
                    line_len--;
                }
                line[line_len] = '\0';
                if (strncmp(line, "data:", 5) == 0) {
                    const char *p = line + 5;
                    while (*p == ' ') {
                        p++;
                    }
                    handle_event(p);
                }
                line_len = 0;
            } else if (line_len < sizeof(line) - 1) {
                line[line_len++] = ch;
            }
        }
    }
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return result;
}

static void turn_task(void *arg)
{
    char *text = arg;
    app_state_append_message(ROLE_USER, text);
    app_state_append_message(ROLE_AGENT, "");
    esp_err_t err = stream_turn(text);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "turn failed: %s", esp_err_to_name(err));
    }
    free(text);
    s_in_flight = false;
    vTaskDelete(NULL);
}

void agent_client_send(const char *text)
{
    if (s_in_flight || !text || !text[0]) {
        return;
    }
    char *copy = strdup(text);
    if (!copy) {
        return;
    }
    s_in_flight = true;
    if (xTaskCreate(turn_task, "agent_turn", 8192, copy, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "failed to spawn turn task");
        free(copy);
        s_in_flight = false;
    }
}

bool agent_client_healthz(void)
{
    char url[APP_URL_MAXLEN + 16];
    snprintf(url, sizeof(url), "%s/healthz", s_base);
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = 8000,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client); // bridge returns 200 only when ok:true
    esp_http_client_cleanup(client);
    return err == ESP_OK && status == 200;
}
