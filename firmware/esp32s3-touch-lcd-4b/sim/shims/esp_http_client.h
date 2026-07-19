#pragma once
// Sim shim for esp_http_client.h (#517) — libcurl behind ESP-IDF's API.
//
// The firmware uses the STREAMING form (open → write → fetch_headers → read…),
// which is what makes `/v1/chat` SSE work: agent_client.c pulls tokens as they
// arrive and appends them to app_state, so the reply streams into the bubble.
// A request/response shim would have broken that into one late blob, so this
// preserves the pull semantics: a worker thread runs curl and pushes body bytes
// into a pipe; esp_http_client_read() reads the pipe (blocking, exactly like the
// device's socket read).
//
// TLS is libcurl's default verification against the system trust store — never
// disabled (see esp_crt_bundle.h).
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

typedef enum {
    HTTP_METHOD_GET = 0,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
} esp_http_client_method_t;

typedef struct esp_http_client *esp_http_client_handle_t;

typedef struct esp_http_client_config_t {
    const char *url;
    esp_http_client_method_t method;
    int timeout_ms;
    esp_err_t (*crt_bundle_attach)(void *conf);
    int buffer_size;
    int buffer_size_tx;
    bool disable_auto_redirect;
    void *user_data;
} esp_http_client_config_t;

esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *cfg);
esp_err_t esp_http_client_set_header(esp_http_client_handle_t c, const char *k, const char *v);
esp_err_t esp_http_client_set_url(esp_http_client_handle_t c, const char *url);
esp_err_t esp_http_client_set_method(esp_http_client_handle_t c, esp_http_client_method_t m);

/// Begin a request whose body is `write_len` bytes (0 = none). The transfer is
/// not issued until fetch_headers(), so write() can fill the body first.
esp_err_t esp_http_client_open(esp_http_client_handle_t c, int write_len);
int       esp_http_client_write(esp_http_client_handle_t c, const char *data, int len);
/// Issue the request and block until response headers are in. Returns the
/// Content-Length (-1 when chunked/unknown, as on-device for SSE).
int       esp_http_client_fetch_headers(esp_http_client_handle_t c);
int       esp_http_client_read(esp_http_client_handle_t c, char *buf, int len);
int       esp_http_client_get_status_code(esp_http_client_handle_t c);
esp_err_t esp_http_client_close(esp_http_client_handle_t c);
esp_err_t esp_http_client_cleanup(esp_http_client_handle_t c);
/// One-shot (no streaming): issue and drain.
esp_err_t esp_http_client_perform(esp_http_client_handle_t c);
