// Desktop esp_http_client over libcurl (#517) — see the header for rationale.
#include "esp_http_client.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/// pthread_once wants void(void); curl_global_init takes flags. Called exactly
/// once per process, before any easy handle exists.
static void curl_global_init_once(void) { curl_global_init(CURL_GLOBAL_DEFAULT); }

struct esp_http_client {
    CURL *curl;
    struct curl_slist *headers;
    char *url;
    esp_http_client_method_t method;
    long timeout_ms;

    char *body;      // request body accumulated by write()
    size_t body_len;
    size_t body_cap;

    int pipe_fd[2];  // [0] read side for esp_http_client_read, [1] curl thread writes
    pthread_t worker;
    bool running;

    pthread_mutex_t lock;
    pthread_cond_t headers_ready;
    bool have_headers;
    long status;
    long content_length;
};

/// Body bytes → the pipe. A short write (reader slow) is retried, so a fast
/// stream can never silently drop tokens.
static size_t on_body(char *ptr, size_t size, size_t nmemb, void *userdata) {
    struct esp_http_client *c = (struct esp_http_client *)userdata;
    size_t total = size * nmemb, off = 0;
    while (off < total) {
        ssize_t n = write(c->pipe_fd[1], ptr + off, total - off);
        if (n <= 0) { return off; } // reader closed → tell curl to abort
        off += (size_t)n;
    }
    return total;
}

/// The blank line after the status/headers marks "headers complete" — that is
/// when fetch_headers() may return and the firmware may read the status.
static size_t on_header(char *buf, size_t size, size_t nmemb, void *userdata) {
    struct esp_http_client *c = (struct esp_http_client *)userdata;
    size_t total = size * nmemb;
    if (total <= 2 && (buf[0] == '\r' || buf[0] == '\n')) {
        pthread_mutex_lock(&c->lock);
        if (!c->have_headers) {
            curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE, &c->status);
            curl_off_t cl = -1;
            curl_easy_getinfo(c->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
            c->content_length = (long)cl;
            c->have_headers = true;
            pthread_cond_broadcast(&c->headers_ready);
        }
        pthread_mutex_unlock(&c->lock);
    }
    return total;
}

static void *worker_main(void *arg) {
    struct esp_http_client *c = (struct esp_http_client *)arg;
    curl_easy_perform(c->curl);
    // EOF for the reader; also unblocks a fetch_headers() waiting on a request
    // that died before any header arrived (connection refused, DNS, TLS).
    pthread_mutex_lock(&c->lock);
    if (!c->have_headers) {
        curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE, &c->status);
        c->have_headers = true;
        pthread_cond_broadcast(&c->headers_ready);
    }
    pthread_mutex_unlock(&c->lock);
    close(c->pipe_fd[1]);
    c->pipe_fd[1] = -1;
    return NULL;
}

esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *cfg) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, curl_global_init_once);

    struct esp_http_client *c = (struct esp_http_client *)calloc(1, sizeof(*c));
    if (!c) { return NULL; }
    c->curl = curl_easy_init();
    if (!c->curl) { free(c); return NULL; }
    c->url = cfg->url ? strdup(cfg->url) : NULL;
    c->method = cfg->method;
    c->timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : 0;
    c->pipe_fd[0] = c->pipe_fd[1] = -1;
    c->status = 0;
    c->content_length = -1;
    pthread_mutex_init(&c->lock, NULL);
    pthread_cond_init(&c->headers_ready, NULL);
    return c;
}

esp_err_t esp_http_client_set_header(esp_http_client_handle_t c, const char *k, const char *v) {
    if (!c) { return ESP_ERR_INVALID_ARG; }
    char line[2048];
    snprintf(line, sizeof(line), "%s: %s", k, v);
    struct curl_slist *n = curl_slist_append(c->headers, line);
    if (!n) { return ESP_ERR_NO_MEM; }
    c->headers = n;
    return ESP_OK;
}

esp_err_t esp_http_client_set_url(esp_http_client_handle_t c, const char *url) {
    if (!c) { return ESP_ERR_INVALID_ARG; }
    free(c->url);
    c->url = strdup(url);
    return ESP_OK;
}

esp_err_t esp_http_client_set_method(esp_http_client_handle_t c, esp_http_client_method_t m) {
    if (!c) { return ESP_ERR_INVALID_ARG; }
    c->method = m;
    return ESP_OK;
}

esp_err_t esp_http_client_open(esp_http_client_handle_t c, int write_len) {
    if (!c) { return ESP_ERR_INVALID_ARG; }
    c->body_len = 0;
    if (write_len > 0) {
        c->body_cap = (size_t)write_len;
        free(c->body);
        c->body = (char *)malloc(c->body_cap);
        if (!c->body) { return ESP_ERR_NO_MEM; }
    }
    if (pipe(c->pipe_fd) != 0) { return ESP_FAIL; }
    return ESP_OK;
}

int esp_http_client_write(esp_http_client_handle_t c, const char *data, int len) {
    if (!c || len < 0) { return -1; }
    if (c->body_len + (size_t)len > c->body_cap) {
        size_t cap = c->body_len + (size_t)len;
        char *nb = (char *)realloc(c->body, cap);
        if (!nb) { return -1; }
        c->body = nb;
        c->body_cap = cap;
    }
    memcpy(c->body + c->body_len, data, (size_t)len);
    c->body_len += (size_t)len;
    return len;
}

int esp_http_client_fetch_headers(esp_http_client_handle_t c) {
    if (!c || c->running) { return -1; }
    curl_easy_setopt(c->curl, CURLOPT_URL, c->url);
    curl_easy_setopt(c->curl, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(c->curl, CURLOPT_WRITEDATA, c);
    curl_easy_setopt(c->curl, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(c->curl, CURLOPT_HEADERDATA, c);
    curl_easy_setopt(c->curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c->curl, CURLOPT_NOSIGNAL, 1L);
    if (c->timeout_ms > 0) { curl_easy_setopt(c->curl, CURLOPT_TIMEOUT_MS, c->timeout_ms); }
    if (c->headers) { curl_easy_setopt(c->curl, CURLOPT_HTTPHEADER, c->headers); }
    switch (c->method) {
    case HTTP_METHOD_POST:
        curl_easy_setopt(c->curl, CURLOPT_POST, 1L);
        curl_easy_setopt(c->curl, CURLOPT_POSTFIELDS, c->body ? c->body : "");
        curl_easy_setopt(c->curl, CURLOPT_POSTFIELDSIZE, (long)c->body_len);
        break;
    case HTTP_METHOD_PUT:    curl_easy_setopt(c->curl, CURLOPT_CUSTOMREQUEST, "PUT");    break;
    case HTTP_METHOD_DELETE: curl_easy_setopt(c->curl, CURLOPT_CUSTOMREQUEST, "DELETE"); break;
    case HTTP_METHOD_GET:
    default:                 curl_easy_setopt(c->curl, CURLOPT_HTTPGET, 1L);            break;
    }

    if (pthread_create(&c->worker, NULL, worker_main, c) != 0) { return -1; }
    c->running = true;

    pthread_mutex_lock(&c->lock);
    while (!c->have_headers) { pthread_cond_wait(&c->headers_ready, &c->lock); }
    long len = c->content_length;
    pthread_mutex_unlock(&c->lock);
    return (int)len;
}

int esp_http_client_read(esp_http_client_handle_t c, char *buf, int len) {
    if (!c || c->pipe_fd[0] < 0) { return -1; }
    ssize_t n = read(c->pipe_fd[0], buf, (size_t)len);
    return n < 0 ? -1 : (int)n; // 0 = EOF, matching the device's socket read
}

int esp_http_client_get_status_code(esp_http_client_handle_t c) {
    if (!c) { return -1; }
    pthread_mutex_lock(&c->lock);
    long s = c->status;
    pthread_mutex_unlock(&c->lock);
    return (int)s;
}

esp_err_t esp_http_client_close(esp_http_client_handle_t c) {
    if (!c) { return ESP_ERR_INVALID_ARG; }
    if (c->pipe_fd[0] >= 0) { close(c->pipe_fd[0]); c->pipe_fd[0] = -1; }
    if (c->running) {
        pthread_join(c->worker, NULL);
        c->running = false;
    }
    if (c->pipe_fd[1] >= 0) { close(c->pipe_fd[1]); c->pipe_fd[1] = -1; }
    return ESP_OK;
}

esp_err_t esp_http_client_cleanup(esp_http_client_handle_t c) {
    if (!c) { return ESP_ERR_INVALID_ARG; }
    esp_http_client_close(c);
    if (c->headers) { curl_slist_free_all(c->headers); }
    if (c->curl) { curl_easy_cleanup(c->curl); }
    pthread_mutex_destroy(&c->lock);
    pthread_cond_destroy(&c->headers_ready);
    free(c->url);
    free(c->body);
    free(c);
    return ESP_OK;
}

esp_err_t esp_http_client_perform(esp_http_client_handle_t c) {
    if (!c) { return ESP_ERR_INVALID_ARG; }
    if (c->pipe_fd[0] < 0 && pipe(c->pipe_fd) != 0) { return ESP_FAIL; }
    if (esp_http_client_fetch_headers(c) < -1) { return ESP_FAIL; }
    char sink[1024];
    while (esp_http_client_read(c, sink, sizeof(sink)) > 0) { /* drain */ }
    return ESP_OK;
}
