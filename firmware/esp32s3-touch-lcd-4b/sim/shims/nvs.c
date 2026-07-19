// Desktop NVS (#517) — see nvs.h for the rationale + file format.
#include "nvs.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_ENTRIES 32
#define MAX_KEY     32
#define MAX_VAL     512 // the K10 blob is 32 B; omnis are 64-hex — ample

struct entry {
    char key[MAX_KEY];
    char type; // 'b' blob (hex), 's' string, 'u' u8
    unsigned char val[MAX_VAL];
    size_t len;
};

struct nvs_handle_impl {
    char ns[MAX_KEY];
    struct entry e[MAX_ENTRIES];
    size_t n;
    int writable;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *store_dir(void) {
    static char dir[1024];
    if (dir[0]) { return dir; }
    const char *override = getenv("AGENTKEYS_MOCK_DEVICE_DIR");
    if (override && *override) {
        snprintf(dir, sizeof(dir), "%s", override);
    } else {
        const char *home = getenv("HOME");
        snprintf(dir, sizeof(dir), "%s/.agentkeys/mock-device", home ? home : ".");
    }
    // mkdir -p (two levels is all we need)
    char parent[1024];
    snprintf(parent, sizeof(parent), "%s", dir);
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        mkdir(parent, 0700);
    }
    mkdir(dir, 0700);
    return dir;
}

const char *nvs_sim_path(const char *ns) {
    static char path[1200];
    snprintf(path, sizeof(path), "%s/%s.nvs", store_dir(), ns);
    return path;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

static void load(struct nvs_handle_impl *h) {
    FILE *f = fopen(nvs_sim_path(h->ns), "r");
    if (!f) { return; }
    char line[2048];
    while (h->n < MAX_ENTRIES && fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) { *nl = '\0'; }
        char *t1 = strchr(line, '\t');
        if (!t1) { continue; }
        *t1 = '\0';
        char *t2 = strchr(t1 + 1, '\t');
        if (!t2) { continue; }
        *t2 = '\0';
        struct entry *e = &h->e[h->n];
        snprintf(e->key, sizeof(e->key), "%s", line);
        e->type = t1[1];
        const char *v = t2 + 1;
        if (e->type == 'b') {
            size_t hexlen = strlen(v);
            e->len = hexlen / 2;
            if (e->len > MAX_VAL) { continue; }
            for (size_t i = 0; i < e->len; i++) {
                int hi = hexval(v[i * 2]), lo = hexval(v[i * 2 + 1]);
                if (hi < 0 || lo < 0) { e->len = 0; break; }
                e->val[i] = (unsigned char)((hi << 4) | lo);
            }
        } else {
            e->len = strlen(v);
            if (e->len >= MAX_VAL) { continue; }
            memcpy(e->val, v, e->len);
            e->val[e->len] = '\0';
        }
        h->n++;
    }
    fclose(f);
}

static esp_err_t store(struct nvs_handle_impl *h) {
    const char *path = nvs_sim_path(h->ns);
    char tmp[1300];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) { return ESP_FAIL; }
    // 0600 BEFORE any secret lands in it.
    if (chmod(tmp, 0600) != 0) { /* best-effort; umask usually suffices */ }
    for (size_t i = 0; i < h->n; i++) {
        struct entry *e = &h->e[i];
        fprintf(f, "%s\t%c\t", e->key, e->type);
        if (e->type == 'b') {
            for (size_t j = 0; j < e->len; j++) { fprintf(f, "%02x", e->val[j]); }
        } else {
            fwrite(e->val, 1, e->len, f);
        }
        fputc('\n', f);
    }
    fclose(f);
    return rename(tmp, path) == 0 ? ESP_OK : ESP_FAIL;
}

static struct entry *find(struct nvs_handle_impl *h, const char *key) {
    for (size_t i = 0; i < h->n; i++) {
        if (strcmp(h->e[i].key, key) == 0) { return &h->e[i]; }
    }
    return NULL;
}

static struct entry *upsert(struct nvs_handle_impl *h, const char *key) {
    struct entry *e = find(h, key);
    if (e) { return e; }
    if (h->n >= MAX_ENTRIES) { return NULL; }
    e = &h->e[h->n++];
    snprintf(e->key, sizeof(e->key), "%s", key);
    return e;
}

esp_err_t nvs_flash_init(void) { return ESP_OK; }

esp_err_t nvs_open(const char *ns, nvs_open_mode_t mode, nvs_handle_t *out) {
    struct nvs_handle_impl *h = (struct nvs_handle_impl *)calloc(1, sizeof(*h));
    if (!h) { return ESP_ERR_NO_MEM; }
    snprintf(h->ns, sizeof(h->ns), "%s", ns);
    h->writable = (mode == NVS_READWRITE);
    pthread_mutex_lock(&g_lock);
    load(h);
    pthread_mutex_unlock(&g_lock);
    *out = h;
    return ESP_OK;
}

void nvs_close(nvs_handle_t h) { free(h); }

esp_err_t nvs_commit(nvs_handle_t h) {
    if (!h->writable) { return ESP_ERR_INVALID_STATE; }
    pthread_mutex_lock(&g_lock);
    esp_err_t r = store(h);
    pthread_mutex_unlock(&g_lock);
    return r;
}

esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *val, size_t len) {
    if (!h->writable || len > MAX_VAL) { return ESP_ERR_INVALID_ARG; }
    struct entry *e = upsert(h, key);
    if (!e) { return ESP_ERR_NO_MEM; }
    e->type = 'b';
    memcpy(e->val, val, len);
    e->len = len;
    return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *len) {
    struct entry *e = find(h, key);
    if (!e || e->type != 'b') { return ESP_ERR_NVS_NOT_FOUND; }
    if (!out) { *len = e->len; return ESP_OK; }
    if (*len < e->len) { return ESP_ERR_INVALID_SIZE; }
    memcpy(out, e->val, e->len);
    *len = e->len;
    return ESP_OK;
}

esp_err_t nvs_set_str(nvs_handle_t h, const char *key, const char *val) {
    size_t n = strlen(val);
    if (!h->writable || n >= MAX_VAL) { return ESP_ERR_INVALID_ARG; }
    struct entry *e = upsert(h, key);
    if (!e) { return ESP_ERR_NO_MEM; }
    e->type = 's';
    memcpy(e->val, val, n);
    e->val[n] = '\0';
    e->len = n;
    return ESP_OK;
}

esp_err_t nvs_get_str(nvs_handle_t h, const char *key, char *out, size_t *len) {
    struct entry *e = find(h, key);
    if (!e || e->type != 's') { return ESP_ERR_NVS_NOT_FOUND; }
    if (!out) { *len = e->len + 1; return ESP_OK; }
    if (*len < e->len + 1) { return ESP_ERR_INVALID_SIZE; }
    memcpy(out, e->val, e->len);
    out[e->len] = '\0';
    *len = e->len + 1;
    return ESP_OK;
}

esp_err_t nvs_set_u8(nvs_handle_t h, const char *key, uint8_t val) {
    if (!h->writable) { return ESP_ERR_INVALID_STATE; }
    struct entry *e = upsert(h, key);
    if (!e) { return ESP_ERR_NO_MEM; }
    e->type = 'u';
    e->len = 1;
    snprintf((char *)e->val, MAX_VAL, "%u", (unsigned)val);
    e->len = strlen((char *)e->val);
    return ESP_OK;
}

esp_err_t nvs_get_u8(nvs_handle_t h, const char *key, uint8_t *out) {
    struct entry *e = find(h, key);
    if (!e || e->type != 'u') { return ESP_ERR_NVS_NOT_FOUND; }
    *out = (uint8_t)atoi((const char *)e->val);
    return ESP_OK;
}
