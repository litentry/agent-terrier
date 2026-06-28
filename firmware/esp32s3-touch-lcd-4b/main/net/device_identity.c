#include "device_identity.h"

#include <string.h>

#include "agentkeys_device.h" // generated FFI header for agentkeys-device-core
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"

static const char *TAG = "device_id";

#define NVS_NS         "agentkeys"
#define NVS_KEY_DEVKEY "device_key"  // the 32-byte K10 private scalar (blob)
#define NVS_KEY_PAIRED "paired"      // u8 flag: 1 once a master has claimed this device
#define NVS_KEY_MASTER "master_omni" // the operator (master) omni from the §10.2 claim
#define NVS_KEY_CHILD  "child_omni"  // this device's agent (child) omni

// k256 secp256k1 (keygen + ECDSA) needs far more stack than the firmware's default
// task stacks (the 8 KB main task overflowed → boot-loop, #367). It runs on a
// PERSISTENT worker with a STATIC stack:
//   - static, so it can't fail to allocate — a dynamic xTaskCreate from the heap
//     failed once WiFi had fragmented internal RAM ("could not spawn the crypto task");
//   - persistent (one long-lived worker fed by a queue), so there's no create/delete
//     churn and no reuse race.
// Internal RAM (not PSRAM): the worker also runs NVS writes (flash ops), which a
// PSRAM-resident stack could not survive while the cache is disabled.
#define CRYPTO_STACK_BYTES 32768
#define CRYPTO_STACK_WORDS (CRYPTO_STACK_BYTES / sizeof(StackType_t))

static StaticTask_t s_crypto_tcb;
static StackType_t s_crypto_stack[CRYPTO_STACK_WORDS];
static QueueHandle_t s_crypto_q;

static uint8_t s_priv[32];
static bool s_have;
static char s_address[DEVICE_ID_ADDR_LEN];

typedef struct {
    esp_err_t (*fn)(void *ctx);
    void *ctx;
    esp_err_t result;
    SemaphoreHandle_t done;
} crypto_job_t;

static void crypto_worker(void *arg)
{
    (void)arg;
    crypto_job_t *job = NULL;
    for (;;) {
        if (xQueueReceive(s_crypto_q, &job, portMAX_DELAY) == pdTRUE && job) {
            job->result = job->fn(job->ctx);
            ESP_LOGI(TAG, "crypto job: stack low-water %u B",
                     (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)));
            xSemaphoreGive(job->done);
        }
    }
}

// Dispatch `fn(ctx)` to the persistent crypto worker (big static stack) and block the
// caller until it returns. Lazily starts the worker on the first call (boot, single-
// threaded), so the big stack costs nothing until first use.
static esp_err_t run_on_crypto_task(esp_err_t (*fn)(void *), void *ctx)
{
    if (!s_crypto_q) {
        s_crypto_q = xQueueCreate(2, sizeof(crypto_job_t *));
        if (!s_crypto_q) {
            return ESP_ERR_NO_MEM;
        }
        xTaskCreateStatic(crypto_worker, "ak_crypto", CRYPTO_STACK_WORDS, NULL, 5, s_crypto_stack,
                          &s_crypto_tcb);
    }
    crypto_job_t job = {.fn = fn, .ctx = ctx, .result = ESP_FAIL, .done = xSemaphoreCreateBinary()};
    if (!job.done) {
        return ESP_ERR_NO_MEM;
    }
    crypto_job_t *jp = &job;
    if (xQueueSend(s_crypto_q, &jp, portMAX_DELAY) != pdTRUE) {
        vSemaphoreDelete(job.done);
        return ESP_ERR_NO_MEM;
    }
    xSemaphoreTake(job.done, portMAX_DELAY);
    vSemaphoreDelete(job.done);
    return job.result;
}

static esp_err_t persist_key(void)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) {
        return e;
    }
    e = nvs_set_blob(h, NVS_KEY_DEVKEY, s_priv, sizeof(s_priv));
    if (e == ESP_OK) {
        e = nvs_commit(h);
    }
    nvs_close(h);
    return e;
}

// Load the K10 from NVS, or generate + persist one on first boot. Runs on the crypto
// worker (ak_device_keygen / ak_device_address do EC math).
static esp_err_t id_init_run(void *ctx)
{
    (void)ctx;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(s_priv);
        esp_err_t e = nvs_get_blob(h, NVS_KEY_DEVKEY, s_priv, &len);
        nvs_close(h);
        if (e == ESP_OK && len == sizeof(s_priv) &&
            ak_device_address(s_priv, s_address, sizeof(s_address)) == AK_OK) {
            s_have = true;
            ESP_LOGI(TAG, "K10 loaded from NVS: %s", s_address);
            return ESP_OK;
        }
    }

    // First boot: generate from hardware entropy. esp_fill_random is a CSPRNG only
    // while the RF subsystem is active, so init() must run after wifi_start().
    uint8_t entropy[32];
    esp_fill_random(entropy, sizeof(entropy));
    Ak r = ak_device_keygen(entropy, s_priv, s_address, sizeof(s_address));
    memset(entropy, 0, sizeof(entropy)); // scrub the transient copy
    if (r != AK_OK) {
        ESP_LOGE(TAG, "ak_device_keygen failed: %d", (int)r);
        return ESP_FAIL;
    }
    esp_err_t e = persist_key();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "K10 persist failed: %s", esp_err_to_name(e));
        return e;
    }
    s_have = true;
    ESP_LOGI(TAG, "K10 generated + stored: %s", s_address);
    return ESP_OK;
}

esp_err_t device_identity_init(void)
{
    return run_on_crypto_task(id_init_run, NULL);
}

const char *device_identity_address(void)
{
    return s_have ? s_address : "";
}

esp_err_t device_identity_key_hash(char *out, size_t cap)
{
    // keccak only (no EC scalar math) — light stack, safe on the caller's task.
    if (!s_have) {
        return ESP_ERR_INVALID_STATE;
    }
    return ak_device_key_hash(s_address, out, cap) == AK_OK ? ESP_OK : ESP_FAIL;
}

typedef struct {
    char *out;
    size_t cap;
} pop_sig_ctx_t;

static esp_err_t pop_sig_run(void *ctx)
{
    pop_sig_ctx_t *c = (pop_sig_ctx_t *)ctx;
    return ak_device_pop_sig(s_priv, c->out, c->cap) == AK_OK ? ESP_OK : ESP_FAIL;
}

esp_err_t device_identity_pop_sig(char *out, size_t cap)
{
    // RFC6979 ECDSA — heavier on the stack than keygen; same crypto-worker path.
    if (!s_have) {
        return ESP_ERR_INVALID_STATE;
    }
    pop_sig_ctx_t ctx = {.out = out, .cap = cap};
    return run_on_crypto_task(pop_sig_run, &ctx);
}

typedef struct {
    const char *sandbox_key;
    const char *scope;
    uint64_t expires_at;
    char *out;
    size_t cap;
} deleg_ctx_t;

static esp_err_t deleg_sig_run(void *ctx)
{
    deleg_ctx_t *c = (deleg_ctx_t *)ctx;
    return ak_device_delegation_sig(s_priv, c->sandbox_key, c->scope, c->expires_at, c->out,
                                    c->cap) == AK_OK
               ? ESP_OK
               : ESP_FAIL;
}

esp_err_t device_identity_delegation_sig(const char *sandbox_key, const char *scope,
                                         uint64_t expires_at, char *out, size_t cap)
{
    // Same RFC6979 ECDSA + crypto-worker path as pop_sig; device_key_hash is derived
    // from the K10 inside the FFI, so the device can only ever delegate under its own.
    if (!s_have) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!sandbox_key || !scope || !out) {
        return ESP_ERR_INVALID_ARG;
    }
    deleg_ctx_t ctx = {.sandbox_key = sandbox_key,
                       .scope = scope,
                       .expires_at = expires_at,
                       .out = out,
                       .cap = cap};
    return run_on_crypto_task(deleg_sig_run, &ctx);
}

esp_err_t device_identity_save_binding(const char *master_omni, const char *child_omni)
{
    // Pure NVS (no EC) — runs on the caller. Survives reboot + `idf.py flash` (the nvs
    // partition is not erased); only `idf.py erase-flash` / a factory reset clears it.
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) {
        return e;
    }
    e = nvs_set_u8(h, NVS_KEY_PAIRED, 1);
    if (e == ESP_OK && master_omni && master_omni[0]) {
        e = nvs_set_str(h, NVS_KEY_MASTER, master_omni);
    }
    if (e == ESP_OK && child_omni && child_omni[0]) {
        e = nvs_set_str(h, NVS_KEY_CHILD, child_omni);
    }
    if (e == ESP_OK) {
        e = nvs_commit(h);
    }
    nvs_close(h);
    return e;
}

bool device_identity_paired(char *master_out, size_t cap)
{
    if (master_out && cap) {
        master_out[0] = '\0';
    }
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    uint8_t paired = 0;
    nvs_get_u8(h, NVS_KEY_PAIRED, &paired);
    if (paired && master_out && cap) {
        size_t len = cap;
        nvs_get_str(h, NVS_KEY_MASTER, master_out, &len);
    }
    nvs_close(h);
    return paired == 1;
}
