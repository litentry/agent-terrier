#include "channel_client.h"
#include "app_config.h"
#include "app_state.h"
#include "audio_io.h"
#include "device_identity.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

// #523 — device-minted channel messaging. The device resolves a session (J1)
// with its K10 agent-PoP, mints channel-pub/sub caps with its #76 cap-PoP
// (op=channel_publish/subscribe, data_class=channel), and publishes/polls on the
// channel worker. The CapToken the broker returns is stored + forwarded
// VERBATIM — broker_sig covers Sha256(json(payload)), so the device must never
// re-serialize it field-by-field.
#define RESOLVE_PATH  "/v1/agent/resolve"
#define CAP_PUB_PATH  "/v1/cap/channel-pub"
#define CAP_SUB_PATH  "/v1/cap/channel-sub"
#define PUBLISH_PATH  "/v1/channel/publish"
#define POLL_PATH     "/v1/channel/poll"
#define CAP_TTL_SECS  300
// Short long-poll: a device both sends + receives on one task, so the poll
// wait bounds how long a just-enqueued turn waits before it's drained. Replies
// are unaffected — the worker's NRT wakeup completes a held poll immediately on
// a delegate publish, so this only sets the idle re-poll / send-drain cadence.
#define POLL_WAIT_SEC 3

static const char *TAG = "channel";

// Off-stack scratch (.bss): the HTTPS/mbedTLS handshake already needs most of a
// task's stack, so keep the ~KB buffers here. One publish/poll in flight at a
// time (the poll loop is single-threaded; publish is called from the UI turn
// task while the loop is parked in a poll — the worker serializes on S3).
static char s_session[1200]; // session_jwt (JWT can be long)
static char s_pub_cap[1400]; // channel-pub CapToken JSON, stored verbatim
static char s_sub_cap[1400]; // channel-sub CapToken JSON, stored verbatim
static char s_req[6144];
static char s_resp[8192];
static char s_cursor[160]; // the poll feed-key cursor (S3 key), advances per event
static volatile bool s_started;

// Outgoing turns are QUEUED, not published inline: a caller (the LVGL TALK
// handler) must never block on the HTTPS publish, and ALL channel HTTP + the
// shared buffers/caps are owned by the single channel task, so there is no
// cross-thread buffer race. `body_b64` is heap-owned (freed after publish), so
// a turn of any size (a future audio-clip) fits without a fixed item buffer.
typedef struct {
    char kind[16];
    char *body_b64;
    char voice[48];  // "" = omit
    int speech_rate; // INT32_MIN = omit
} outbox_item_t;
static QueueHandle_t s_outbox;

// ── minimal base64 (portable across the sim + ESP32; no mbedTLS dependency) ──
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Encode `len` bytes → NUL-terminated base64 in `out` (cap incl. NUL). Returns
// the written length, or -1 if `out` is too small.
static int b64_encode(const uint8_t *in, size_t len, char *out, size_t cap)
{
    size_t need = 4 * ((len + 2) / 3) + 1;
    if (cap < need) {
        return -1;
    }
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint32_t)in[i] << 16;
        n |= (i + 1 < len ? (uint32_t)in[i + 1] : 0) << 8;
        n |= (i + 2 < len ? (uint32_t)in[i + 2] : 0);
        out[o++] = B64[(n >> 18) & 63];
        out[o++] = B64[(n >> 12) & 63];
        out[o++] = (i + 1 < len) ? B64[(n >> 6) & 63] : '=';
        out[o++] = (i + 2 < len) ? B64[n & 63] : '=';
    }
    out[o] = '\0';
    return (int)o;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Decode base64 `in` → bytes in `out` (cap). Returns the byte length, or -1.
static int b64_decode(const char *in, uint8_t *out, size_t cap)
{
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '=' || *p == '\n' || *p == '\r') {
            continue;
        }
        int v = b64_val(*p);
        if (v < 0) {
            return -1;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) {
                return -1;
            }
            out[o++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    return (int)o;
}

// ── HTTP ─────────────────────────────────────────────────────────────────────
// POST `req` (JSON) to `url`, optional Bearer, read the JSON response into `out`.
// Returns the HTTP status, or -1 on a transport error. TLS validated against the
// bundled CA roots (the sim's shim uses the system trust store; never disabled).
static int http_post(const char *url, const char *bearer, const char *req, char *out,
                     size_t out_len)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 30000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 1536,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    if (bearer && bearer[0]) {
        char auth[1300];
        snprintf(auth, sizeof(auth), "Bearer %s", bearer);
        esp_http_client_set_header(client, "Authorization", auth);
    }
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

// Streaming POST: write `nparts` body chunks (with ONE content-length = their
// total) then read the JSON response. This publishes an arbitrarily large body
// (an audio-clip's base64) WITHOUT a giant intermediate buffer — the small
// JSON prefix/suffix bracket the payload part, which stays where it already
// lives (the outbox item's heap string). No bearer (the cap is the auth).
static int http_post_parts(const char *url, const char *const parts[], const size_t part_lens[],
                           int nparts, char *out, size_t out_len)
{
    size_t total = 0;
    for (int i = 0; i < nparts; i++) {
        total += part_lens[i];
    }
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 30000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 1536,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    if (esp_http_client_open(client, (int)total) != ESP_OK) {
        esp_http_client_cleanup(client);
        return -1;
    }
    for (int i = 0; i < nparts; i++) {
        size_t off = 0;
        while (off < part_lens[i]) {
            int w = esp_http_client_write(client, parts[i] + off, (int)(part_lens[i] - off));
            if (w < 0) {
                esp_http_client_close(client);
                esp_http_client_cleanup(client);
                return -1;
            }
            off += (size_t)w;
        }
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

// ── session + caps ───────────────────────────────────────────────────────────
// Resolve J1 with the device's K10 agent-PoP. is_device:true suppresses the
// sandbox spawn (a channel-only device). Caches into s_session; returns success.
static bool resolve_session(void)
{
    const char *addr = device_identity_address();
    if (!addr[0]) {
        return false;
    }
    char pop[DEVICE_ID_SIG_LEN];
    if (device_identity_pop_sig(pop, sizeof(pop)) != ESP_OK) {
        return false;
    }
    char url[APP_URL_MAXLEN + 40];
    snprintf(url, sizeof(url), "%s%s", BROKER_URL, RESOLVE_PATH);
    snprintf(s_req, sizeof(s_req),
             "{\"device_pubkey\":\"%s\",\"pop_sig\":\"%s\",\"is_device\":true}", addr, pop);
    int status = http_post(url, NULL, s_req, s_resp, sizeof(s_resp));
    if (status != 200) {
        ESP_LOGW(TAG, "resolve -> %d", status);
        return false;
    }
    cJSON *root = cJSON_Parse(s_resp);
    if (!root) {
        return false;
    }
    const cJSON *jwt = cJSON_GetObjectItemCaseSensitive(root, "session_jwt");
    bool ok = cJSON_IsString(jwt) && jwt->valuestring[0];
    if (ok) {
        strncpy(s_session, jwt->valuestring, sizeof(s_session) - 1);
        s_session[sizeof(s_session) - 1] = '\0';
    }
    cJSON_Delete(root);
    return ok;
}

// Mint a channel cap. `service` = "channel-{pub,sub}:<id>", `op` =
// "channel_{publish,subscribe}". The #76 cap-PoP signs (operator, actor,
// service, op, data_class=channel, client_nonce, client_ts) — all echoed into
// the mint body so the broker + worker recompute the same digest. The response
// (a full CapToken object) is stored VERBATIM into `dst`.
static bool mint_cap(const char *path, const char *service, const char *op, char *dst,
                     size_t dst_len)
{
    char operator_omni[80], actor_omni[80], dkh[DEVICE_ID_HASH_LEN];
    if (device_identity_operator_omni(operator_omni, sizeof(operator_omni)) != ESP_OK ||
        device_identity_actor_omni(actor_omni, sizeof(actor_omni)) != ESP_OK ||
        device_identity_key_hash(dkh, sizeof(dkh)) != ESP_OK) {
        return false;
    }
    if (!operator_omni[0] || !actor_omni[0]) {
        ESP_LOGW(TAG, "cap mint: no bound omnis (unpaired?)");
        return false;
    }

    // client_nonce = lowercase hex of 16 random bytes; client_ts = unix seconds.
    // NOTE (ESP32): the broker rejects a client_ts >60 s future / >300 s stale,
    // so a real board must SNTP-sync its clock before minting (the sim has the
    // host's real time). Boot-relative seconds would be rejected as stale.
    uint8_t nb[16];
    esp_fill_random(nb, sizeof(nb));
    char nonce[33];
    for (int i = 0; i < 16; i++) {
        snprintf(nonce + i * 2, 3, "%02x", nb[i]);
    }
    uint64_t ts = (uint64_t)time(NULL);

    char sig[DEVICE_ID_SIG_LEN];
    if (device_identity_cap_pop_sig(operator_omni, actor_omni, service, op, "channel", nonce, ts,
                                    sig, sizeof(sig)) != ESP_OK) {
        ESP_LOGW(TAG, "cap-PoP sign failed");
        return false;
    }

    char url[APP_URL_MAXLEN + 40];
    snprintf(url, sizeof(url), "%s%s", BROKER_URL, path);
    snprintf(s_req, sizeof(s_req),
             "{\"operator_omni\":\"%s\",\"actor_omni\":\"%s\",\"service\":\"%s\","
             "\"device_key_hash\":\"%s\",\"ttl_seconds\":%d,\"client_sig\":\"%s\","
             "\"client_nonce\":\"%s\",\"client_ts\":%llu}",
             operator_omni, actor_omni, service, dkh, CAP_TTL_SECS, sig, nonce,
             (unsigned long long)ts);
    int status = http_post(url, s_session, s_req, dst, dst_len);
    if (status == 401) {
        s_session[0] = '\0'; // stale JWT → re-resolve next round
        ESP_LOGW(TAG, "cap mint %s -> 401 (session expired)", service);
        return false;
    }
    if (status != 200) {
        ESP_LOGW(TAG, "cap mint %s -> %d", service, status);
        return false;
    }
    // Sanity: the response must look like a CapToken (has "broker_sig"). Stored
    // verbatim in `dst` already; we only validate, never reformat.
    if (!strstr(dst, "broker_sig")) {
        ESP_LOGW(TAG, "cap mint %s: response is not a CapToken", service);
        dst[0] = '\0';
        return false;
    }
    return true;
}

// Channel id: the configured opchat-<label>. Empty = the device is not
// channel-configured (falls back to the direct bridge).
static const char *channel_id(void)
{
    return CHAT_CHANNEL_ID;
}

bool channel_client_ready(void)
{
    return channel_id()[0] && device_identity_paired(NULL, 0);
}

// Ensure the pub (or sub) cap is present, minting on demand. Re-mints whenever
// the slot is empty (first use, expiry-driven clear, or a 401 reset).
static bool ensure_cap(bool publish)
{
    char *slot = publish ? s_pub_cap : s_sub_cap;
    if (slot[0]) {
        return true;
    }
    if (!s_session[0] && !resolve_session()) {
        return false;
    }
    char service[80];
    snprintf(service, sizeof(service), "channel-%s:%s", publish ? "pub" : "sub", channel_id());
    return mint_cap(publish ? CAP_PUB_PATH : CAP_SUB_PATH, service,
                    publish ? "channel_publish" : "channel_subscribe", slot,
                    publish ? sizeof(s_pub_cap) : sizeof(s_sub_cap));
}

// ── publish ──────────────────────────────────────────────────────────────────
// Publish ONE queued turn. Runs ONLY on the channel task, so it owns s_resp +
// the pub cap exclusively (no cross-thread race). The body is STREAMED as three
// parts — the JSON prefix (splicing the cap VERBATIM), the base64 payload
// (which stays in the outbox item's heap string), and the suffix — so an
// audio-clip of any size publishes without a giant intermediate buffer.
// Direction "in" = a turn TO the agent.
static esp_err_t publish_now(const outbox_item_t *item)
{
    if (!ensure_cap(true)) {
        return ESP_FAIL;
    }
    char audio[128] = "";
    if (item->voice[0] || item->speech_rate != INT32_MIN) {
        char parts[96] = "";
        size_t n = 0;
        if (item->voice[0]) {
            n += (size_t)snprintf(parts + n, sizeof(parts) - n, "\"voice\":\"%s\"", item->voice);
        }
        if (item->speech_rate != INT32_MIN) {
            n += (size_t)snprintf(parts + n, sizeof(parts) - n, "%s\"speech_rate\":%d",
                                  n ? "," : "", item->speech_rate);
        }
        snprintf(audio, sizeof(audio), ",\"audio\":{%s}", parts);
    }
    // Prefix carries the ~KB cap verbatim, so it is heap-sized to fit.
    char *prefix = malloc(strlen(s_pub_cap) + 128);
    if (!prefix) {
        return ESP_ERR_NO_MEM;
    }
    int plen =
        sprintf(prefix, "{\"cap\":%s,\"kind\":\"%s\",\"direction\":\"in\",\"body_b64\":\"",
                s_pub_cap, item->kind);
    char suffix[160];
    int slen = snprintf(suffix, sizeof(suffix), "\"%s}", audio);

    const char *parts[3] = {prefix, item->body_b64, suffix};
    const size_t lens[3] = {(size_t)plen, strlen(item->body_b64), (size_t)slen};
    char url[APP_URL_MAXLEN + 40];
    snprintf(url, sizeof(url), "%s%s", CHANNEL_WORKER_URL, PUBLISH_PATH);
    int status = http_post_parts(url, parts, lens, 3, s_resp, sizeof(s_resp));
    free(prefix);
    if (status == 401 || status == 403) {
        s_pub_cap[0] = '\0'; // cap rejected/expired → re-mint next time
    }
    if (status < 200 || status >= 300) {
        ESP_LOGW(TAG, "publish -> %d", status);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t channel_client_publish_turn(const char *kind, const char *body_b64, const char *voice,
                                      int speech_rate)
{
    if (!channel_client_ready() || !s_outbox) {
        return ESP_ERR_INVALID_STATE;
    }
    // Enqueue (non-blocking) — the channel task owns all HTTP + buffers, so the
    // caller (e.g. the LVGL TALK handler) never blocks on the publish.
    outbox_item_t item = {.speech_rate = speech_rate};
    snprintf(item.kind, sizeof(item.kind), "%s", kind);
    if (voice && voice[0]) {
        snprintf(item.voice, sizeof(item.voice), "%s", voice);
    }
    item.body_b64 = strdup(body_b64);
    if (!item.body_b64) {
        return ESP_ERR_NO_MEM;
    }
    if (xQueueSend(s_outbox, &item, 0) != pdTRUE) {
        free(item.body_b64);
        ESP_LOGW(TAG, "outbox full — turn dropped");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t channel_client_send_text(const char *text)
{
    if (!text) {
        return ESP_ERR_INVALID_ARG;
    }
    char b64[1024];
    if (b64_encode((const uint8_t *)text, strlen(text), b64, sizeof(b64)) < 0) {
        return ESP_ERR_NO_MEM;
    }
    // Reflect the user's turn locally right away (the poll loop surfaces only the
    // agent's replies, never the device's own echo).
    app_state_append_message(ROLE_USER, text);
    return channel_client_publish_turn("text", b64, NULL, INT32_MIN);
}

esp_err_t channel_client_request_tasks(void)
{
    // command:jobs — the sandbox answers with a `doc` listing (rendered in the
    // conversation via deliver_event). No local echo; the reply is the result.
    char b64[12];
    if (b64_encode((const uint8_t *)"jobs", 4, b64, sizeof(b64)) < 0) {
        return ESP_ERR_NO_MEM;
    }
    return channel_client_publish_turn("command", b64, NULL, INT32_MIN);
}

esp_err_t channel_client_send_audio(const uint8_t *wav, size_t wav_len, const char *voice,
                                    int speech_rate)
{
    if (!wav || !wav_len) {
        return ESP_ERR_INVALID_ARG;
    }
    // Base64 the clip on the heap (a few seconds of 16 kHz mono is ~100s of KB).
    size_t cap = 4 * ((wav_len + 2) / 3) + 1;
    char *b64 = malloc(cap);
    if (!b64) {
        return ESP_ERR_NO_MEM;
    }
    int n = b64_encode(wav, wav_len, b64, cap);
    if (n < 0) {
        free(b64);
        return ESP_ERR_NO_MEM;
    }
    app_state_append_message(ROLE_USER, "(voice message)");
    esp_err_t r = channel_client_publish_turn("audio-clip", b64, voice, speech_rate);
    free(b64); // publish_turn copied it into the outbox item
    return r;
}

// ── subscribe poll loop ──────────────────────────────────────────────────────
// Deliver one inbound reply event to app_state. Only direction:"out" events are
// surfaced (the agent's replies); the device's own "in" turns are skipped.
static void deliver_event(const cJSON *ev)
{
    const cJSON *dir = cJSON_GetObjectItemCaseSensitive(ev, "direction");
    if (!cJSON_IsString(dir) || strcmp(dir->valuestring, "out") != 0) {
        return;
    }
    const cJSON *kind = cJSON_GetObjectItemCaseSensitive(ev, "kind");
    const cJSON *body = cJSON_GetObjectItemCaseSensitive(ev, "body");
    if (!cJSON_IsString(kind) || !cJSON_IsString(body)) {
        return;
    }
    if (strcmp(kind->valuestring, "text") == 0 || strcmp(kind->valuestring, "doc") == 0) {
        // Decode the base64 plaintext into a bounded reply buffer + render it.
        static char text[1024];
        int dl = b64_decode(body->valuestring, (uint8_t *)text, sizeof(text) - 1);
        if (dl >= 0) {
            text[dl] = '\0';
            app_state_append_message(ROLE_AGENT, text);
        }
    } else if (strcmp(kind->valuestring, "audio-clip") == 0) {
        // #524 — the spoken reply: decode the base64 WAV (heap; a clip is larger
        // than the text buffer) and play it through the speaker. The matching
        // text reply arrives as its own correlated `text` event (rendered above).
        size_t b64len = strlen(body->valuestring);
        uint8_t *wav = malloc(b64len); // decoded is smaller than the base64
        if (wav) {
            int dl = b64_decode(body->valuestring, wav, b64len);
            if (dl > 0) {
                audio_play_wav(wav, (size_t)dl);
            }
            free(wav);
        }
    } else {
        ESP_LOGI(TAG, "reply kind '%s' (%d b64 chars) — playback in a later slice",
                 kind->valuestring, (int)strlen(body->valuestring));
    }
}

static void channel_task(void *arg)
{
    (void)arg;
    uint32_t backoff = 2000;
    // Boot fast-forward: adopt the current cursor without replaying history, so
    // a device restart doesn't re-render the whole transcript.
    bool fast_forwarded = false;

    // Wait for pairing to BIND before minting — the task is spawned once at boot
    // (the channel id is a compile/config constant), but the runtime grant only
    // exists after the master claims the device.
    while (!channel_client_ready()) {
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
    ESP_LOGI(TAG, "channel client: conversing on '%s' via %s", channel_id(), CHANNEL_WORKER_URL);

    for (;;) {
        // Drain queued outgoing turns first (the caller enqueued them off the
        // LVGL thread). Replies still arrive via the poll below — the worker's
        // NRT wakeup completes a held poll the instant the delegate publishes.
        outbox_item_t out;
        while (xQueueReceive(s_outbox, &out, 0) == pdTRUE) {
            publish_now(&out);
            free(out.body_b64);
        }
        if (!ensure_cap(false)) {
            vTaskDelay(pdMS_TO_TICKS(backoff));
            if (backoff < 60000) {
                backoff *= 2;
            }
            continue;
        }
        // Short poll wait so a turn enqueued while we're parked here is picked up
        // within ~POLL_WAIT_SEC; a reply arrives sooner (NRT wakeup).
        snprintf(s_req, sizeof(s_req), "{\"cap\":%s,\"after\":\"%s\",\"wait_seconds\":%d}", s_sub_cap,
                 s_cursor, fast_forwarded ? POLL_WAIT_SEC : 0);
        char url[APP_URL_MAXLEN + 40];
        snprintf(url, sizeof(url), "%s%s", CHANNEL_WORKER_URL, POLL_PATH);
        int status = http_post(url, NULL, s_req, s_resp, sizeof(s_resp));
        if (status == 401 || status == 403) {
            s_sub_cap[0] = '\0'; // re-mint (and maybe re-resolve) next round
            vTaskDelay(pdMS_TO_TICKS(backoff));
            continue;
        }
        if (status < 200 || status >= 300) {
            vTaskDelay(pdMS_TO_TICKS(backoff));
            if (backoff < 60000) {
                backoff *= 2;
            }
            continue;
        }
        backoff = 2000;
        cJSON *root = cJSON_Parse(s_resp);
        if (!root) {
            continue;
        }
        const cJSON *cursor = cJSON_GetObjectItemCaseSensitive(root, "cursor");
        const cJSON *events = cJSON_GetObjectItemCaseSensitive(root, "events");
        if (cJSON_IsString(cursor) && cursor->valuestring[0]) {
            strncpy(s_cursor, cursor->valuestring, sizeof(s_cursor) - 1);
            s_cursor[sizeof(s_cursor) - 1] = '\0';
        }
        if (!fast_forwarded) {
            fast_forwarded = true; // first poll only advances the cursor
        } else if (cJSON_IsArray(events)) {
            const cJSON *ev;
            cJSON_ArrayForEach(ev, events)
            {
                deliver_event(ev);
            }
        }
        cJSON_Delete(root);
    }
}

void channel_client_start(void)
{
    // Spawn ONCE when the device is channel-configured (CHAT_CHANNEL_ID set — a
    // compile/config constant, so no NVS at boot); the task itself waits for
    // pairing to bind. An unconfigured demo device never spawns the loop and
    // stays on the direct bridge.
    if (s_started || !channel_id()[0]) {
        return;
    }
    s_outbox = xQueueCreate(8, sizeof(outbox_item_t));
    if (!s_outbox) {
        ESP_LOGE(TAG, "failed to create the outbox queue");
        return;
    }
    s_started = true;
    // 10 KB: the HTTPS/mbedTLS handshake is the stack hog (same budget class as
    // the pairing task); the K10 crypto runs on device_identity's own worker.
    if (xTaskCreate(channel_task, "channel", 10240, NULL, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "failed to spawn channel task");
        s_started = false;
    }
}
