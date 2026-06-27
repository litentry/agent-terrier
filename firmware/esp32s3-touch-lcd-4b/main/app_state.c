#include "app_state.h"
#include "app_config.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

typedef struct {
    msg_role_t role;
    char text[APP_MSG_MAXLEN];
} message_t;

static struct {
    conn_state_t conn;
    char ip[APP_IP_MAXLEN];

    pair_state_t pairing;
    char deep_link[APP_DEEPLINK_MAXLEN];
    char code[APP_CODE_MAXLEN];
    char device_key_hash[APP_HASH_MAXLEN];

    bool speak;
    int speed;
    char voice[APP_VOICE_MAXLEN];

    message_t messages[APP_MAX_MESSAGES];
    size_t message_count;

    uint32_t revision;
} s;

static SemaphoreHandle_t s_lock;

#define LOCK()   xSemaphoreTakeRecursive(s_lock, portMAX_DELAY)
#define UNLOCK() xSemaphoreGiveRecursive(s_lock)

static void copy_str(char *dst, size_t dst_len, const char *src)
{
    if (dst_len == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
}

void app_state_init(void)
{
    s_lock = xSemaphoreCreateRecursiveMutex();
    memset(&s, 0, sizeof(s));
    s.conn = CONN_BOOT;
    s.pairing = PAIR_UNKNOWN;
    s.speak = DEFAULT_SPEAK_ON;
    s.speed = DEFAULT_SPEECH_SPEED;
    copy_str(s.voice, sizeof(s.voice), DEFAULT_VOICE_ID);
}

void app_state_set_conn(conn_state_t state)
{
    LOCK();
    s.conn = state;
    s.revision++;
    UNLOCK();
}

conn_state_t app_state_get_conn(void)
{
    LOCK();
    conn_state_t v = s.conn;
    UNLOCK();
    return v;
}

void app_state_set_ip(const char *ip)
{
    LOCK();
    copy_str(s.ip, sizeof(s.ip), ip);
    s.revision++;
    UNLOCK();
}

void app_state_get_ip(char *out, size_t out_len)
{
    LOCK();
    copy_str(out, out_len, s.ip);
    UNLOCK();
}

void app_state_set_pairing(pair_state_t state, const char *deep_link, const char *code,
                           const char *device_key_hash)
{
    LOCK();
    s.pairing = state;
    if (deep_link) {
        copy_str(s.deep_link, sizeof(s.deep_link), deep_link);
    }
    if (code) {
        copy_str(s.code, sizeof(s.code), code);
    }
    if (device_key_hash) {
        copy_str(s.device_key_hash, sizeof(s.device_key_hash), device_key_hash);
    }
    s.revision++;
    UNLOCK();
}

pair_state_t app_state_get_pairing(char *deep_link_out, size_t dl_len, char *code_out,
                                   size_t code_len, char *hash_out, size_t hash_len)
{
    LOCK();
    pair_state_t v = s.pairing;
    copy_str(deep_link_out, dl_len, s.deep_link);
    copy_str(code_out, code_len, s.code);
    copy_str(hash_out, hash_len, s.device_key_hash);
    UNLOCK();
    return v;
}

void app_state_set_speak(bool on)
{
    LOCK();
    s.speak = on;
    s.revision++;
    UNLOCK();
}

bool app_state_get_speak(void)
{
    LOCK();
    bool v = s.speak;
    UNLOCK();
    return v;
}

void app_state_set_speed(int percent)
{
    if (percent < 50) {
        percent = 50;
    } else if (percent > 200) {
        percent = 200;
    }
    LOCK();
    s.speed = percent;
    s.revision++;
    UNLOCK();
}

int app_state_get_speed(void)
{
    LOCK();
    int v = s.speed;
    UNLOCK();
    return v;
}

void app_state_set_voice(const char *voice_id)
{
    LOCK();
    copy_str(s.voice, sizeof(s.voice), voice_id);
    s.revision++;
    UNLOCK();
}

void app_state_get_voice(char *out, size_t out_len)
{
    LOCK();
    copy_str(out, out_len, s.voice);
    UNLOCK();
}

void app_state_append_message(msg_role_t role, const char *text)
{
    LOCK();
    if (s.message_count == APP_MAX_MESSAGES) {
        memmove(&s.messages[0], &s.messages[1], sizeof(message_t) * (APP_MAX_MESSAGES - 1));
        s.message_count--;
    }
    s.messages[s.message_count].role = role;
    copy_str(s.messages[s.message_count].text, APP_MSG_MAXLEN, text);
    s.message_count++;
    s.revision++;
    UNLOCK();
}

void app_state_append_to_last_agent(const char *chunk)
{
    if (chunk == NULL || chunk[0] == '\0') {
        return;
    }
    LOCK();
    if (s.message_count > 0 && s.messages[s.message_count - 1].role == ROLE_AGENT) {
        char *dst = s.messages[s.message_count - 1].text;
        size_t used = strlen(dst);
        if (used < APP_MSG_MAXLEN - 1) {
            strncat(dst, chunk, APP_MSG_MAXLEN - 1 - used);
        }
        s.revision++;
    }
    UNLOCK();
}

size_t app_state_message_count(void)
{
    LOCK();
    size_t v = s.message_count;
    UNLOCK();
    return v;
}

bool app_state_get_message(size_t index, msg_role_t *role_out, char *text_out, size_t text_len)
{
    bool ok = false;
    LOCK();
    if (index < s.message_count) {
        if (role_out) {
            *role_out = s.messages[index].role;
        }
        copy_str(text_out, text_len, s.messages[index].text);
        ok = true;
    }
    UNLOCK();
    return ok;
}

uint32_t app_state_revision(void)
{
    LOCK();
    uint32_t v = s.revision;
    UNLOCK();
    return v;
}
