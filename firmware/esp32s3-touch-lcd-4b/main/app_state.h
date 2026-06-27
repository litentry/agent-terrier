// Shared device state, owned here and mutated from any task (WiFi, agent client, UI).
// Every accessor is mutex-guarded; the UI rebuilds dynamic content when app_state_revision()
// changes, so network tasks never touch LVGL directly (LVGL is not thread-safe).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CONN_BOOT = 0,
    CONN_WIFI_CONNECTING,
    CONN_WIFI_OK,
    CONN_AGENT_OK,
    CONN_ERROR,
} conn_state_t;

typedef enum {
    PAIR_UNKNOWN = 0,
    PAIR_REQUESTING,
    PAIR_UNBOUND,
    PAIR_BOUND,
    PAIR_ERROR,
} pair_state_t;

typedef enum { ROLE_USER = 0, ROLE_AGENT } msg_role_t;

#define APP_MAX_MESSAGES    16
#define APP_MSG_MAXLEN      512
#define APP_DEEPLINK_MAXLEN 256
#define APP_CODE_MAXLEN     40
#define APP_HASH_MAXLEN     67 // "0x" + 64-hex keccak256 + NUL: hold the FULL device_key_hash so the operator verifies it exactly vs the master UI (never a silent prefix)
#define APP_IP_MAXLEN       16
#define APP_VOICE_MAXLEN    32

void app_state_init(void);

// Connection / agent reachability.
void app_state_set_conn(conn_state_t state);
conn_state_t app_state_get_conn(void);
void app_state_set_ip(const char *ip);
void app_state_get_ip(char *out, size_t out_len);

// Pairing (the deep-link rendered as the QR, the short code, the #224 device-key hash).
void app_state_set_pairing(pair_state_t state, const char *deep_link, const char *code,
                           const char *device_key_hash);
pair_state_t app_state_get_pairing(char *deep_link_out, size_t dl_len, char *code_out,
                                   size_t code_len, char *hash_out, size_t hash_len);

// Settings.
void app_state_set_speak(bool on);
bool app_state_get_speak(void);
void app_state_set_speed(int percent);
int app_state_get_speed(void);
void app_state_set_voice(const char *voice_id);
void app_state_get_voice(char *out, size_t out_len);

// Conversation. append_to_last_agent() streams reply tokens into the most recent agent bubble.
void app_state_append_message(msg_role_t role, const char *text);
void app_state_append_to_last_agent(const char *chunk);
size_t app_state_message_count(void);
bool app_state_get_message(size_t index, msg_role_t *role_out, char *text_out, size_t text_len);

// Monotonic counter bumped on every mutation; the UI refresh timer diffs against it.
uint32_t app_state_revision(void);
