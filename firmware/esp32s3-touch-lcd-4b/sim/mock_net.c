// The simulator replaces the device's net/ layer (agent_client.c / pairing.c / wifi.c)
// with these stubs, so the SAME ui/*.c screens compile and render against sample data.
// Live agent/voice/pairing BEHAVIOR is exercised by the volcano-probe TUI, not here —
// this mirror is for the pixels, layout, and touch UX of the real LVGL screens.
#include "app_state.h"
#include "agent_client.h"
#include "channel_client.h"
#include "pairing.h"
#include "wifi.h"
#include "mock_net.h"

void agent_client_init(const char *base_url, const char *bearer) {
    (void)base_url;
    (void)bearer;
}

void agent_client_send(const char *text) {
    // Mirror a real agent turn: a ROLE_USER bubble, then a streamed ROLE_AGENT reply.
    app_state_append_message(ROLE_USER, text);
    app_state_append_message(ROLE_AGENT, "");
    app_state_append_to_last_agent("This is the on-device UI mirror. ");
    app_state_append_to_last_agent("Live answers come from your paired agent.");
}

bool agent_client_healthz(void) {
    return true;
}

void pairing_start(void) {
    // Render a realistic pairing QR (the canonical deep-link) + short code + #224 device-key hash.
    app_state_set_pairing(PAIR_UNBOUND,
                          "agentkeys-pair://claim?code=SIM-7K2Q&broker=https://broker.example",
                          "SIM-7K2Q",
                          "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
}

void wifi_start(const char *ssid, const char *password) {
    (void)ssid;
    (void)password;
    app_state_set_ip("192.168.0.194");
    app_state_set_conn(CONN_AGENT_OK);
}

// #523 — channel-client stubs for the browser/mock build (the real
// net/channel_client.c is desktop-only: no sockets/pthreads/libcurl in WASM).
// ready() is false, so the shared ui/ screens route TALK down the mocked
// agent_client bridge path — pixels + UX still exercised, no real channel.
bool channel_client_ready(void) {
    return false;
}

esp_err_t channel_client_send_text(const char *text) {
    agent_client_send(text);
    return ESP_OK;
}

void mock_net_seed(void) {
    // Boot into a connected, mid-conversation state so every screen is populated.
    app_state_set_conn(CONN_AGENT_OK);
    app_state_set_ip("192.168.0.194");
    app_state_append_message(ROLE_AGENT, "Hi! Hold TALK to speak with me.");
    app_state_append_message(ROLE_USER, "What's the weather?");
    app_state_append_message(ROLE_AGENT, "It's sunny and 24 degrees right now.");
}
