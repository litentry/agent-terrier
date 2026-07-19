// Browser/desktop simulator entry point for the AgentKeys device UI.
//
// It compiles the REAL firmware screens (../main/ui/*.c) + the REAL shared state
// (../main/app_state.c) against LVGL's SDL backend, so the mirror can never drift
// from the device — it IS the device's UI code, with only the display/touch driver
// and the net/ layer swapped (see shims/ + mock_net.c). On the device, app_main.c
// is the entry point; here, sim_main.c is.
#include "lvgl.h"
#include "ui.h"
#include "app_state.h"
#ifdef AGENTKEYS_REAL_NET
// #517 real-device mode: the firmware's OWN net/ layer, no fixtures.
#include "agent_client.h"
#include "device_identity.h"
#include "esp_log.h"
#include "nvs.h"
#include "pairing.h"
#include "wifi.h"
#else
#include "mock_net.h"
#endif

#include <SDL2/SDL.h>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

// LVGL v9 tick source (replaces the ESP timer): SDL's millisecond clock.
static uint32_t tick_cb(void) {
    return SDL_GetTicks();
}

static void main_loop(void) {
    lv_timer_handler();
}

int main(void) {
    lv_init();
    lv_tick_set_cb(tick_cb);

    // 480x480 SDL window + mouse-as-touch — the same resolution as the panel.
    lv_sdl_window_create(480, 480);
    lv_sdl_mouse_create();

    app_state_init();
#ifdef AGENTKEYS_REAL_NET
    // Boot the REAL device: load-or-generate the K10 (persisted in ~/.agentkeys/
    // mock-device), report the host's IP, point the agent client at the broker,
    // then open a genuine §10.2 pairing request. Everything the operator sees —
    // the QR, the device-key hash, the reply text — comes off the wire.
    nvs_flash_init();
    if (device_identity_init() != ESP_OK) {
        ESP_LOGE("mirror", "device identity init failed — no K10, cannot pair");
    }
    wifi_start(NULL, NULL);
    const char *agent = getenv("AGENTKEYS_AGENT_URL");
    const char *bearer = getenv("AGENTKEYS_AGENT_BEARER");
    if (agent && *agent) { agent_client_init(agent, bearer ? bearer : ""); }
    char dkh[80] = {0};
    if (device_identity_key_hash(dkh, sizeof(dkh)) == ESP_OK) {
        ESP_LOGI("mirror", "device_key_hash %s  (identity file: %s)", dkh, nvs_sim_path("agentkeys"));
    }
    // Already claimed by a master on a previous run? Then this boot is a
    // reconnect, not a fresh pairing — same branch the firmware takes.
    char master[80] = {0};
    if (device_identity_paired(master, sizeof(master))) {
        ESP_LOGI("mirror", "already paired to master %s", master);
    } else {
        pairing_start();
    }
#else
    mock_net_seed();   // populate a sample conversation + pairing QR + connected status
#endif
    ui_init();         // builds all 5 real screens + starts the refresh timer
#ifdef AGENTKEYS_REAL_NET
    // Boot marker: proves the main thread got past the (blocking) identity +
    // pairing bring-up and into the LVGL loop. If you see the pairing logs but
    // NOT this line, the hang is in net/ bring-up, not the renderer.
    ESP_LOGI("mirror", "UI ready — entering LVGL loop");
#endif

#ifdef __EMSCRIPTEN__
    emscripten_set_main_loop(main_loop, 0, 1);
#else
    while (1) {
        lv_timer_handler();
        SDL_Delay(5);
    }
#endif
    return 0;
}
