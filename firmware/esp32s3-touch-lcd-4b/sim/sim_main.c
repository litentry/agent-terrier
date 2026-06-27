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
#include "mock_net.h"

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
    mock_net_seed();   // populate a sample conversation + pairing QR + connected status
    ui_init();         // builds all 5 real screens + starts the refresh timer

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
