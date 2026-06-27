// LVGL UI for the 480x480 touch panel — mirrors the volcano-probe TUI screens.
// All builders run once under the LVGL lock (ui_init); the refresh timer redraws the active
// screen's dynamic content whenever app_state_revision() changes. Screens never block.
#pragma once

#include "lvgl.h"
#include "app_state.h"

typedef enum {
    UI_SCREEN_HOME = 0,
    UI_SCREEN_PAIRING,
    UI_SCREEN_SETTINGS,
    UI_SCREEN_CONNECTION,
    UI_SCREEN_VOICES,
    UI_SCREEN_COUNT,
} ui_screen_t;

// One screen: its root object + an optional refresh hook run by the UI timer while it's active.
typedef struct {
    lv_obj_t *root;
    void (*refresh)(void);
} ui_screen_view_t;

// Lifecycle. ui_init() builds every screen + starts the timer; call after bsp_display_start().
void ui_init(void);
// Switch screens. Safe to call from any task (takes the recursive LVGL lock) or from an event cb.
void ui_show(ui_screen_t screen);

// Per-screen builders (defined in screen_*.c, called once by ui_init under the lock).
ui_screen_view_t ui_build_home(void);
ui_screen_view_t ui_build_pairing(void);
ui_screen_view_t ui_build_settings(void);
ui_screen_view_t ui_build_connection(void);
ui_screen_view_t ui_build_voices(void);

// Shared theme + widget helpers (implemented in ui.c).
#define UI_COL_BG     lv_color_hex(0x10131A)
#define UI_COL_PANEL  lv_color_hex(0x1B2030)
#define UI_COL_ACCENT lv_color_hex(0x4F8CFF)
#define UI_COL_TEXT   lv_color_hex(0xE6E9EF)
#define UI_COL_MUTED  lv_color_hex(0x8A91A3)
#define UI_COL_OK     lv_color_hex(0x3FD07A)
#define UI_COL_WARN   lv_color_hex(0xFFB23F)
#define UI_COL_ERR    lv_color_hex(0xFF5D5D)

lv_obj_t *ui_make_screen(void);                              // full-size themed screen root
lv_obj_t *ui_make_status_bar(lv_obj_t *parent);             // top bar (wifi · agent · paired · speak · batt)
void ui_status_bar_refresh(lv_obj_t *bar);                  // pull live values from app_state
lv_obj_t *ui_make_title(lv_obj_t *parent, const char *text);
lv_obj_t *ui_add_nav_button(lv_obj_t *parent, const char *text, ui_screen_t target);
