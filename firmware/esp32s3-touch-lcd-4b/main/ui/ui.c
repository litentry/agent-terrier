#include "ui.h"

#include <stdint.h>

#include "bsp/esp-bsp.h"
#include "esp_log.h"

static const char *TAG = "ui";

typedef struct {
    lv_obj_t *wifi;
    lv_obj_t *agent;
    lv_obj_t *paired;
    lv_obj_t *speak;
    lv_obj_t *batt;
} status_bar_t;

static ui_screen_view_t s_views[UI_SCREEN_COUNT];
static ui_screen_t s_active = UI_SCREEN_HOME;
static uint32_t s_last_rev;
static bool s_force = true;

static void refresh_timer_cb(lv_timer_t *timer)
{
    (void)timer;
    uint32_t rev = app_state_revision();
    if (!s_force && rev == s_last_rev) {
        return;
    }
    s_force = false;
    s_last_rev = rev;
    if (s_views[s_active].refresh) {
        s_views[s_active].refresh();
    }
}

void ui_init(void)
{
    bsp_display_lock(0);
    s_views[UI_SCREEN_HOME] = ui_build_home();
    s_views[UI_SCREEN_PAIRING] = ui_build_pairing();
    s_views[UI_SCREEN_SETTINGS] = ui_build_settings();
    s_views[UI_SCREEN_CONNECTION] = ui_build_connection();
    s_views[UI_SCREEN_VOICES] = ui_build_voices();
    lv_screen_load(s_views[UI_SCREEN_HOME].root);
    s_active = UI_SCREEN_HOME;
    s_force = true;
    lv_timer_create(refresh_timer_cb, 200, NULL);
    bsp_display_unlock();
    ESP_LOGI(TAG, "ui ready (%d screens)", UI_SCREEN_COUNT);
}

void ui_show(ui_screen_t screen)
{
    if (screen >= UI_SCREEN_COUNT) {
        return;
    }
    bsp_display_lock(0); // recursive lock — safe to call from an event cb already holding it
    s_active = screen;
    s_force = true;
    lv_screen_load(s_views[screen].root);
    bsp_display_unlock();
}

lv_obj_t *ui_make_screen(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr, UI_COL_BG, 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
    lv_obj_set_style_text_color(scr, UI_COL_TEXT, 0);
    lv_obj_set_style_pad_all(scr, 0, 0);
    lv_obj_set_style_border_width(scr, 0, 0);
    lv_obj_set_flex_flow(scr, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(scr, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_remove_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
    return scr;
}

lv_obj_t *ui_make_status_bar(lv_obj_t *parent)
{
    lv_obj_t *bar = lv_obj_create(parent);
    lv_obj_set_size(bar, lv_pct(100), 40);
    lv_obj_set_style_bg_color(bar, UI_COL_PANEL, 0);
    lv_obj_set_style_bg_opa(bar, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(bar, 0, 0);
    lv_obj_set_style_radius(bar, 0, 0);
    lv_obj_set_style_pad_hor(bar, 14, 0);
    lv_obj_set_style_pad_ver(bar, 4, 0);
    lv_obj_remove_flag(bar, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bar, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    status_bar_t *sb = lv_malloc(sizeof(status_bar_t));
    sb->wifi = lv_label_create(bar);
    sb->agent = lv_label_create(bar);
    sb->paired = lv_label_create(bar);
    sb->speak = lv_label_create(bar);
    sb->batt = lv_label_create(bar);
    lv_obj_set_user_data(bar, sb);
    ui_status_bar_refresh(bar);
    return bar;
}

void ui_status_bar_refresh(lv_obj_t *bar)
{
    status_bar_t *sb = lv_obj_get_user_data(bar);
    if (!sb) {
        return;
    }
    conn_state_t conn = app_state_get_conn();
    bool wifi_ok = (conn == CONN_WIFI_OK || conn == CONN_AGENT_OK);
    bool agent_ok = (conn == CONN_AGENT_OK);
    pair_state_t pair = app_state_get_pairing(NULL, 0, NULL, 0, NULL, 0);
    bool speak = app_state_get_speak();

    lv_label_set_text(sb->wifi, LV_SYMBOL_WIFI);
    lv_obj_set_style_text_color(sb->wifi,
                                wifi_ok ? UI_COL_OK : (conn == CONN_ERROR ? UI_COL_ERR : UI_COL_MUTED), 0);

    lv_label_set_text(sb->agent, "AGENT");
    lv_obj_set_style_text_color(sb->agent, agent_ok ? UI_COL_OK : UI_COL_MUTED, 0);

    lv_label_set_text(sb->paired, pair == PAIR_BOUND ? LV_SYMBOL_OK " paired" : "unpaired");
    lv_obj_set_style_text_color(sb->paired, pair == PAIR_BOUND ? UI_COL_OK : UI_COL_MUTED, 0);

    lv_label_set_text(sb->speak, speak ? LV_SYMBOL_AUDIO : LV_SYMBOL_MUTE);
    lv_obj_set_style_text_color(sb->speak, speak ? UI_COL_TEXT : UI_COL_MUTED, 0);

    lv_label_set_text(sb->batt, LV_SYMBOL_BATTERY_FULL); // TODO P4: read AXP2101 state-of-charge
    lv_obj_set_style_text_color(sb->batt, UI_COL_MUTED, 0);
}

lv_obj_t *ui_make_title(lv_obj_t *parent, const char *text)
{
    lv_obj_t *label = lv_label_create(parent);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(label, UI_COL_TEXT, 0);
    lv_obj_set_style_pad_ver(label, 6, 0);
    return label;
}

static void nav_event_cb(lv_event_t *e)
{
    ui_screen_t target = (ui_screen_t)(intptr_t)lv_event_get_user_data(e);
    ui_show(target);
}

lv_obj_t *ui_add_nav_button(lv_obj_t *parent, const char *text, ui_screen_t target)
{
    lv_obj_t *btn = lv_button_create(parent);
    lv_obj_set_style_bg_color(btn, UI_COL_PANEL, 0);
    lv_obj_set_style_radius(btn, 8, 0);
    lv_obj_set_style_pad_hor(btn, 16, 0);
    lv_obj_set_style_pad_ver(btn, 10, 0);
    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, UI_COL_TEXT, 0);
    lv_obj_center(label);
    lv_obj_add_event_cb(btn, nav_event_cb, LV_EVENT_CLICKED, (void *)(intptr_t)target);
    return btn;
}
