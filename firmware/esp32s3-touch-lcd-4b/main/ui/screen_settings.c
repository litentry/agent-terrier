// Settings — speak on/off, speech speed, and entry points to the Voice + Connection screens.
// Mirrors the TUI `t` (speak), speed control, and `v` (voices).
#include "ui.h"

static lv_obj_t *s_bar;
static lv_obj_t *s_speed_value;

static lv_obj_t *make_panel(lv_obj_t *parent)
{
    lv_obj_t *panel = lv_obj_create(parent);
    lv_obj_set_width(panel, lv_pct(92));
    lv_obj_set_height(panel, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(panel, UI_COL_PANEL, 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(panel, 10, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_pad_all(panel, 12, 0);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    return panel;
}

static void speak_event_cb(lv_event_t *e)
{
    lv_obj_t *sw = lv_event_get_target(e);
    app_state_set_speak(lv_obj_has_state(sw, LV_STATE_CHECKED));
}

static void speed_event_cb(lv_event_t *e)
{
    lv_obj_t *slider = lv_event_get_target(e);
    int value = lv_slider_get_value(slider);
    app_state_set_speed(value);
    if (s_speed_value) {
        lv_label_set_text_fmt(s_speed_value, "%d%%", value);
    }
}

static void settings_refresh(void)
{
    ui_status_bar_refresh(s_bar);
}

ui_screen_view_t ui_build_settings(void)
{
    lv_obj_t *scr = ui_make_screen();
    s_bar = ui_make_status_bar(scr);

    lv_obj_t *content = lv_obj_create(scr);
    lv_obj_set_width(content, lv_pct(100));
    lv_obj_set_flex_grow(content, 1);
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_pad_all(content, 8, 0);
    lv_obj_set_style_pad_row(content, 10, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    ui_make_title(content, "Settings");

    lv_obj_t *speak_panel = make_panel(content);
    lv_obj_set_flex_flow(speak_panel, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(speak_panel, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_t *speak_label = lv_label_create(speak_panel);
    lv_label_set_text(speak_label, "Speak replies aloud");
    lv_obj_t *speak_sw = lv_switch_create(speak_panel);
    if (app_state_get_speak()) {
        lv_obj_add_state(speak_sw, LV_STATE_CHECKED);
    }
    lv_obj_add_event_cb(speak_sw, speak_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    lv_obj_t *speed_panel = make_panel(content);
    lv_obj_set_flex_flow(speed_panel, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(speed_panel, 8, 0);
    lv_obj_t *speed_header = lv_obj_create(speed_panel);
    lv_obj_set_width(speed_header, lv_pct(100));
    lv_obj_set_height(speed_header, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(speed_header, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(speed_header, 0, 0);
    lv_obj_set_style_pad_all(speed_header, 0, 0);
    lv_obj_remove_flag(speed_header, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(speed_header, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(speed_header, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_t *speed_label = lv_label_create(speed_header);
    lv_label_set_text(speed_label, "Speech speed");
    s_speed_value = lv_label_create(speed_header);
    lv_label_set_text_fmt(s_speed_value, "%d%%", app_state_get_speed());
    lv_obj_t *speed_slider = lv_slider_create(speed_panel);
    lv_obj_set_width(speed_slider, lv_pct(100));
    lv_slider_set_range(speed_slider, 50, 200);
    lv_slider_set_value(speed_slider, app_state_get_speed(), LV_ANIM_OFF);
    lv_obj_add_event_cb(speed_slider, speed_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    lv_obj_t *voice_btn = ui_add_nav_button(content, LV_SYMBOL_AUDIO "  Voice", UI_SCREEN_VOICES);
    lv_obj_set_width(voice_btn, lv_pct(92));
    lv_obj_t *conn_btn = ui_add_nav_button(content, LV_SYMBOL_WIFI "  Connection", UI_SCREEN_CONNECTION);
    lv_obj_set_width(conn_btn, lv_pct(92));

    lv_obj_t *footer = lv_obj_create(scr);
    lv_obj_set_size(footer, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(footer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(footer, 0, 0);
    lv_obj_set_style_pad_all(footer, 8, 0);
    lv_obj_remove_flag(footer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(footer, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(footer, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    ui_add_nav_button(footer, LV_SYMBOL_LEFT "  Back", UI_SCREEN_HOME);

    ui_screen_view_t view = { .root = scr, .refresh = settings_refresh };
    return view;
}
