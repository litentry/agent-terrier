// Voice picker — scrollable list, select sets the active voice. Mirrors the TUI Voices mode.
// #524: real Doubao bigmodel speaker ids (the fake `zh_female_warm`-style ids were placeholders
// that the gate TTS would reject). The FIRST entry is the verified default; the rest use the
// documented bigmodel naming. The authoritative, per-agent catalog is fetched live from the gate
// `GET /v1/audio/voices` in #527 — this static list is the pre-catalog fallback.
#include "ui.h"

#include <stdint.h>

static lv_obj_t *s_bar;

static const struct {
    const char *id;
    const char *label;
} VOICES[] = {
    { "zh_female_meilinvyou_moon_bigtts", "魅力女友 · Chinese female" },
    { "zh_male_yangguangqingnian_moon_bigtts", "阳光青年 · Chinese male" },
    { "zh_female_tianmeixiaoyuan_moon_bigtts", "甜美小源 · Chinese female" },
    { "zh_male_jingqiangkanye_moon_bigtts", "京腔侃爷 · Chinese male" },
    { "en_female_anna_mars_bigtts", "Anna · English female" },
};
#define VOICE_COUNT (sizeof(VOICES) / sizeof(VOICES[0]))

static void voice_event_cb(lv_event_t *e)
{
    intptr_t index = (intptr_t)lv_event_get_user_data(e);
    app_state_set_voice(VOICES[index].id);
    ui_show(UI_SCREEN_SETTINGS);
}

static void voices_refresh(void)
{
    ui_status_bar_refresh(s_bar);
}

ui_screen_view_t ui_build_voices(void)
{
    lv_obj_t *scr = ui_make_screen();
    s_bar = ui_make_status_bar(scr);
    ui_make_title(scr, "Voice");

    lv_obj_t *list = lv_list_create(scr);
    lv_obj_set_width(list, lv_pct(94));
    lv_obj_set_flex_grow(list, 1);
    lv_obj_set_style_bg_color(list, UI_COL_PANEL, 0);
    lv_obj_set_style_border_width(list, 0, 0);
    lv_obj_set_style_radius(list, 10, 0);
    for (size_t i = 0; i < VOICE_COUNT; i++) {
        lv_obj_t *btn = lv_list_add_button(list, LV_SYMBOL_AUDIO, VOICES[i].label);
        lv_obj_set_style_bg_color(btn, UI_COL_PANEL, 0);
        lv_obj_set_style_text_color(btn, UI_COL_TEXT, 0);
        lv_obj_add_event_cb(btn, voice_event_cb, LV_EVENT_CLICKED, (void *)(intptr_t)i);
    }

    lv_obj_t *footer = lv_obj_create(scr);
    lv_obj_set_size(footer, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(footer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(footer, 0, 0);
    lv_obj_set_style_pad_all(footer, 8, 0);
    lv_obj_remove_flag(footer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(footer, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(footer, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    ui_add_nav_button(footer, LV_SYMBOL_LEFT "  Back", UI_SCREEN_SETTINGS);

    ui_screen_view_t view = { .root = scr, .refresh = voices_refresh };
    return view;
}
