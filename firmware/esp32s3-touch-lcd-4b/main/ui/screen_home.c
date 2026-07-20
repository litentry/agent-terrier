// Home / Conversation — mirrors the probe TUI conversation pane + header + hold-to-talk.
#include "ui.h"
#include "agent_client.h"
#include "channel_client.h"

#include "esp_log.h"

static const char *TAG = "ui.home";

static lv_obj_t *s_bar;
static lv_obj_t *s_convo;

static void add_bubble(lv_obj_t *parent, msg_role_t role, const char *text)
{
    lv_obj_t *row = lv_obj_create(parent);
    lv_obj_set_width(row, lv_pct(100));
    lv_obj_set_height(row, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_remove_flag(row, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, role == ROLE_USER ? LV_FLEX_ALIGN_END : LV_FLEX_ALIGN_START,
                          LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    lv_obj_t *bubble = lv_obj_create(row);
    lv_obj_set_width(bubble, lv_pct(86));
    lv_obj_set_height(bubble, LV_SIZE_CONTENT);
    lv_obj_set_style_radius(bubble, 12, 0);
    lv_obj_set_style_pad_all(bubble, 10, 0);
    lv_obj_set_style_border_width(bubble, 0, 0);
    lv_obj_remove_flag(bubble, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_bg_color(bubble, role == ROLE_USER ? UI_COL_ACCENT : UI_COL_PANEL, 0);

    lv_obj_t *label = lv_label_create(bubble);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(label, lv_pct(100));
    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, role == ROLE_USER ? lv_color_hex(0xFFFFFF) : UI_COL_TEXT, 0);
}

static void home_refresh(void)
{
    ui_status_bar_refresh(s_bar);
    lv_obj_clean(s_convo);
    size_t count = app_state_message_count();
    for (size_t i = 0; i < count; i++) {
        msg_role_t role;
        char text[APP_MSG_MAXLEN];
        if (app_state_get_message(i, &role, text, sizeof(text))) {
            add_bubble(s_convo, role, text);
        }
    }
    lv_obj_scroll_to_y(s_convo, LV_COORD_MAX, LV_ANIM_OFF);
}

static void talk_event_cb(lv_event_t *e)
{
    lv_event_code_t code = lv_event_get_code(e);
    lv_obj_t *btn = lv_event_get_target(e);
    lv_obj_t *label = lv_obj_get_child(btn, 0);
    if (code == LV_EVENT_PRESSED) {
        lv_label_set_text(label, LV_SYMBOL_AUDIO "  Listening...");
    } else if (code == LV_EVENT_RELEASED) {
        lv_label_set_text(label, LV_SYMBOL_AUDIO "  TALK");
        // #524 replaces this with: stop ES8311 mic capture -> an audio-clip turn.
        // Until then a placeholder transcript drives a real turn so the path is
        // testable. A PAIRED + channel-configured device converses over the
        // channel plane (#523); an unpaired demo device uses the direct bridge.
        const char *msg = "Hello! Tell me something interesting in one sentence.";
        if (channel_client_ready()) {
            ESP_LOGI(TAG, "talk released -> channel turn");
            channel_client_send_text(msg);
        } else {
            ESP_LOGI(TAG, "talk released -> bridge turn");
            agent_client_send(msg);
        }
    }
}

ui_screen_view_t ui_build_home(void)
{
    lv_obj_t *scr = ui_make_screen();
    s_bar = ui_make_status_bar(scr);

    s_convo = lv_obj_create(scr);
    lv_obj_set_width(s_convo, lv_pct(100));
    lv_obj_set_flex_grow(s_convo, 1);
    lv_obj_set_style_bg_opa(s_convo, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_convo, 0, 0);
    lv_obj_set_style_pad_all(s_convo, 10, 0);
    lv_obj_set_style_pad_row(s_convo, 8, 0);
    lv_obj_set_flex_flow(s_convo, LV_FLEX_FLOW_COLUMN);

    lv_obj_t *talk = lv_button_create(scr);
    lv_obj_set_size(talk, lv_pct(92), 76);
    lv_obj_set_style_bg_color(talk, UI_COL_ACCENT, 0);
    lv_obj_set_style_radius(talk, 16, 0);
    lv_obj_t *talk_label = lv_label_create(talk);
    lv_label_set_text(talk_label, LV_SYMBOL_AUDIO "  TALK");
    lv_obj_set_style_text_font(talk_label, &lv_font_montserrat_28, 0);
    lv_obj_set_style_text_color(talk_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(talk_label);
    lv_obj_add_event_cb(talk, talk_event_cb, LV_EVENT_ALL, NULL);

    lv_obj_t *footer = lv_obj_create(scr);
    lv_obj_set_size(footer, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(footer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(footer, 0, 0);
    lv_obj_set_style_pad_all(footer, 8, 0);
    lv_obj_remove_flag(footer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(footer, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(footer, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    ui_add_nav_button(footer, "Pair", UI_SCREEN_PAIRING);
    ui_add_nav_button(footer, LV_SYMBOL_SETTINGS "  Settings", UI_SCREEN_SETTINGS);

    ui_screen_view_t view = { .root = scr, .refresh = home_refresh };
    return view;
}
