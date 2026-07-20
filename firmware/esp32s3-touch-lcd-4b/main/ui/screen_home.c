// Home / Conversation — mirrors the probe TUI conversation pane + header + the
// click-to-toggle Listen button (#524).
#include "ui.h"
#include "agent_client.h"
#include "audio_io.h"
#include "channel_client.h"

#include <stdint.h>
#include <stdlib.h>

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

static bool s_listening;

// The device's current TTS reply preferences (settings screen), passed with a
// voice turn so the agent synthesizes the reply the way the user chose (#522).
static int reply_speech_rate(void)
{
    // 50..200 % of nominal maps linearly onto Doubao speech_rate [-50, 100].
    int rate = app_state_get_speed() - 100;
    if (rate < -50) {
        rate = -50;
    } else if (rate > 100) {
        rate = 100;
    }
    return rate;
}

// #524 — click-to-toggle Listen. Voice capture needs BOTH real audio AND the
// channel (ASR runs agent-side): first click starts listening, second click
// stops + sends the clip. Without audio (WASM/ESP32 stub) or a channel, one
// click sends the placeholder transcript so the path stays testable.
static void talk_event_cb(lv_event_t *e)
{
    if (lv_event_get_code(e) != LV_EVENT_CLICKED) {
        return;
    }
    lv_obj_t *btn = lv_event_get_target(e);
    lv_obj_t *label = lv_obj_get_child(btn, 0);

    if (audio_io_available() && channel_client_ready()) {
        if (!s_listening) {
            if (audio_capture_start() == ESP_OK) {
                s_listening = true;
                lv_label_set_text(label, LV_SYMBOL_AUDIO "  Listening… tap to send");
                return;
            }
        } else {
            s_listening = false;
            lv_label_set_text(label, LV_SYMBOL_AUDIO "  TALK");
            size_t len = 0;
            uint8_t *wav = audio_capture_stop(&len);
            if (wav && len) {
                char voice[40];
                app_state_get_voice(voice, sizeof(voice));
                channel_client_send_audio(wav, len, voice, reply_speech_rate());
            } else {
                ESP_LOGW(TAG, "no audio captured (silent mic / permission?)");
            }
            free(wav);
            return;
        }
    }

    // Fallback: a placeholder text turn (unpaired demo device or no audio).
    const char *msg = "Hello! Tell me something interesting in one sentence.";
    if (channel_client_ready()) {
        channel_client_send_text(msg);
    } else {
        agent_client_send(msg);
    }
}

// #525 — request the delegate's background-task list over the channel.
static void tasks_event_cb(lv_event_t *e)
{
    (void)e;
    if (channel_client_ready()) {
        channel_client_request_tasks();
    } else {
        app_state_append_message(ROLE_AGENT, "Tasks are available once paired to an agent.");
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
    lv_obj_add_event_cb(talk, talk_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *footer = lv_obj_create(scr);
    lv_obj_set_size(footer, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(footer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(footer, 0, 0);
    lv_obj_set_style_pad_all(footer, 8, 0);
    lv_obj_remove_flag(footer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(footer, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(footer, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    ui_add_nav_button(footer, "Pair", UI_SCREEN_PAIRING);
    // #525 — Tasks: ask the delegate for its background-task list over the
    // channel; the reply renders as a `doc` bubble in the conversation.
    lv_obj_t *tasks = lv_button_create(footer);
    lv_obj_set_style_bg_color(tasks, UI_COL_PANEL, 0);
    lv_label_set_text(lv_label_create(tasks), LV_SYMBOL_LIST "  Tasks");
    lv_obj_add_event_cb(tasks, tasks_event_cb, LV_EVENT_CLICKED, NULL);
    ui_add_nav_button(footer, LV_SYMBOL_SETTINGS "  Settings", UI_SCREEN_SETTINGS);

    ui_screen_view_t view = { .root = scr, .refresh = home_refresh };
    return view;
}
