// Pairing — the real agentkeys-pair://claim deep-link rendered as a QR (LVGL lv_qrcode), plus
// the short pairing code + #224 device-key hash, flipping unbound -> bound. Mirrors the TUI `p`.
#include "ui.h"
#include "pairing.h"

#include <string.h>

static lv_obj_t *s_bar;
static lv_obj_t *s_qr;
static lv_obj_t *s_code;
static lv_obj_t *s_hash;
static lv_obj_t *s_status;
static char s_last_dl[APP_DEEPLINK_MAXLEN];

static void pairing_refresh(void)
{
    ui_status_bar_refresh(s_bar);

    char deep_link[APP_DEEPLINK_MAXLEN];
    char code[APP_CODE_MAXLEN];
    char hash[APP_HASH_MAXLEN];
    pair_state_t state = app_state_get_pairing(deep_link, sizeof(deep_link), code, sizeof(code),
                                               hash, sizeof(hash));

    if (strcmp(deep_link, s_last_dl) != 0) {
        strncpy(s_last_dl, deep_link, sizeof(s_last_dl) - 1);
        s_last_dl[sizeof(s_last_dl) - 1] = '\0';
        if (deep_link[0]) {
            lv_qrcode_update(s_qr, deep_link, strlen(deep_link));
            lv_obj_remove_flag(s_qr, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_qr, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (code[0]) {
        lv_label_set_text_fmt(s_code, "Code  %s", code);
    } else {
        lv_label_set_text(s_code, "");
    }
    if (hash[0]) {
        // Hash on its own line so the full 66-char value wraps (set_long_mode WRAP) instead
        // of being clipped — the operator must read it ALL to compare against the master UI.
        lv_label_set_text_fmt(s_hash, "device-key\n%s", hash);
    } else {
        lv_label_set_text(s_hash, "");
    }

    switch (state) {
    case PAIR_REQUESTING:
        lv_label_set_text(s_status, "Requesting pairing code...");
        lv_obj_set_style_text_color(s_status, UI_COL_WARN, 0);
        break;
    case PAIR_UNBOUND:
        lv_label_set_text(s_status, "Scan in the parent-control app or enter the code.\nWaiting for your master...");
        lv_obj_set_style_text_color(s_status, UI_COL_MUTED, 0);
        break;
    case PAIR_BOUND:
        lv_label_set_text(s_status, LV_SYMBOL_OK "  Paired");
        lv_obj_set_style_text_color(s_status, UI_COL_OK, 0);
        break;
    case PAIR_ERROR:
        lv_label_set_text(s_status, LV_SYMBOL_WARNING "  Pairing failed - tap Request to retry");
        lv_obj_set_style_text_color(s_status, UI_COL_ERR, 0);
        break;
    default:
        lv_label_set_text(s_status, "Tap Request to begin pairing");
        lv_obj_set_style_text_color(s_status, UI_COL_MUTED, 0);
        break;
    }
}

static void request_event_cb(lv_event_t *e)
{
    (void)e;
    pairing_start();
}

ui_screen_view_t ui_build_pairing(void)
{
    lv_obj_t *scr = ui_make_screen();
    s_bar = ui_make_status_bar(scr);

    lv_obj_t *content = lv_obj_create(scr);
    lv_obj_set_width(content, lv_pct(100));
    lv_obj_set_flex_grow(content, 1);
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_pad_all(content, 8, 0);
    lv_obj_set_style_pad_row(content, 6, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    ui_make_title(content, "Pair this device");

    s_qr = lv_qrcode_create(content);
    lv_qrcode_set_size(s_qr, 280);
    lv_qrcode_set_dark_color(s_qr, lv_color_black());
    lv_qrcode_set_light_color(s_qr, lv_color_white());
    lv_obj_set_style_border_color(s_qr, lv_color_white(), 0);
    lv_obj_set_style_border_width(s_qr, 6, 0); // QR quiet zone
    lv_obj_add_flag(s_qr, LV_OBJ_FLAG_HIDDEN); // until a deep-link exists

    s_code = lv_label_create(content);
    lv_obj_set_style_text_font(s_code, &lv_font_montserrat_20, 0);
    lv_label_set_text(s_code, "");

    s_hash = lv_label_create(content);
    // The full device_key_hash ("0x" + 64 hex) is the operator's attested-identity check
    // vs the master UI — wrap it across lines (the master UI uses break-all too), never clip.
    lv_obj_set_width(s_hash, lv_pct(94));
    lv_label_set_long_mode(s_hash, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_align(s_hash, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(s_hash, UI_COL_MUTED, 0);
    lv_label_set_text(s_hash, "");

    s_status = lv_label_create(content);
    lv_obj_set_width(s_status, lv_pct(96));
    lv_obj_set_style_text_align(s_status, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(s_status, LV_LABEL_LONG_WRAP);
    lv_label_set_text(s_status, "Tap Request to begin pairing");

    lv_obj_t *footer = lv_obj_create(scr);
    lv_obj_set_size(footer, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(footer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(footer, 0, 0);
    lv_obj_set_style_pad_all(footer, 8, 0);
    lv_obj_remove_flag(footer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(footer, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(footer, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    ui_add_nav_button(footer, LV_SYMBOL_LEFT "  Back", UI_SCREEN_HOME);
    lv_obj_t *request = lv_button_create(footer);
    lv_obj_set_style_bg_color(request, UI_COL_ACCENT, 0);
    lv_obj_set_style_radius(request, 8, 0);
    lv_obj_set_style_pad_hor(request, 16, 0);
    lv_obj_set_style_pad_ver(request, 10, 0);
    lv_obj_t *request_label = lv_label_create(request);
    lv_label_set_text(request_label, LV_SYMBOL_REFRESH "  Request");
    lv_obj_set_style_text_color(request_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(request_label);
    lv_obj_add_event_cb(request, request_event_cb, LV_EVENT_CLICKED, NULL);

    ui_screen_view_t view = { .root = scr, .refresh = pairing_refresh };
    return view;
}
