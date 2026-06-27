// Connection / onboarding — WiFi + agent endpoint status. On-device provisioning (SoftAP/BLE)
// lands in P2; for now this shows the configured target + live connection state.
#include "ui.h"
#include "app_config.h"

static lv_obj_t *s_bar;
static lv_obj_t *s_ip;
static lv_obj_t *s_state;

static const char *conn_text(conn_state_t state)
{
    switch (state) {
    case CONN_BOOT:
        return "booting";
    case CONN_WIFI_CONNECTING:
        return "connecting to WiFi...";
    case CONN_WIFI_OK:
        return "WiFi connected";
    case CONN_AGENT_OK:
        return "agent reachable";
    case CONN_ERROR:
        return "connection error";
    default:
        return "?";
    }
}

static lv_obj_t *kv_row(lv_obj_t *parent, const char *key, const char *value)
{
    lv_obj_t *row = lv_label_create(parent);
    lv_obj_set_width(row, lv_pct(100));
    lv_label_set_long_mode(row, LV_LABEL_LONG_WRAP);
    lv_label_set_text_fmt(row, "%s   %s", key, value);
    return row;
}

static void connection_refresh(void)
{
    ui_status_bar_refresh(s_bar);
    char ip[APP_IP_MAXLEN];
    app_state_get_ip(ip, sizeof(ip));
    lv_label_set_text_fmt(s_ip, "IP   %s", ip[0] ? ip : "-");
    conn_state_t state = app_state_get_conn();
    lv_label_set_text_fmt(s_state, "Status   %s", conn_text(state));
    lv_obj_set_style_text_color(s_state,
                                state == CONN_AGENT_OK   ? UI_COL_OK
                                : state == CONN_ERROR    ? UI_COL_ERR
                                : state == CONN_WIFI_OK  ? UI_COL_OK
                                                         : UI_COL_WARN,
                                0);
}

ui_screen_view_t ui_build_connection(void)
{
    lv_obj_t *scr = ui_make_screen();
    s_bar = ui_make_status_bar(scr);

    lv_obj_t *content = lv_obj_create(scr);
    lv_obj_set_width(content, lv_pct(100));
    lv_obj_set_flex_grow(content, 1);
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(content, 0, 0);
    lv_obj_set_style_pad_all(content, 8, 0);
    lv_obj_set_style_pad_row(content, 8, 0);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    ui_make_title(content, "Connection");

    lv_obj_t *panel = lv_obj_create(content);
    lv_obj_set_width(panel, lv_pct(94));
    lv_obj_set_height(panel, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(panel, UI_COL_PANEL, 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(panel, 10, 0);
    lv_obj_set_style_border_width(panel, 0, 0);
    lv_obj_set_style_pad_all(panel, 12, 0);
    lv_obj_set_style_pad_row(panel, 8, 0);
    lv_obj_remove_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(panel, LV_FLEX_FLOW_COLUMN);

    kv_row(panel, "WiFi", WIFI_SSID);
    s_ip = kv_row(panel, "IP", "-");
    s_state = kv_row(panel, "Status", "booting");
    kv_row(panel, "Agent", AGENT_BASE_URL);
    kv_row(panel, "Broker", BROKER_URL);

    lv_obj_t *note = lv_label_create(content);
    lv_obj_set_width(note, lv_pct(94));
    lv_label_set_long_mode(note, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_color(note, UI_COL_MUTED, 0);
    lv_label_set_text(note, "On-device WiFi setup (SoftAP / BLE) arrives in P2. For now, set "
                            "credentials in main/secrets.h or via NVS at provisioning.");

    lv_obj_t *footer = lv_obj_create(scr);
    lv_obj_set_size(footer, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(footer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(footer, 0, 0);
    lv_obj_set_style_pad_all(footer, 8, 0);
    lv_obj_remove_flag(footer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(footer, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(footer, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    ui_add_nav_button(footer, LV_SYMBOL_LEFT "  Back", UI_SCREEN_SETTINGS);

    ui_screen_view_t view = { .root = scr, .refresh = connection_refresh };
    return view;
}
