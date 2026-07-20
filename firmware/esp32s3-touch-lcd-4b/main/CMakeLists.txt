idf_component_register(
    SRCS
        "app_main.c"
        "app_state.c"
        "ui/ui.c"
        "ui/screen_home.c"
        "ui/screen_pairing.c"
        "ui/screen_settings.c"
        "ui/screen_connection.c"
        "ui/screen_voices.c"
        "net/agent_client.c"
        "net/pairing.c"
        "net/wifi.c"
        "net/device_identity.c"
        "net/channel_client.c"
    INCLUDE_DIRS "." "ui" "net"
    # `main` implicitly depends on every component, so the managed BSP (waveshare/
    # esp32_s3_touch_lcd_4b) + esp_lvgl_port + LVGL headers resolve without being listed here;
    # we only name the IDF built-ins the sources include directly.
    REQUIRES
        esp_wifi
        esp_event
        esp_netif
        esp_http_client
        esp-tls
        mbedtls
        nvs_flash
        json
        esp_hw_support  # esp_fill_random (device_identity.c K10 entropy)
        agentkeys_device  # the shared Rust K10 crypto staticlib (#367)
)
