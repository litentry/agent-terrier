# AgentKeys ESP32-S3 demo firmware — main component manifest

idf_component_register(
    SRCS
        "main.c"
        "wifi_sta.c"
        "https_chat.c"
        "button.c"
        "led_status.c"
    INCLUDE_DIRS "."
    REQUIRES
        nvs_flash
        esp_wifi
        esp_event
        esp_netif
        esp_http_client
        mbedtls
        json
        driver
        esp_timer
        esp_ringbuf
)
