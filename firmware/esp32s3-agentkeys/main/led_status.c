// AgentKeys ESP32-S3 demo firmware — LED status task
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md
//
// v0 STUB: blinks the on-board GPIO at 1 Hz to prove the firmware is alive.
// TODO: drive the WS2812 RGB LED on GPIO 48 with proper state machine
//       (idle/processing/error/wifi-down) per the event group bits.

#include "led_status.h"
#include "config.h"

#include "esp_log.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "led";

void led_status_task(void *arg)
{
    // For v0 stub, use GPIO_NUM_2 (often a generic LED on dev boards)
    // The real RGB LED at GPIO 48 needs WS2812 RMT driver — TODO.
    const gpio_num_t led_pin = GPIO_NUM_2;

    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .pin_bit_mask = (1ULL << led_pin),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = 0,
        .pull_down_en = 0,
    };
    gpio_config(&io_conf);

    ESP_LOGI(TAG, "stub blinker on GPIO %d (TODO: real WS2812 state machine on GPIO %d)",
             led_pin, LED_GPIO);

    int state = 0;
    while (1) {
        gpio_set_level(led_pin, state);
        state = !state;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}
