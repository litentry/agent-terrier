// AgentKeys ESP32-S3 demo firmware — button task
// Plan: docs/spec/plans/issue-103-aiosandbox-hermes-esp32-demo.md
//
// GPIO interrupt → ISR posts to queue → task debounces (200ms) → emits press event.

#include "button.h"
#include "config.h"

#include "esp_log.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

static const char *TAG = "btn";
static QueueHandle_t s_isr_queue = NULL;

#define DEBOUNCE_MS 200

static void IRAM_ATTR button_isr_handler(void *arg)
{
    uint32_t ts = (uint32_t)(esp_log_timestamp());
    xQueueSendFromISR(s_isr_queue, &ts, NULL);
}

void button_task(void *arg)
{
    // ISR-side queue: deeper than the app-side queue to absorb bouncing
    s_isr_queue = xQueueCreate(16, sizeof(uint32_t));

    // Configure GPIO as input with pull-up + falling-edge interrupt
    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_NEGEDGE,
        .pin_bit_mask = (1ULL << BUTTON_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = 1,
        .pull_down_en = 0,
    };
    gpio_config(&io_conf);

    // Install ISR service + handler
    gpio_install_isr_service(0);
    gpio_isr_handler_add(BUTTON_GPIO, button_isr_handler, NULL);

    ESP_LOGI(TAG, "ready (GPIO %d, falling edge, %dms debounce)", BUTTON_GPIO, DEBOUNCE_MS);

    uint32_t ts;
    uint32_t last_ts = 0;
    while (1) {
        if (xQueueReceive(s_isr_queue, &ts, portMAX_DELAY)) {
            // Debounce: only emit if at least DEBOUNCE_MS since last press
            if (ts - last_ts >= DEBOUNCE_MS) {
                last_ts = ts;
                ESP_LOGI(TAG, "pressed @ %lu ms", (unsigned long)ts);
                xQueueSend(g_button_queue, &ts, 0);
            }
        }
    }
}
