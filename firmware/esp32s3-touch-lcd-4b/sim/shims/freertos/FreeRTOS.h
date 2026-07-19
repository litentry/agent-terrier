#pragma once
// Sim shim: the only FreeRTOS surface app_state.c touches is the recursive-mutex
// API (semphr.h) + portMAX_DELAY. The sim is single-threaded (one LVGL loop), so
// the mutex is a no-op (see semphr.h) and this header just supplies the constant.
#include <stdint.h>
#define portMAX_DELAY 0xFFFFFFFFUL

// A 1 ms tick, so ms and ticks are interchangeable in the mirror (vTaskDelay
// sleeps for exactly this many milliseconds).
#ifndef portTICK_PERIOD_MS
#define portTICK_PERIOD_MS 1u
#endif
#ifndef pdMS_TO_TICKS
#define pdMS_TO_TICKS(ms) ((uint32_t)(ms))
#endif
