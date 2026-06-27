#pragma once
// Sim shim: the only FreeRTOS surface app_state.c touches is the recursive-mutex
// API (semphr.h) + portMAX_DELAY. The sim is single-threaded (one LVGL loop), so
// the mutex is a no-op (see semphr.h) and this header just supplies the constant.
#include <stdint.h>
#define portMAX_DELAY 0xFFFFFFFFUL
