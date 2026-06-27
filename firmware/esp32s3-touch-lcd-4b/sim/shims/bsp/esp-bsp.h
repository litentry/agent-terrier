#pragma once
// Sim shim for the Waveshare BSP. On-device `bsp/esp-bsp.h` owns the ST7701/GT911
// pins and a recursive LVGL lock (bsp_display_lock/unlock). The simulator drives
// LVGL single-threaded from one loop, so the lock is a no-op — and ui.c only ever
// calls these two BSP symbols, so nothing else needs shimming.
#include <stdbool.h>
#include <stdint.h>

static inline bool bsp_display_lock(uint32_t timeout_ms) {
    (void)timeout_ms;
    return true;
}
static inline void bsp_display_unlock(void) {}
