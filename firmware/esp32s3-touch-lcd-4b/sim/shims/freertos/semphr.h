#pragma once
// Sim shim for FreeRTOS recursive semaphores. app_state.c locks on every accessor
// for cross-task safety on-device; the simulator runs app_state from ONE thread
// (the LVGL loop), so the lock is a no-op. This keeps app_state.c byte-identical
// between firmware and sim (no #ifdef) — the whole point of the drift-free mirror.
#include <stdint.h>

typedef int SemaphoreHandle_t;

static inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutex(void) {
    return 1;
}
static inline int xSemaphoreTakeRecursive(SemaphoreHandle_t s, uint32_t timeout) {
    (void)s;
    (void)timeout;
    return 1;
}
static inline int xSemaphoreGiveRecursive(SemaphoreHandle_t s) {
    (void)s;
    return 1;
}
