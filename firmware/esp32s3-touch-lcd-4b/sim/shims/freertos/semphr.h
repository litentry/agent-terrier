#pragma once
// Sim shim for FreeRTOS semaphores.
//
// TWO flavours share one `SemaphoreHandle_t`, exactly as in FreeRTOS:
//
//  • RECURSIVE MUTEX — app_state.c locks on every accessor for cross-task
//    safety on-device; the simulator runs app_state from ONE thread (the LVGL
//    loop), so the lock stays a no-op. This keeps app_state.c byte-identical
//    between firmware and sim (no #ifdef) — the whole point of the drift-free
//    mirror.
//
//  • BINARY SEMAPHORE (#517) — net/device_identity.c blocks a caller until the
//    crypto worker THREAD finishes a job. Once the real net/ compiles here that
//    is genuine cross-thread signalling, so it must be REAL: a no-op would let
//    the caller read the result before the worker wrote it.
//
// Hence the handle became a POINTER: the recursive flavour returns a sentinel
// it never dereferences, the binary flavour a live object. (Mixing the two
// families on one handle is a FreeRTOS misuse on-device too, so no guard here.)
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "FreeRTOS.h"

#ifndef pdTRUE
#define pdTRUE  1
#define pdFALSE 0
#endif
#ifndef portMAX_DELAY
#define portMAX_DELAY 0xFFFFFFFFu
#endif

typedef struct ak_sem {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    bool signalled;
} *SemaphoreHandle_t;

// ── recursive mutex (app_state) — deliberate no-op ───────────────────────────
/// Sentinel: non-NULL so callers' `if (!s)` checks pass; never dereferenced.
static inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutex(void) {
    return (SemaphoreHandle_t)(void *)1;
}
static inline int xSemaphoreTakeRecursive(SemaphoreHandle_t s, uint32_t timeout) {
    (void)s;
    (void)timeout;
    return pdTRUE;
}
static inline int xSemaphoreGiveRecursive(SemaphoreHandle_t s) {
    (void)s;
    return pdTRUE;
}

// ── binary semaphore (net/ crypto worker) — real ─────────────────────────────
static inline SemaphoreHandle_t xSemaphoreCreateBinary(void) {
    struct ak_sem *s = (struct ak_sem *)calloc(1, sizeof(*s));
    if (!s) { return NULL; }
    pthread_mutex_init(&s->lock, NULL);
    pthread_cond_init(&s->cond, NULL);
    return s;
}

static inline int xSemaphoreGive(SemaphoreHandle_t s) {
    if (!s) { return pdFALSE; }
    pthread_mutex_lock(&s->lock);
    s->signalled = true;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->lock);
    return pdTRUE;
}

static inline int xSemaphoreTake(SemaphoreHandle_t s, uint32_t timeout) {
    (void)timeout; // callers pass portMAX_DELAY; the mirror blocks
    if (!s) { return pdFALSE; }
    pthread_mutex_lock(&s->lock);
    while (!s->signalled) { pthread_cond_wait(&s->cond, &s->lock); }
    s->signalled = false;
    pthread_mutex_unlock(&s->lock);
    return pdTRUE;
}

static inline void vSemaphoreDelete(SemaphoreHandle_t s) {
    if (!s || s == (SemaphoreHandle_t)(void *)1) { return; } // never free the sentinel
    pthread_mutex_destroy(&s->lock);
    pthread_cond_destroy(&s->cond);
    free(s);
}
