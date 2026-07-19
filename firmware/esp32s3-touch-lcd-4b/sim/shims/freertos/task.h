#pragma once
// Sim shim for freertos/task.h (#517) — pthreads.
//
// net/ spawns real background workers (the crypto worker that does K10 EC math,
// the pairing poll loop, the chat stream reader). Those are REAL concurrency in
// the firmware, so the mirror runs them as real threads rather than flattening
// them — the point of #517 is that the desktop app runs the same code paths.
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "FreeRTOS.h"

typedef void *TaskHandle_t;
typedef void (*TaskFunction_t)(void *);
/// device_identity.c allocates the crypto worker's TCB + stack STATICALLY so the
/// ESP32 keeps them in internal RAM (not PSRAM). The desktop has no such split,
/// so these are inert placeholders — pthreads owns the real stack.
typedef struct { void *_unused; } StaticTask_t;
typedef unsigned long StackType_t;

#ifndef pdPASS
#define pdPASS 1
#endif

/// The firmware passes delays as `ms / portTICK_PERIOD_MS`; with a 1 ms tick the
/// argument IS milliseconds, which is what this sleeps for.
static inline void vTaskDelay(uint32_t ticks) {
    struct timespec ts = { .tv_sec = (time_t)(ticks / 1000u),
                           .tv_nsec = (long)(ticks % 1000u) * 1000000L };
    nanosleep(&ts, NULL);
}

struct ak_task_trampoline_arg {
    TaskFunction_t fn;
    void *arg;
};

static inline void *ak_task_trampoline(void *p) {
    struct ak_task_trampoline_arg *a = (struct ak_task_trampoline_arg *)p;
    TaskFunction_t fn = a->fn;
    void *arg = a->arg;
    free(a);
    fn(arg);
    return NULL;
}

/// Detached — FreeRTOS tasks that `vTaskDelete(NULL)` themselves have no joiner,
/// and the sim's lifetime is the window's.
static inline int xTaskCreate(TaskFunction_t fn, const char *name, uint32_t stack,
                              void *arg, unsigned prio, TaskHandle_t *out) {
    (void)name; (void)stack; (void)prio;
    struct ak_task_trampoline_arg *a =
        (struct ak_task_trampoline_arg *)malloc(sizeof(*a));
    if (!a) { return 0; }
    a->fn = fn;
    a->arg = arg;
    pthread_t t;
    if (pthread_create(&t, NULL, ak_task_trampoline, a) != 0) { free(a); return 0; }
    pthread_detach(t);
    if (out) { *out = (TaskHandle_t)t; }
    return pdPASS;
}

/// Static variant → the same detached pthread; the caller's TCB/stack buffers
/// are ignored (see StaticTask_t above). Returns a handle, not pdPASS.
static inline TaskHandle_t xTaskCreateStatic(TaskFunction_t fn, const char *name,
                                             uint32_t stack, void *arg, unsigned prio,
                                             StackType_t *stack_buf, StaticTask_t *tcb) {
    (void)stack_buf; (void)tcb;
    TaskHandle_t h = NULL;
    return xTaskCreate(fn, name, stack, arg, prio, &h) == pdPASS ? h : NULL;
}

/// Stack-headroom diagnostic the firmware logs after the crypto job. pthreads
/// gives us no equivalent, and 0 is the honest answer ("unknown") rather than a
/// number that would read as a real measurement.
static inline uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t t) {
    (void)t;
    return 0;
}

static inline void vTaskDelete(TaskHandle_t t) {
    // Self-delete (the FreeRTOS idiom `vTaskDelete(NULL)`) = just return from the
    // thread function; the trampoline above handles it.
    (void)t;
}
