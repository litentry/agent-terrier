#pragma once
// Sim shim for freertos/queue.h + binary semaphores (#517) — pthreads.
//
// net/ hands work between threads over a queue (the crypto worker's request
// channel) and signals completion with a binary semaphore. Both are real
// synchronisation in the firmware, so the mirror implements them for real
// rather than serialising — a device whose crypto ran inline would hide
// exactly the ordering bugs this mirror exists to surface.
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "FreeRTOS.h"

#ifndef pdTRUE
#define pdTRUE  1
#define pdFALSE 0
#endif
#ifndef portMAX_DELAY
#define portMAX_DELAY 0xFFFFFFFFu
#endif

typedef struct ak_queue {
    unsigned char *buf;
    size_t item_size, capacity, head, tail, count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty, not_full;
} *QueueHandle_t;

static inline QueueHandle_t xQueueCreate(size_t len, size_t item_size) {
    struct ak_queue *q = (struct ak_queue *)calloc(1, sizeof(*q));
    if (!q) { return NULL; }
    q->buf = (unsigned char *)calloc(len, item_size);
    if (!q->buf) { free(q); return NULL; }
    q->item_size = item_size;
    q->capacity = len;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
    return q;
}

static inline int xQueueSend(QueueHandle_t q, const void *item, uint32_t timeout) {
    (void)timeout; // callers use portMAX_DELAY; the mirror blocks
    if (!q) { return pdFALSE; }
    pthread_mutex_lock(&q->lock);
    while (q->count == q->capacity) { pthread_cond_wait(&q->not_full, &q->lock); }
    memcpy(q->buf + q->tail * q->item_size, item, q->item_size);
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return pdTRUE;
}

static inline int xQueueReceive(QueueHandle_t q, void *out, uint32_t timeout) {
    (void)timeout;
    if (!q) { return pdFALSE; }
    pthread_mutex_lock(&q->lock);
    while (q->count == 0) { pthread_cond_wait(&q->not_empty, &q->lock); }
    memcpy(out, q->buf + q->head * q->item_size, q->item_size);
    q->head = (q->head + 1) % q->capacity;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return pdTRUE;
}

// The binary semaphore lives in semphr.h — it must share SemaphoreHandle_t with
// the recursive mutex app_state.c uses (one FreeRTOS type, two flavours).
