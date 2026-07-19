#pragma once
// Sim shim for esp_random.h (#517).
//
// On-device this is the hardware RNG, and it seeds the K10 device key
// (device_identity.c). The desktop mirror MUST therefore use a CSPRNG, not
// rand() — a mock device whose key is predictable would be a real key-custody
// footgun the moment someone pairs it against a live broker. macOS/BSD get
// arc4random_buf; Linux gets getrandom(2).
#include <stddef.h>
#include <stdint.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h>
static inline void esp_fill_random(void *buf, size_t len) { arc4random_buf(buf, len); }
#else
#include <sys/random.h>
static inline void esp_fill_random(void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = getrandom((unsigned char *)buf + off, len - off, 0);
        if (n <= 0) { continue; }
        off += (size_t)n;
    }
}
#endif

static inline uint32_t esp_random(void) {
    uint32_t v;
    esp_fill_random(&v, sizeof(v));
    return v;
}
