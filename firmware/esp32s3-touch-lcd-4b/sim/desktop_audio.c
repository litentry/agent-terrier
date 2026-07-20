// #524 — the desktop mirror's audio_io implementation, over SDL2's audio queue
// API (no callback threads: SDL_QueueAudio for playback, SDL_DequeueAudio for
// capture). Mono 16-bit PCM at AUDIO_SAMPLE_RATE, wrapped in a 44-byte WAV
// header on capture — exactly what the gate ASR relay accepts as format:"wav".
//
// On Emscripten (the browser mirror / firmware-sim CI gate) real capture is
// unavailable, so audio_io_available() reports false and the caller uses the
// text fallback — never a silent no-op.
#include "audio_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <SDL2/SDL.h>

#ifdef __EMSCRIPTEN__

esp_err_t audio_io_init(void) { return ESP_OK; }
bool audio_io_available(void) { return false; }
esp_err_t audio_capture_start(void) { return ESP_ERR_NOT_SUPPORTED; }
bool audio_capture_active(void) { return false; }
uint8_t *audio_capture_stop(size_t *out_len) {
    if (out_len) { *out_len = 0; }
    return NULL;
}
esp_err_t audio_play_wav(const uint8_t *wav, size_t len) {
    (void)wav;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}

#else

static SDL_AudioDeviceID s_cap;  // microphone
static SDL_AudioDeviceID s_play; // speaker
static bool s_ready;
static bool s_capturing;

static SDL_AudioSpec want_spec(void) {
    SDL_AudioSpec s;
    SDL_zero(s);
    s.freq = AUDIO_SAMPLE_RATE;
    s.format = AUDIO_S16SYS;
    s.channels = 1;
    s.samples = 1024;
    return s;
}

esp_err_t audio_io_init(void) {
    if (s_ready) {
        return ESP_OK;
    }
    if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) {
        fprintf(stderr, "W (audio) SDL_InitSubSystem(AUDIO) failed: %s\n", SDL_GetError());
        return ESP_FAIL;
    }
    SDL_AudioSpec want = want_spec(), have;
    // NULL callback => use the queue API (SDL_QueueAudio / SDL_DequeueAudio).
    s_cap = SDL_OpenAudioDevice(NULL, 1 /*iscapture*/, &want, &have, 0);
    if (!s_cap) {
        fprintf(stderr, "W (audio) no capture device: %s — mic input disabled\n", SDL_GetError());
    }
    s_play = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
    if (!s_play) {
        fprintf(stderr, "W (audio) no playback device: %s — reply audio disabled\n", SDL_GetError());
    }
    s_ready = true;
    return ESP_OK;
}

bool audio_io_available(void) {
    return s_ready && s_cap != 0 && s_play != 0;
}

esp_err_t audio_capture_start(void) {
    if (!s_cap) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    SDL_ClearQueuedAudio(s_cap);
    SDL_PauseAudioDevice(s_cap, 0); // unpause = record
    s_capturing = true;
    return ESP_OK;
}

bool audio_capture_active(void) {
    return s_capturing;
}

// Little-endian WAV (44-byte header + PCM). `pcm_len` = payload bytes.
static uint8_t *wrap_wav(const uint8_t *pcm, size_t pcm_len, size_t *out_len) {
    size_t total = 44 + pcm_len;
    uint8_t *w = (uint8_t *)malloc(total);
    if (!w) {
        return NULL;
    }
    uint32_t rate = AUDIO_SAMPLE_RATE, byte_rate = rate * 2; // mono, 16-bit
    memcpy(w, "RIFF", 4);
    uint32_t riff = (uint32_t)(36 + pcm_len);
    memcpy(w + 4, &riff, 4);
    memcpy(w + 8, "WAVE", 4);
    memcpy(w + 12, "fmt ", 4);
    uint32_t fmt_size = 16;
    memcpy(w + 16, &fmt_size, 4);
    uint16_t pcm_fmt = 1, channels = 1, block_align = 2, bits = 16;
    memcpy(w + 20, &pcm_fmt, 2);
    memcpy(w + 22, &channels, 2);
    memcpy(w + 24, &rate, 4);
    memcpy(w + 28, &byte_rate, 4);
    memcpy(w + 32, &block_align, 2);
    memcpy(w + 34, &bits, 2);
    memcpy(w + 36, "data", 4);
    uint32_t data_size = (uint32_t)pcm_len;
    memcpy(w + 40, &data_size, 4);
    memcpy(w + 44, pcm, pcm_len);
    *out_len = total;
    return w;
}

uint8_t *audio_capture_stop(size_t *out_len) {
    if (out_len) {
        *out_len = 0;
    }
    if (!s_cap || !s_capturing) {
        return NULL;
    }
    s_capturing = false;
    SDL_PauseAudioDevice(s_cap, 1); // stop recording
    uint32_t queued = SDL_GetQueuedAudioSize(s_cap);
    if (queued == 0) {
        return NULL; // silence / no mic permission
    }
    uint8_t *pcm = (uint8_t *)malloc(queued);
    if (!pcm) {
        SDL_ClearQueuedAudio(s_cap);
        return NULL;
    }
    uint32_t got = SDL_DequeueAudio(s_cap, pcm, queued);
    uint8_t *wav = wrap_wav(pcm, got, out_len);
    free(pcm);
    return wav;
}

esp_err_t audio_play_wav(const uint8_t *wav, size_t len) {
    if (!s_play) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    // Skip a 44-byte WAV header if present; queue the raw PCM.
    const uint8_t *pcm = wav;
    size_t pcm_len = len;
    if (len >= 44 && memcmp(wav, "RIFF", 4) == 0) {
        pcm += 44;
        pcm_len -= 44;
    }
    if (SDL_QueueAudio(s_play, pcm, (uint32_t)pcm_len) != 0) {
        return ESP_FAIL;
    }
    SDL_PauseAudioDevice(s_play, 0); // unpause = play
    return ESP_OK;
}

#endif // __EMSCRIPTEN__
