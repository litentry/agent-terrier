// #524 — the device audio I/O abstraction: microphone CAPTURE (→ a self-
// contained WAV clip) + speaker PLAYBACK. One header, three implementations:
//   - desktop mirror  → sim/desktop_audio.c   (SDL2 audio; WASM = unavailable)
//   - ESP32-S3 board   → main/net/audio_es8311.c (ES8311 codec; scaffolded)
// A build without real audio (WASM mock, or the ESP32 until the codec path
// lands) reports `audio_io_available() == false`, and the caller falls back to
// the placeholder-transcript text turn — never a silent no-op.
//
// Clips are mono 16-bit PCM at AUDIO_SAMPLE_RATE, wrapped in a 44-byte WAV
// header (what the gate ASR relay accepts as `format:"wav"`).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

// Doubao bigmodel ASR accepts 16 kHz mono comfortably; keep capture + playback
// on one rate so no resampling is needed on-device.
#define AUDIO_SAMPLE_RATE 16000

// Init the mic + speaker. Idempotent. A no-op that returns ESP_OK on builds
// without real audio (so boot never fails on it); check audio_io_available().
esp_err_t audio_io_init(void);

// True when this build has real capture + playback (desktop SDL2). False on the
// WASM mock and the not-yet-wired ESP32 codec — the caller then uses the text
// fallback for a TALK turn.
bool audio_io_available(void);

// Begin buffering microphone audio. Returns ESP_ERR_NOT_SUPPORTED when audio is
// unavailable.
esp_err_t audio_capture_start(void);

// True between start and stop.
bool audio_capture_active(void);

// Stop capturing and return the clip as a malloc'd WAV (mono 16-bit) the CALLER
// frees; *out_len = byte length. Returns NULL if nothing was captured or audio
// is unavailable.
uint8_t *audio_capture_stop(size_t *out_len);

// Queue a WAV clip (mono 16-bit) for playback through the speaker. Non-blocking.
// ESP_ERR_NOT_SUPPORTED when audio is unavailable.
esp_err_t audio_play_wav(const uint8_t *wav, size_t len);
