// #523 — the firmware CHANNEL client: a paired device converses with its
// operator (and, transitively, a spawned delegate) over the §22e channel plane
// (`/v1/channel/publish` + `/v1/channel/poll`) instead of the direct agent
// bridge. The device mints its OWN `channel-pub:<id>` / `channel-sub:<id>` caps
// with its K10 cap-PoP (#76/#408) — the K10 never leaves NVS, and the operator
// owns the duplex feed (`opchat-<label>`, D8) both meet on.
//
// This is the paired-device path; a device holds ONLY channel grants, so it
// talks to the channel worker for messaging and the broker only to resolve its
// session (J1) + mint caps. `channel_client_publish` sends a turn (text or an
// `audio-clip`, #522); the background poll loop delivers `direction:out`
// replies to the app via app_state, exactly as `agent_client` does for the
// bridge path.
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

// True once pairing is BOUND and the channel coordinates (worker URL + the
// `opchat-<label>` channel id) are configured — i.e. the device can converse
// over the channel plane. When false, the firmware falls back to the direct
// `agent_client` bridge path (an unpaired demo device).
bool channel_client_ready(void);

// Publish one turn on the device's channel feed: `kind` is the wire kind
// ("text" or "audio-clip"), `body_b64` the already-base64 payload, `voice`/
// `speech_rate` the optional #522 audio params for the reply (voice may be NULL
// / speech_rate INT32_MIN to omit). Direction is always "in" (device → agent).
// Blocks on the resolve → cap-mint → publish round-trip; safe to call from a
// worker task (not the LVGL thread). Returns ESP_OK on a 2xx publish.
esp_err_t channel_client_publish_turn(const char *kind, const char *body_b64, const char *voice,
                                      int speech_rate);

// Convenience for a text turn (no audio params).
esp_err_t channel_client_send_text(const char *text);

// #524 — send a captured voice clip (a mono-16-bit WAV) as an `audio-clip`
// turn: the client base64-encodes it and publishes with the reply `voice` +
// `speech_rate` (#522 audio params; voice NULL / speech_rate INT32_MIN = omit).
// Reflects a "voice message" user bubble locally. `wav`/`wav_len` are owned by
// the caller (copied internally).
esp_err_t channel_client_send_audio(const uint8_t *wav, size_t wav_len, const char *voice,
                                    int speech_rate);

// Start the background subscribe long-poll loop: resolves J1, mints a
// `channel-sub` cap, long-polls `/v1/channel/poll`, and for each inbound
// `direction:out` event appends it to app_state (text → a bubble; audio-clip →
// queued for playback). Idempotent — a second call is a no-op. Mirrors
// `agent_client`'s turn-task model; every failure is loud + backed off, never a
// crash. No-op when `channel_client_ready()` is false.
void channel_client_start(void);
