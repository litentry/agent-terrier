// #524 — the ESP32-S3 audio_io implementation over the on-board ES8311 codec.
// SCAFFOLD: the codec init + I2S mic/speaker wiring is hardware work that can
// only be validated on a board, so today this reports audio_io_available() ==
// false and the firmware falls back to the placeholder-transcript text turn —
// loudly, never silently. The real path (bsp_audio_init + I2S read/write into
// the same mono-16-bit-WAV contract the sim's desktop_audio.c implements) lands
// with on-hardware bring-up; the audio_io.h contract does not change.
#include "audio_io.h"

#include "esp_log.h"

static const char *TAG = "audio";
static bool s_warned;

esp_err_t audio_io_init(void)
{
    // P: bsp_audio_init() + bsp_audio_codec_microphone_init() /
    // bsp_audio_codec_speaker_init() + bsp_audio_poweramp_enable(true).
    if (!s_warned) {
        ESP_LOGW(TAG, "ES8311 audio not yet wired — TALK uses the text fallback (#524 hardware bring-up)");
        s_warned = true;
    }
    return ESP_OK;
}

bool audio_io_available(void)
{
    return false; // flips true when the ES8311 I2S path lands
}

esp_err_t audio_capture_start(void)
{
    return ESP_ERR_NOT_SUPPORTED;
}

bool audio_capture_active(void)
{
    return false;
}

uint8_t *audio_capture_stop(size_t *out_len)
{
    if (out_len) {
        *out_len = 0;
    }
    return NULL;
}

esp_err_t audio_play_wav(const uint8_t *wav, size_t len)
{
    (void)wav;
    (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}
