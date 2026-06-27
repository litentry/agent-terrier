// WiFi STA bring-up. Uses the configured SSID/password; drives app_state conn
// (CONN_WIFI_CONNECTING -> CONN_WIFI_OK / CONN_ERROR) + the device IP, and auto-reconnects.
// P2 adds on-device provisioning (SoftAP/BLE) from the Connection screen.
#pragma once

void wifi_start(const char *ssid, const char *password);
