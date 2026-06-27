// Compile-time configuration + per-device override layering.
// Priority (high → low): NVS (namespace "agentkeys", set at provisioning) > secrets.h (dev) >
// the DEFAULT_* below. The agent base URL + bearer normally arrive at provisioning/pairing
// time (issue #348 open question); the defaults let the firmware boot + be demoed first.
#pragma once

#ifndef PROJECT_VER
#define PROJECT_VER "0.1.0"
#endif

// The device's assigned cloud agent (a hermes-sandbox bridge, PR #347) + its broker.
#define DEFAULT_AGENT_BASE_URL "https://agent.example.invalid"
#define DEFAULT_AGENT_BEARER   "" // AGENTKEYS_BRIDGE_TOKEN; empty = bridge unauthenticated dev mode
#define DEFAULT_BROKER_URL     "https://broker.example.invalid"

#define DEFAULT_SPEAK_ON     true
#define DEFAULT_SPEECH_SPEED 100 // percent of nominal rate, clamped 50..200
#define DEFAULT_VOICE_ID     "default"

#define APP_HTTP_RX_CHUNK 1024
#define APP_URL_MAXLEN    192

#if __has_include("secrets.h")
#include "secrets.h"
#endif

#ifndef WIFI_SSID
#define WIFI_SSID "your-wifi-ssid"
#endif
#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD "your-wifi-password"
#endif
#ifndef AGENT_BASE_URL
#define AGENT_BASE_URL DEFAULT_AGENT_BASE_URL
#endif
#ifndef AGENT_BEARER
#define AGENT_BEARER DEFAULT_AGENT_BEARER
#endif
#ifndef BROKER_URL
#define BROKER_URL DEFAULT_BROKER_URL
#endif
