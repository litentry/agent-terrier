// Client for the device's assigned agent (a hermes-sandbox bridge, PR #347):
//   POST {base}/v1/chat  with  Authorization: Bearer <AGENTKEYS_BRIDGE_TOKEN>
//   GET  {base}/healthz
// The /v1/chat SSE contract (token / tool_start / tool / done / error) is parsed straight into
// app_state so the UI streams the reply live.
#pragma once

#include <stdbool.h>

void agent_client_init(const char *base_url, const char *bearer);

// One conversational turn, fire-and-forget: appends the user message to app_state, then streams
// the agent reply into the last agent bubble. Spawns a short-lived task; the UI never blocks.
// A turn already in flight is ignored.
void agent_client_send(const char *text);

// True when a direct-agent base URL is configured (AGENTKEYS_AGENT_URL). The UI
// uses this to distinguish "a direct-agent turn can be attempted" from an
// unconfigured device — so an unpaired, no-agent device guides the operator to
// pair instead of POSTing to an empty base (a cryptic "HTTP 0").
bool agent_client_configured(void);

// Liveness probe: GET {base}/healthz → true on HTTP 200 with ok:true. Blocking; call off-UI.
bool agent_client_healthz(void);
