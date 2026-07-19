// #517 — see sim_config.h. Env-or-default, resolved once per process.
#include "sim_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/// Empty/unset env → the caller's fallback. Never returns NULL: the firmware
/// snprintf()s these straight into a URL, so a NULL would be a crash and an
/// empty string would produce a silently malformed request.
static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

const char *ak_sim_broker_url(void) {
    static const char *cached;
    if (!cached) {
        cached = env_or("AGENTKEYS_BROKER_URL", "https://broker.example.invalid");
        if (strstr(cached, "example.invalid")) {
            // Loud, not silent: the default cannot pair, and a mirror that
            // "starts fine" then fails deep inside a poll loop wastes the
            // operator's time.
            fprintf(stderr,
                    "W (sim_config) AGENTKEYS_BROKER_URL is unset — using %s, which cannot pair.\n"
                    "                Set it to a real broker, e.g.\n"
                    "                  AGENTKEYS_BROKER_URL=https://broker.agentterrier.cn ./mirror\n",
                    cached);
        }
    }
    return cached;
}

const char *ak_sim_agent_url(void) {
    static const char *cached;
    if (!cached) { cached = env_or("AGENTKEYS_AGENT_URL", "https://agent.example.invalid"); }
    return cached;
}

const char *ak_sim_agent_bearer(void) {
    static const char *cached;
    if (!cached) { cached = env_or("AGENTKEYS_AGENT_BEARER", ""); }
    return cached;
}
