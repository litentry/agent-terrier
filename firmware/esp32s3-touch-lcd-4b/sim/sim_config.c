// #517 — see sim_config.h. Env-or-default, resolved once per process.
#include "sim_config.h"

#include <stdbool.h>
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

// #523 — the channel worker the paired device publishes/polls against. Explicit
// AGENTKEYS_CHANNEL_WORKER_URL wins; else DERIVE it from the broker URL by
// swapping the leading `broker.` host label for `channel.` (the deployment
// convention: worker vhosts are `<slug>.<zone>` co-located with the broker), so
// the operator normally sets only AGENTKEYS_BROKER_URL.
const char *ak_sim_channel_worker_url(void) {
    static char buf[256];
    static const char *cached;
    if (!cached) {
        const char *explicit = getenv("AGENTKEYS_CHANNEL_WORKER_URL");
        if (explicit && *explicit) {
            cached = explicit;
            return cached;
        }
        const char *broker = ak_sim_broker_url();
        const char *host = strstr(broker, "://");
        // Derive only when the host label is literally `broker.`; otherwise fall
        // back to the broker URL itself (loudly wrong is better than silently
        // dialing a made-up host).
        if (host && strncmp(host + 3, "broker.", 7) == 0) {
            size_t scheme_len = (size_t)(host + 3 - broker);
            int n = snprintf(buf, sizeof(buf), "%.*schannel.%s", (int)scheme_len, broker,
                             host + 3 + 7);
            cached = (n > 0 && (size_t)n < sizeof(buf)) ? buf : broker;
        } else {
            fprintf(stderr,
                    "W (sim_config) cannot derive the channel worker from %s (host is not "
                    "`broker.<zone>`).\n                Set AGENTKEYS_CHANNEL_WORKER_URL "
                    "explicitly.\n",
                    broker);
            cached = broker;
        }
    }
    return cached;
}

// The `opchat-<label>` channel id this device converses on (matches the delegate
// it mirrors). Empty = not channel-configured → the direct agent bridge is used.
const char *ak_sim_chat_channel_id(void) {
    static const char *cached;
    static bool done;
    if (!done) {
        const char *v = getenv("AGENTKEYS_CHAT_CHANNEL_ID");
        cached = (v && *v) ? v : "";
        done = true;
    }
    return cached;
}
