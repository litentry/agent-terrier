#pragma once
// #517 — runtime coordinates for the desktop mirror.
//
// The firmware takes its broker/agent URLs as COMPILE-TIME macros (app_config.h,
// overridden by a dev secrets.h) because an ESP32 is flashed per deployment. A
// desktop mirror is not: the operator wants to point the same binary at the VE
// stack, then AWS, then a local dev broker, without a rebuild.
//
// So the sim build force-includes this file (`-include sim_config.h`) BEFORE
// app_config.h runs its `#ifndef BROKER_URL` fallbacks. Because these expand to
// a function call returning `const char *`, every use site in the firmware
// (`snprintf("%s%s", BROKER_URL, PATH)`) compiles unchanged — pairing.c and
// agent_client.c are not forked or #ifdef'd, which is the whole point of #517.
//
//   AGENTKEYS_BROKER_URL   the broker the device pairs against (required)
//   AGENTKEYS_AGENT_URL    the agent bridge /v1/chat talks to
//   AGENTKEYS_AGENT_BEARER bearer for that bridge ("" = unauthenticated dev)

const char *ak_sim_broker_url(void);
const char *ak_sim_agent_url(void);
const char *ak_sim_agent_bearer(void);

#define BROKER_URL     ak_sim_broker_url()
#define AGENT_BASE_URL ak_sim_agent_url()
#define AGENT_BEARER   ak_sim_agent_bearer()
