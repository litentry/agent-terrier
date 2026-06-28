// §10.2 device-initiated pairing (arch.md), spoken DIRECTLY to the broker with the
// device's own K10 (device_identity) — pop_sig-authenticated, no bearer, no agent
// bridge in the path (issue #367 Phase B). Opens an unbound pairing request, builds
// the canonical agentkeys-pair://claim?code=..&broker=.. deep-link into app_state for
// the Pairing screen QR, then polls the broker until the master's claim mints
// J1_agent (status "claimed") → bound.
#pragma once

// Begin pairing: PAIR_REQUESTING -> PAIR_UNBOUND (artifact ready, QR shown) -> PAIR_BOUND.
// Spawns a task; safe to call from a UI event cb. No-op if pairing is already in flight or bound.
void pairing_start(void);
