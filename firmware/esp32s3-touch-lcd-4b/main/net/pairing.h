// §10.2 device pairing (arch.md + PR #347). Asks this device's agent/broker for the pairing
// artifact (pairing_code + the canonical deep-link agentkeys-pair://claim?code=..&broker=..),
// stores it in app_state for the Pairing screen QR, then polls until the web master claims it.
#pragma once

// Begin pairing: PAIR_REQUESTING -> PAIR_UNBOUND (artifact ready, QR shown) -> PAIR_BOUND.
// Spawns a task; safe to call from a UI event cb. No-op if pairing is already in flight or bound.
void pairing_start(void);
