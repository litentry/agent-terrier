#pragma once
// Seed sample device state so the mirror boots populated (all 5 screens visible).
// Call after app_state_init(), before ui_init().
void mock_net_seed(void);
