# The open-source frontend is keyless by design

> Why publishing the parent-control web UI source changes nothing about key safety — and exactly what a malicious clone or a phished magic-link can (and cannot) reach. Defers to [Blockchain TEE Architecture §7](blockchain-tee-architecture#7-security-model-assumptions-and-attacker-surface) and [`arch.md`](../arch.md) §3–§6 for the canonical model.

The parent-control web app (the browser onboarding + master dashboard) is open source. A natural worry: *if anyone can read and clone the frontend, can a hacker stand up a malicious copy, trigger the login email, persuade me to click the magic link, and walk away with my keys?*

**Short answer: no.** The frontend holds no keys, can't reach your local daemon from another origin, and even a successfully-phished login lands at a chain-registered-device + hardware-passkey gate that a remote attacker can't pass. The worst realistic outcome is a generic magic-link phish that yields a **bounded, data-less, expiring session** — the same risk every email login on the internet carries — which we bound further still.

---

## 1. The frontend is a keyless remote control

Per [`arch.md`](../arch.md) §3 (trust boundaries) and §4 (key inventory), every key that matters lives somewhere the browser can't read:

| Key | Lives in | Frontend can read it? |
|---|---|---|
| **K10** — device key (secp256k1) | the daemon's OS keychain | never |
| **K11** — master passkey (P-256) | the platform authenticator's **hardware** (Secure Enclave / TPM / StrongBox) | never — not exfiltrable even by host-OS root |
| **K3 / KEK** — the credential + memory encryption root | the **signer TEE** (attested enclave) | never |
| **J1** — the session bearer | **the daemon** | never — the daemon is the authenticated proxy and keeps the bearer; the browser drives it but is never handed the token |

The browser app's job is to *drive ceremonies* (show the email box, run the WebAuthn prompt, render the dashboard), not to *hold secrets*. The daemon's onboarding endpoints return only non-secret status (`{ status, omni_account }`) — never a key, never the J1 bearer. So a malicious clone running in your browser has **nothing in the browser to steal**: the "cache all the keys" attack has no target.

This is the same posture as [Key Security](key-security): clients hold a bearer at most, never private keys; the authority lives server-side and in hardware.

---

## 2. The gates a malicious frontend hits

Walk the attack the way an attacker would:

**Gate 1 — a frontend at `evil.com` can't drive your daemon.** The daemon's ui-bridge ([`ui_bridge.rs`](../../crates/agentkeys-daemon/src/ui_bridge.rs)) binds `127.0.0.1:3114`, and its CORS layer allows only the local app origin (`http://localhost:3113`). The email endpoints take `application/json`, which forces a CORS **preflight** — and a preflight from `evil.com` is denied, so the browser never even sends the request (preflight-denied ≠ "response merely unreadable"). The `text/plain` dodge that skips preflight fails too: the JSON extractor rejects non-JSON bodies. A foreign origin cannot make your daemon do anything.

**Gate 2 — triggering the email is public, and harmless anyway.** Anyone — `curl`, an attacker's server — can ask the broker to email a magic link to any address; that's how "enter your email" works, identical to every password reset. The attacker doesn't even need the cloned frontend for this, and sending the email compromises nothing.

**Gate 3 — using a stolen session needs a chain-registered device.** Even if a session is phished (§3), the broker's cap-mint re-checks that the requesting **device key (K10) is registered on chain for that actor** (the per-actor isolation invariants → `DeviceBindingMismatch` otherwise; [`arch.md`](../arch.md) §3 + the broker `mint_cap` checks). The attacker's device isn't registered for your actor → **cap-mint fails → no credentials, no memory, no payments.**

**Gate 4 — registering a device needs your hardware passkey (K11).** To get past Gate 3 the attacker would have to register their device on chain — a **master mutation**, which [`arch.md`](../arch.md) §3 / §4 require to carry a **K11 (Touch ID / Hello / StrongBox) assertion** sealed in your hardware. They don't have it. Dead end.

---

## 3. What a phished magic-link can — and can't — reach

The one residual is the class every email login shares: **magic-link phishing (session fixation).** The attacker starts *their own* email request for your address, tricks you into clicking *their* link, and polls *their* request to obtain a session for your identity.

What that session is, and isn't:

- **Is:** a low-authority identity bearer — and per Gate 3 it is *device-less*, so it can't even mint caps. Time-bounded (J1 TTL), scope-bounded, and every action is re-verified against on-chain scope by the workers and is auditable.
- **Is not:** any of your keys. K10 / K11 / K3 / KEK never leave the daemon / Secure Enclave / signer TEE. The attacker cannot read your credentials or memory (Gate 3), cannot change scope, bind a device, or rotate keys (Gate 4), and cannot persist.

This maps exactly to the [`arch.md`](../arch.md) §3 attacker matrix: a *stolen J1 alone* is only dangerous **paired with a stolen, chain-registered K10** — which stays in your daemon.

> **Note on re-login / re-testing.** Encryption survives logins because the KEK is `HKDF(K3, actor_omni)` and `actor_omni` is **frozen at the first managed-wallet attestation** ([`arch.md`](../arch.md) §6). Re-logging-in with the *same email* keeps the same anchor (same S3 paths, same KEK); only J1 re-mints. The device key K10 is reused from the keychain — the on-chain device registration is the one irreversible step, kept idempotent (skip-if-registered).

---

## 4. How we bound the residual

The phishing class is inherent to email login, but we shrink it on several axes:

- **The daemon holds J1; the browser never receives it** — so even XSS or a malicious frontend running in your own browser has no bearer to exfiltrate.
- **Origin / same-site gate on `/v1/auth/email/start`** — defense-in-depth on top of CORS, so only the local app can trigger the email.
- **Broker-side (recommended): bind + match-code.** Bind the magic link to the originating request with a short TTL, and show a **match code** in the email that must equal a code shown on the originating device — this defeats blind-click phishing, because the attacker's request carries a *different* code. Plus "login requested from `<origin>` at `<time>` — ignore if this wasn't you" copy.
- **The chain + worker floor** — the ultimate backstop: no session can exceed on-chain scope (every cap is re-verified by the worker), and no master mutation happens without K11.

---

## 5. Summary

| Attack step | Possible? | Why it's contained |
|---|---|---|
| Read / clone the open-source frontend | yes | it's keyless — nothing sensitive to learn |
| Malicious clone drives *your* daemon | **no** | localhost-bound + CORS + JSON preflight |
| Trigger a magic-link email to you | yes (public) | harmless on its own |
| Phish your click → steal a session | yes (generic email-login risk) | bounded: device-less, scope-/TTL-bounded, auditable |
| Use that session to read credentials / memory | **no** | cap-mint needs a chain-registered device (Gate 3) |
| Register a device / change scope / persist | **no** | needs your hardware passkey K11 (Gate 4) |
| Obtain K10 / K11 / K3 / KEK | **no** | live only in the daemon keychain / Secure Enclave / signer TEE |

**Bottom line:** open-sourcing the frontend is safe because the frontend was never where the security lives. Authority sits in a *chain-registered device* plus your *hardware passkey* — exactly the two things a remote attacker cannot obtain — and the browser is a deliberately keyless, low-authority remote control. See [Key Security](key-security) for client-side storage hardening and [Blockchain TEE Architecture §7](blockchain-tee-architecture#7-security-model-assumptions-and-attacker-surface) for the full server-side attacker matrix.
