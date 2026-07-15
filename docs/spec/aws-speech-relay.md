# AWS speech plane — ASR/TTS through the cap→STS relay (#441)

**Status:** shipped with epic #439 (stack ②). **Scope:** the AWS stack only —
the VE stack's speech plane stays on the #386 gate-held app-token posture (its
minted STS is rejected by the Doubao Voice endpoints; `e2e/speech-sts-token-capability.sh`
is the tripwire that flips VE onto this posture the day Volcengine's tokens work).

## Shape

The epic's consistent-auth principle: every delegate-facing endpoint uses the
SAME cap-mint → short-TTL STS relay. Speech is a **compute plane** (no bucket,
no worker) so it takes the `/v1/cap/classify`-family shape with a broker-side
redeemer, mirroring `/v1/cap/canonical-sts`:

1. **Mint** — `POST /v1/cap/speech` (route statically fixes `op: SpeechUse`,
   `data_class: Speech`, **and** `service: "speech"`). Minting runs the full
   layer-1 gate: session==operator (or the actor-session family for delegates),
   device binding, the on-chain **`speech` grant** for cross-actor mints
   (master-self rides the #195 skip), K10 cap-PoP when supplied (#76),
   device→sandbox delegation (#369) passed through.
2. **Redeem** — `POST /v1/cap/speech-sts` (broker): re-verifies the cap
   (broker_sig, op/class/service, expiry, **actor==session**, #369 delegation
   re-check), mints an actor-tagged OIDC JWT INTERNALLY, AssumeRoles
   `SPEECH_ROLE_ARN` with an inline session policy pinning exactly
   `transcribe:StartStreamTranscription{,WebSocket}` + `polly:SynthesizeSpeech`,
   and returns 900s creds + the region.
3. **Consume** — `agentkeys speech creds` (JSON creds for an embedded client)
   / `agentkeys speech probe` (one REAL Polly synthesis + one REAL Transcribe
   stream on the relay creds — the acceptance check; the sandbox image ships
   this binary, so this is also the delegate consumption reference; the
   firmware voice path follows the same two calls).

## Why no `${aws:PrincipalTag}` layer here

Transcribe streaming + Polly synthesis have no per-actor AWS resources
(`Resource: *` by necessity), so layer 3 of the #90 defense stack does not
apply. The per-actor gate is layer 1 (the on-chain `speech` grant at cap-mint
+ actor==session at redemption); the STS session is still tagged with the
actor omni for CloudTrail attribution. Layer-2/4 don't exist (no worker, no
bucket) — the wrong-plane redemption negatives in `suite-3` step 25 pin the
boundary instead (a Speech cap is rejected by every storage worker via
`check_data_class`, and `/v1/cap/speech-sts` rejects every non-Speech cap).

## Pieces

| Piece | Where |
|---|---|
| Mint endpoint + enums | `crates/agentkeys-broker-server/src/handlers/cap.rs` (`CapOp::SpeechUse`, `DataClass::Speech`, `cap_speech`, `SPEECH_SERVICE`) |
| Redeem endpoint | `crates/agentkeys-broker-server/src/handlers/speech_sts.rs` |
| Wire types | `agentkeys-protocol` (`CapMintOp::SpeechUse`, `SpeechStsBody`, `SpeechStsResult`) |
| Client | `agentkeys-backend-client::BackendClient::speech_sts` |
| CLI / sandbox consumption | `crates/agentkeys-cli/src/speech.rs` (`agentkeys speech creds|probe`) |
| IAM role | `scripts/operator/cloud/provision-speech-role.sh` ← `setup-cloud.sh` **step 19** (wire-in rule); `SPEECH_ROLE_ARN` in all four AWS env files + the CI materializer |
| Broker config | `SPEECH_ROLE_ARN` env → `BrokerConfig::speech_role_arn` (unset ⇒ the redeem endpoint returns "not configured", no boot impact) |
| Regression gate | `e2e/suite-3-isolation.sh` step 25 — always-on cap-layer negatives: fixed-service 403 · **agent-signed** un-granted mint 403 (ServiceNotInScope) · wrong-plane cap 403 at speech-sts. The live two-leg probe is **opt-in** (`AGENTKEYS_SPEECH_PROBE=1`), like the VE suite's credentialed rungs |

## Testing the per-actor gate: the negative MUST be agent-signed

`SpeechUse` is in the broker's **actor-session** op family (`op_requires_actor_session`,
alongside #295 `CanonicalFetch`, #339 `Append`, #406 channel pub/sub): the
delegate mints with its OWN J1 and never holds the operator bearer. A
consequence that is easy to get wrong — and did fail CI once here — is that a
cross-actor negative presented on the **operator's** session is refused by the
*session* gate (`403 operator_mismatch`) **before** the on-chain `speech` scope
check is consulted. The assertion goes green while proving nothing about the
grant. The un-granted negative therefore SIWEs as the agent (`mint_cap_as`) so
the rejection is genuinely `ServiceNotInScope`. The storage ops (`memory-put`
et al.) are NOT actor-session, which is why their cross-actor negatives can and
do use the operator session — do not copy that template here.

## Grant model

One coarse on-chain service id **`speech`** (granted with the same scope
tooling as every service). Splitting ASR/TTS into `speech-asr` / `speech-tts`
later is a new-service addition, not a rename. The **provider** (Transcribe/
Polly today) stays behind the broker role + inline policy — swapping providers
is an IAM-policy + redeemer change, invisible to the cap surface.
