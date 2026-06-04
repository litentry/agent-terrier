The K11 WebAuthn ceremony at AgentKeys binds master-only mutations (scope grant/revoke, device add/revoke, K10 rotation, recovery) to a hardware-attested Touch ID / Face ID / Windows Hello assertion. Without operator-readable text on the confirmation page, the operator sees only the 32-byte challenge hex and has to trust the daemon that the bytes mean what it claims — exactly the same "agent signed `0xdead…beef` without me knowing what it was" failure mode that arch.md §15.3a calls out for typed-data signs.

This page is the design rationale + integration recipe for the K11 confirmation page's intent block. See [`crates/agentkeys-cli/src/k11_webauthn.rs`](../../crates/agentkeys-cli/src/k11_webauthn.rs) for the implementation.

## The OS-level constraint

WebAuthn's platform-authenticator prompt (the OS modal that triggers Touch ID / Face ID) is **fixed by the platform**. macOS shows "Use Touch ID for `http://companion.localhost:50342`?" — literally just the origin and the action verb. **Apple, Microsoft, Google do not expose an API for an application to inject custom text into the OS prompt.** This is by design — the OS doesn't trust application-supplied strings inside its trust-boundary UI.

The cryptographic signature is over a 32-byte challenge value (`PublicKeyCredentialRequestOptions.challenge`). Whatever the application wants to authorize must be hashed into those 32 bytes, and `clientDataJSON` (which the authenticator signs alongside the challenge) records the literal challenge bytes + origin + type. The signature is therefore bound to "this 32-byte commitment from this origin at this moment" — and not to any natural-language meaning of those bytes.

## Where AgentKeys closes the gap

Since the OS prompt can't render intent, the **localhost confirmation page** that AgentKeys serves before triggering `navigator.credentials.get()` is the only surface where intent rendering can happen. The browser tab shows:

1. **Role badge** — `🔑 PRIMARY MASTER` (blue) or `🛡️ COMPANION MASTER` (purple) so the operator knows which credential is about to be exercised.
2. **RP-ID callout** — "About to sign with the passkey bound to `localhost`. Make sure the Touch ID prompt shows this RP." (defends against the operator tapping the OS prompt when the wrong tab has focus).
3. **Intent block (NEW — this page's subject)** — operator-readable text about what's being authorized + per-field rows.
4. **Operator + RP-ID + Challenge-raw section** — the cryptographic primitives, raw. Auditors verify these.
5. **Big "Sign as PRIMARY MASTER" button** — only the operator's click triggers `navigator.credentials.get()`. The OS prompt fires AFTER the click, not before.

The operator's eyes between steps 3 and 5 are the load-bearing safety check. The page's content is daemon-controlled; the daemon proves to the operator (via the intent text) what bytes are being signed, and the operator confirms by clicking + tapping. If the intent text doesn't match what the operator expects, they close the tab + investigate.

## The intent block

Rendered as a CSS-bordered section above the raw challenge block, the intent block has three parts:

1. **Header**: `You are about to authorize:` in small-caps, role-accent-color.
2. **Headline** (`intent.text`): one-line plain-English description. Example: `"Grant agent demo-agent access to openrouter"`, `"Approve USDC 1000 to Uniswap v4 router"`, `"Revoke companion master device 0xabcd…1234"`.
3. **Per-field rows** (`intent.fields`): `(label, value)` pairs. Common rows: service, agent, K3 epoch, max_calls, expires_at.
4. **Caveat** (static): "Review the above BEFORE pressing Sign. The Touch ID prompt itself cannot show this text — your eyes are the last line of defense."

The headline + fields are HTML-escaped before interpolation — a malicious daemon-supplied intent string cannot inject `<script>` to manipulate the page (see [`html_escape`](../../crates/agentkeys-cli/src/k11_webauthn.rs) + the `html_escape_neutralizes_script_injection` test).

## Public API

[`crates/agentkeys-cli/src/k11_webauthn.rs`](../../crates/agentkeys-cli/src/k11_webauthn.rs) exposes:

```rust
pub struct K11IntentContext {
    pub text: Option<String>,
    pub fields: Vec<(String, String)>,
}

pub async fn assert_webauthn_with_intent(
    operator_omni: &str,
    message: &[u8],
    rp_id: &str,
    intent: K11IntentContext,
) -> Result<Vec<u8>, WebauthnError>;

pub async fn assert_webauthn_for_chain_with_intent(
    operator_omni: &str,
    expected_challenge: [u8; 32],
    rp_id: &str,
    intent: K11IntentContext,
) -> Result<K11ChainAssertion, WebauthnError>;
```

The legacy entry points (`assert_webauthn`, `assert_webauthn_with_rp`, `assert_webauthn_for_chain`) still work — they pass `K11IntentContext::empty()` internally and the page renders without the intent block, matching the pre-existing behavior. New call sites should prefer the `_with_intent` variants so the operator sees what they're signing.

## Caller pattern — scope grant example

```rust
use agentkeys_cli::k11_webauthn::{assert_webauthn_for_chain_with_intent, K11IntentContext};

let intent = K11IntentContext {
    text: Some(format!(
        "Grant agent {} access to {}",
        agent_label, service
    )),
    fields: vec![
        ("Agent omni".into(), format!("0x{}", &agent_omni_hex[..8] + "…" + &agent_omni_hex[56..])),
        ("Service".into(), service.into()),
        ("Max calls / hour".into(), max_calls.to_string()),
        ("K3 epoch".into(), k3_epoch.to_string()),
        ("Expires".into(), format_unix_iso8601(expires_at)),
    ],
};

let assertion = assert_webauthn_for_chain_with_intent(
    &operator_omni,
    expected_challenge,  // 32-byte commitment the chain contract recomputes
    "localhost",
    intent,
).await?;
```

The operator's tab now shows:

```
🔑 PRIMARY MASTER
K11 assertion
Original device authorizing a master-mutation.

[About to sign with the passkey bound to localhost. …]

YOU ARE ABOUT TO AUTHORIZE:
Grant agent demo-agent access to openrouter

  Agent omni       0xb3224706…cc999E02
  Service          openrouter
  Max calls / hour 100
  K3 epoch         1
  Expires          2026-06-20T22:13:20Z

Review the above BEFORE pressing Sign. The Touch ID prompt itself cannot
show this text — your eyes are the last line of defense between the daemon's
claim and the signature.

Operator        0xb3224706f0e33d6b…
RP ID           localhost
Challenge (raw) 0xdead…beef    ← 32-byte commitment — what WebAuthn actually signs

[ Sign as PRIMARY MASTER ]
```

## Cryptographic binding (unchanged)

The `intent` parameter is **display-only**. The cryptographic binding is still:

```
challenge_bytes = sha256(message)     # legacy assert path
                  | expected_challenge   # chain-bound assert path

clientDataJSON  = {"type":"webauthn.get","challenge":b64url(challenge_bytes),"origin":"..."}
authData        = rpIdHash || flags || signCount
signature       = ECDSA-P256(sha256(authData || sha256(clientDataJSON)))
```

The 32-byte challenge is what gets signed by the platform authenticator. The intent text is OUTSIDE the signed payload — adding it doesn't change any existing signature consumer (broker / on-chain `K11Verifier` / audit-row verifier).

## Audit binding — intent_commitment

For master mutations that ALSO emit an audit envelope (per [`audit-envelope-add-op-kind.md`](./audit-envelope-add-op-kind.md)), the same intent string fed to the WebAuthn page SHOULD also populate `AuditEnvelope.intent_text` + `AuditEnvelope.intent_commitment`. The audit-row commitment is:

```
intent_commitment = keccak256(intent_text || 0x7c || op_payload_digest)
```

Auditors later verifying the audit row re-render the intent from the same source (e.g. an ERC-7730 file for typed-data signs, or the contract-side `setScopeWithWebauthn` params for a scope grant) and check the commitment matches. This binds **the operator saw text T, and the audit row commits to T** — closes the "what did the operator actually see?" forensics gap.

```rust
use agentkeys_core::audit::{commit_intent, AuditEnvelope, AuditOpKind};

let intent_text = format!("Grant agent {} access to {}", agent_label, service);
let intent_commitment = commit_intent(&intent_text, &challenge_bytes);

// 1. Show on WebAuthn page (operator sees text T).
let intent = K11IntentContext {
    text: Some(intent_text.clone()),
    fields: vec![/* ... */],
};
let assertion = assert_webauthn_for_chain_with_intent(/* ... */, intent).await?;

// 2. Emit audit envelope (commits to text T).
let envelope = envelope_for(
    actor_omni_bytes,
    operator_omni_bytes,
    AuditOpKind::ScopeGrant,
    ScopeGrantBody { /* ... */ },
    AuditResult::Success,
    Some(intent_text),        // ← same string
    Some(intent_commitment),  // ← same commitment
)?;
audit_client.append(&envelope).await?;
```

The chain commitment hash matches the WebAuthn-displayed text by construction. Operators using a future explorer ([subscan-essentials#12](https://github.com/litentry/subscan-essentials/issues/12)) can replay this verification offline.

## When to provide an intent

| Call site | Provide intent? | Why |
|---|---|---|
| Scope grant / revoke | ✅ Yes | Master-mutation; operator must see which agent + service. |
| Device add / revoke | ✅ Yes | Master-mutation; operator must see which device hash + role bits. |
| K10 rotation | ✅ Yes | Master-mutation; operator must see old device → new device. |
| Recovery (M-of-N) | ✅ Yes | Master-mutation; operator must see what's being revoked. |
| Typed-data sign (ERC-7730) | ✅ Yes | Use the rendered `intent.text` from `clear_signing::build_preview`. |
| Audit-row direct mint | ✅ Yes | Operator must see what op the audit row attests to. |
| K11 enrollment (first-time) | ❌ No | The page already has static "you're enrolling a passkey for AgentKeys" header; no per-call intent. |
| Internal test fixtures | ❌ No | Use the legacy entry points with no intent. |

Rule of thumb: **if the K11 assertion authorizes anything an operator could meaningfully be tricked into authorizing, provide an intent.** When in doubt, provide it — operators tolerate "extra explanation" far better than "blind hash signing."

## Tests

[`crates/agentkeys-cli/src/k11_webauthn.rs::tests`](../../crates/agentkeys-cli/src/k11_webauthn.rs):

- `html_escape_neutralizes_script_injection` — malicious daemon-supplied intent rendered as text, not JS.
- `html_escape_handles_quote_chars` — quote/apostrophe escape correctness.
- `html_escape_passes_safe_text_through` — innocuous text unchanged.
- `k11_intent_context_empty_is_default` — legacy callers get the no-intent rendering.
- `k11_intent_context_with_text_is_not_empty` — sanity check on the constructor.

End-to-end visual verification: open the K11 confirmation page during `harness/v2-stage1-demo.sh --webauthn`; the intent block renders above the challenge hex.

## Cross-references

- [`wiki/k11-intent-conventions.md`](./k11-intent-conventions.md) — **content convention** for what the intent text + rows MUST contain, per-operation canonical headline table, and the uniformity rule across all K11-emitting sites (the rule this page's mechanism enforces).
- [`docs/arch.md`](../arch.md) §10.1 — master init + K11 binding.
- [`docs/arch.md`](../arch.md) §15.3a — `AuditEnvelope` intent_text + intent_commitment fields.
- [`crates/agentkeys-cli/src/k11_webauthn.rs`](../../crates/agentkeys-cli/src/k11_webauthn.rs) — implementation.
- [`crates/agentkeys-core/src/audit/mod.rs`](../../crates/agentkeys-core/src/audit/mod.rs) — `commit_intent` helper (mirror of `clear_signing::commit_intent`).
- [`crates/agentkeys-core/src/clear_signing/`](../../crates/agentkeys-core/src/clear_signing) — ERC-7730 typed-data preview that supplies the intent text for typed-data signs.
- [`wiki/audit-envelope-add-op-kind.md`](./audit-envelope-add-op-kind.md) — process for adding a new audit op_kind (every new master-mutation op_kind should also wire `assert_webauthn_*_with_intent`).
