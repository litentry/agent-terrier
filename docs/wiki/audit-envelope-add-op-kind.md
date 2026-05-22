# Adding a new audit op_kind

This is the operator-facing detailed guide for extending the AgentKeys audit envelope with a new op_kind. Defers to [`docs/arch.md`](../arch.md) §15.3a (canonical schema + 8 non-break invariants) and §15.3b (the 5-step ritual). This page walks through a worked example + the complete PR checklist.

## The current op design (one-paragraph recap)

Every audit-producing surface in AgentKeys (creds, memory, signer, broker, payment-service, email-service, SidecarRegistry, K3EpochCounter) emits a single canonical envelope shape — `AuditEnvelope v1`. The envelope is encoded as deterministic CBOR (RFC 8949 §4.2.1), addressed by `envelope_hash = keccak256(canonical_cbor(envelope))`. The worker (`agentkeys-worker-audit`) stores the full envelope; the chain (`CredentialAudit.appendV2`) commits only `(opKind, envelopeHash)` as an indexed event. An explorer reads chain events, fetches envelopes by hash, renders per-op_kind. New op_kinds add a row to a canonical table in arch.md §15.3a + a Rust variant + a typed body struct — and that's it. The chain contract never decodes `op_body` (op-kind-agnostic), so new op_kinds need ZERO contract redeploys.

## Worked example: adding `PaymentRefund` (byte 32)

Suppose the payment-service ([`crates/agentkeys-worker-payment`](../../crates/agentkeys-worker-payment) — hypothetical) now supports refund flows. The existing payment family has `PaymentEscrowRedeem=30` and `PaymentDirect=31`. We claim byte `32` for `PaymentRefund`.

### Step 1 — pick the byte

```
Family: payments (30-39 reserved)
Used:   30=PaymentEscrowRedeem, 31=PaymentDirect
Pick:   32=PaymentRefund
```

Reserved-but-unused bytes in the payments family: 33-39. Use the lowest unused.

### Step 2 — append the row to arch.md §15.3a canonical op_kind table

Edit [`docs/arch.md`](../arch.md) — find the canonical table in §15.3a, append (do NOT reorder existing rows):

```markdown
| `PaymentRefund` | 32 | `{original_op_envelope_hash: [u8;32], reason_code: u8, amount_returned: U256}` | payment-service |
```

The schema column lists every field in the typed `op_body`. Naming convention: snake_case field names, byte arrays as `[u8;N]`, big integers as `U256` (string-encoded over the wire to survive JSON `i53` limits).

### Step 3 — add the Rust variant

Three files in [`crates/agentkeys-core/src/audit/`](../../crates/agentkeys-core/src/audit):

**[`op_kind.rs`](../../crates/agentkeys-core/src/audit/op_kind.rs):**

```rust
pub enum AuditOpKind {
    // … existing variants …
    PaymentEscrowRedeem = 30,
    PaymentDirect = 31,
    PaymentRefund = 32,  // ← new
    // … rest …
}

impl AuditOpKind {
    pub fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            // … existing arms …
            31 => Self::PaymentDirect,
            32 => Self::PaymentRefund,  // ← new
            // … rest …
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            // … existing arms …
            Self::PaymentDirect => "payment.direct",
            Self::PaymentRefund => "payment.refund",  // ← new
            // … rest …
        }
    }
}
```

**[`bodies.rs`](../../crates/agentkeys-core/src/audit/bodies.rs):**

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentRefundBody {
    /// envelope_hash of the original PaymentEscrowRedeem / PaymentDirect
    /// envelope being refunded. 0x-prefixed 64-hex (32 raw bytes).
    pub original_op_envelope_hash: String,
    /// Refund reason — small open-enum byte: 0=customer_initiated,
    /// 1=service_initiated, 2=chargeback, 3=fraud, 4-255=reserved.
    pub reason_code: u8,
    /// Amount returned in the chain's native units (string-encoded U256).
    pub amount_returned: String,
}
```

And re-export from `bodies::*` at the top of [`mod.rs`](../../crates/agentkeys-core/src/audit/mod.rs):

```rust
pub use bodies::{
    // … existing exports …
    PaymentDirectBody,
    PaymentRefundBody,  // ← new
    PaymentEscrowRedeemBody,
    // … rest …
};
```

**[`mod.rs`](../../crates/agentkeys-core/src/audit/mod.rs) — `TypedAuditBody` enum + decoder:**

```rust
pub enum TypedAuditBody {
    // … existing variants …
    PaymentEscrowRedeem(PaymentEscrowRedeemBody),
    PaymentDirect(PaymentDirectBody),
    PaymentRefund(PaymentRefundBody),  // ← new
    // … rest …
}

impl TypedAuditBody {
    fn from_envelope(env: &AuditEnvelope) -> Option<Self> {
        // … existing arms …
        Some(match kind {
            // … existing arms …
            AuditOpKind::PaymentDirect => {
                Self::PaymentDirect(serde_json::from_value(value).ok()?)
            }
            AuditOpKind::PaymentRefund => {  // ← new
                Self::PaymentRefund(serde_json::from_value(value).ok()?)
            }
            // … rest …
        })
    }
}
```

### Step 4 — wire the emit site

In the payment-service worker (e.g. [`crates/agentkeys-worker-payment/src/handlers.rs`](../../crates/agentkeys-worker-payment) — hypothetical):

```rust
use agentkeys_core::audit::{
    AuditClient, AuditOpKind, AuditResult, PaymentRefundBody, envelope_for,
};

async fn handle_refund(&self, req: RefundRequest) -> Result<RefundResponse, _> {
    // … do the refund work …
    let result = self.execute_refund(&req).await;

    // Emit audit envelope on success OR failure (both are audit-worthy).
    let envelope = envelope_for(
        req.actor_omni_bytes(),
        req.operator_omni_bytes(),
        AuditOpKind::PaymentRefund,
        PaymentRefundBody {
            original_op_envelope_hash: format!("0x{}", hex::encode(req.original_hash)),
            reason_code: req.reason_code,
            amount_returned: req.amount.to_string(),
        },
        match &result {
            Ok(_) => AuditResult::Success,
            Err(_) => AuditResult::Failure,
        },
        Some(format!("Refund {} to {}", req.amount, req.recipient)),
        // intent_commitment = keccak256(intent_text || 0x7c || op_payload_digest)
        // op_payload_digest here is the original_op_envelope_hash (binds refund to the op being refunded).
        Some(agentkeys_core::audit::commit_intent(
            &format!("Refund {} to {}", req.amount, req.recipient),
            &req.original_hash,
        )),
    )?;

    let client = AuditClient::from_env();
    let _ = client.append(&envelope).await;  // emit-and-forget

    result
}
```

The worker stores the envelope by hash. Later (batched or immediate), the same worker — or a sidecar emitter — calls `CredentialAudit.appendV2(operator_omni, actor_omni, op_kind=32, envelope_hash)` on chain. The explorer reads the chain event, fetches the envelope from the worker, renders per the new `PaymentRefundBody` shape.

### Step 5 — ship the three required tests

**Test A — worker CBOR roundtrip** in [`crates/agentkeys-core/src/audit/bodies.rs`](../../crates/agentkeys-core/src/audit/bodies.rs):

```rust
#[test]
fn payment_refund_body_roundtrips() {
    let body = PaymentRefundBody {
        original_op_envelope_hash: format!("0x{}", "de".repeat(32)),
        reason_code: 1,
        amount_returned: "1500000000000000000".to_string(),  // 1.5 in 18-decimals
    };
    let json = serde_json::to_value(&body).unwrap();
    let decoded: PaymentRefundBody = serde_json::from_value(json).unwrap();
    assert_eq!(body, decoded);
}
```

**Test B — explorer Unknown(byte) fallback** in [`subscan-essentials`](https://github.com/litentry/subscan-essentials):

A unit test that crafts an envelope with `op_kind=32` against an older explorer build (one that doesn't yet know about `PaymentRefund`), confirms the indexer:
- Stores the envelope without crashing.
- Renders the row as `Unknown(32)` with envelope-level fields visible (actor, operator, timestamp, intent_text).
- Does NOT 5xx or drop the event.

**Test C — arch.md row uniqueness check.** This is enforced from the Rust side already by [`audit::op_kind::tests::all_byte_values_unique`](../../crates/agentkeys-core/src/audit/op_kind.rs) — adding the new variant at byte 32 will fail this test if 32 was already claimed. Keep the doc + code in sync; the test is the regression guard.

## Explorer-side update (parallel track, separate repos)

The agentKeys-side PR ships independently of the explorer-side PR — that's the whole point of the [non-break design](../arch.md) §15.3a invariant #4 (the explorer always renders `Unknown(byte)` fallback for op_kinds it doesn't recognize yet). Until the explorer-side PR lands, operators see a generic row instead of a typed one; nothing crashes, nothing is dropped.

The explorer work lives in **two separate GitHub repos** with their own PR / review / deploy cadence:

- **[`litentry/subscan-essentials`](https://github.com/litentry/subscan-essentials)** (Go) — indexer + REST API.
- **[`litentry/subscan-essentials-ui-react`](https://github.com/litentry/subscan-essentials-ui-react)** (React/TypeScript) — UI renderer.

Track follow-ups against [subscan-essentials#12](https://github.com/litentry/subscan-essentials/issues/12) — the umbrella issue for Phases D + E.

### A. Indexer decoder ([`litentry/subscan-essentials`](https://github.com/litentry/subscan-essentials))

Continuing the `PaymentRefund` (byte 32) example:

#### A1. Register the op_kind in the decoder table

`indexer/agentkeys/op_kinds.go` (or equivalent) — add a row to the byte→handler map:

```go
var OpKindDecoders = map[uint8]OpKindDecoder{
    // … existing entries …
    30: &PaymentEscrowRedeemDecoder{},
    31: &PaymentDirectDecoder{},
    32: &PaymentRefundDecoder{},  // ← new
    // … rest …
}
```

#### A2. Implement the typed decoder

`indexer/agentkeys/payment_refund.go`:

```go
type PaymentRefundDecoder struct{}

func (d *PaymentRefundDecoder) OpKind() uint8     { return 32 }
func (d *PaymentRefundDecoder) Label() string     { return "payment.refund" }

// Body shape — fields must match the arch.md §15.3a canonical table row
// for byte 32 EXACTLY. Any drift is a non-break-invariant violation.
type PaymentRefundBody struct {
    OriginalOpEnvelopeHash string `cbor:"original_op_envelope_hash" json:"original_op_envelope_hash"`
    ReasonCode             uint8  `cbor:"reason_code"               json:"reason_code"`
    AmountReturned         string `cbor:"amount_returned"           json:"amount_returned"`  // string-encoded U256
}

// Decode parses the CBOR-encoded op_body Map into the typed shape.
// Returns ErrUnknownFields if the body has fields outside the schema
// (catches drift between explorer + arch.md).
func (d *PaymentRefundDecoder) Decode(opBody cbor.RawMessage) (any, error) {
    var body PaymentRefundBody
    if err := cbor.Unmarshal(opBody, &body); err != nil {
        return nil, fmt.Errorf("payment_refund decode: %w", err)
    }
    return &body, nil
}

// REST shape — flattened JSON for the explorer's API consumers.
func (d *PaymentRefundDecoder) RestShape(body any) map[string]any {
    b := body.(*PaymentRefundBody)
    return map[string]any{
        "op_kind":                     "payment.refund",
        "original_op_envelope_hash":   b.OriginalOpEnvelopeHash,
        "reason_code":                 b.ReasonCode,
        "reason_label":                reasonCodeLabel(b.ReasonCode),  // 0=customer_initiated, etc.
        "amount_returned":             b.AmountReturned,
    }
}
```

#### A3. Wire the chain-event handler

The indexer's `AuditAppendedV2` event handler already does the generic flow (read `(operatorOmni, actorOmni, opKind, envelopeHash)`, fetch envelope by hash from the audit worker, dispatch on `opKind`). Adding the new op_kind just registers the decoder — no event-handler changes needed:

```go
// indexer/agentkeys/audit_v2_handler.go (existing, unchanged)
func (h *AuditV2Handler) Handle(ev AuditAppendedV2Event) error {
    cbor, err := h.workerClient.GetEnvelope(ev.EnvelopeHash)
    if err != nil { return err }

    decoder, ok := OpKindDecoders[ev.OpKind]
    if !ok {
        // Per non-break invariant #1, render as Unknown(byte). Don't drop, don't 5xx.
        return h.storeRow(ev, "unknown", map[string]any{
            "op_kind_byte": ev.OpKind,
            "op_body_b64":  base64.StdEncoding.EncodeToString(cbor.OpBody()),
        })
    }
    body, err := decoder.Decode(cbor.OpBody())
    if err != nil { return err }
    return h.storeRow(ev, decoder.Label(), decoder.RestShape(body))
}
```

#### A4. Test the explorer

Three tests minimum in subscan-essentials/`indexer/agentkeys/payment_refund_test.go`:

```go
// 1. Roundtrip — agentKeys-emitted envelope decodes correctly here.
func TestPaymentRefund_DecodesCanonicalFixture(t *testing.T) {
    // Use the SAME CBOR bytes from a Rust-side canonical fixture so
    // the cross-language hash determinism is exercised.
    cborHex := "…canonical fixture from agentkeys-core test…"
    body, err := (&PaymentRefundDecoder{}).Decode(mustHex(cborHex))
    require.NoError(t, err)
    require.Equal(t, "0x" + strings.Repeat("de", 32), body.(*PaymentRefundBody).OriginalOpEnvelopeHash)
}

// 2. Unknown-byte non-break — explorer doesn't crash on op_kind=250.
func TestUnknownOpKind_RendersFallback(t *testing.T) {
    ev := AuditAppendedV2Event{OpKind: 250, EnvelopeHash: …}
    err := handler.Handle(ev)
    require.NoError(t, err)  // MUST NOT error
    // Stored row should have op_kind_byte=250 and a raw op_body_b64.
}

// 3. Cross-language hash — explorer can verify the chain commitment.
func TestEnvelopeHash_MatchesRustImpl(t *testing.T) {
    cborBytes := mustHex("…fixture from agentkeys-core…")
    expected  := mustHex("…hash from Rust audit_module test…")
    require.Equal(t, expected, keccak256(cborBytes))
}
```

The third test is the load-bearing one: it proves the Rust + Go encoders produce byte-identical canonical CBOR (and therefore the same `envelope_hash`) for the same logical envelope. Without it, a subtle CBOR encoder drift could silently desynchronize chain commitments from worker envelopes.

### B. UI renderer ([`litentry/subscan-essentials-ui-react`](https://github.com/litentry/subscan-essentials-ui-react))

#### B1. Add a renderer component

`src/agentkeys/op_kinds/PaymentRefund.tsx`:

```tsx
import { OpKindRenderer } from './types';
import { Card, Field, AddressLink, AmountWithDecimals } from '../../ui';

export const PaymentRefundRenderer: OpKindRenderer = ({ envelope }) => {
  const body = envelope.op_body as {
    original_op_envelope_hash: string;
    reason_code: number;
    reason_label: string;
    amount_returned: string;
  };
  return (
    <Card title="Payment Refund">
      <Field label="Original op">
        <EnvelopeHashLink hash={body.original_op_envelope_hash} />
      </Field>
      <Field label="Reason">{body.reason_label}</Field>
      <Field label="Amount returned">
        <AmountWithDecimals value={body.amount_returned} decimals={18} ticker="HEI" />
      </Field>
      <Field label="Intent">{envelope.intent_text ?? "—"}</Field>
      {/* Envelope-level fields always show, even for op-kinds the renderer doesn't know — see UnknownByteRenderer */}
      <Field label="Actor">       <AddressLink omni={envelope.actor_omni} /></Field>
      <Field label="Operator">    <AddressLink omni={envelope.operator_omni} /></Field>
      <Field label="When">        <RelativeTime ts={envelope.ts_unix} /></Field>
    </Card>
  );
};
```

#### B2. Register in the op_kind → renderer map

`src/agentkeys/op_kinds/registry.ts`:

```typescript
import { PaymentRefundRenderer } from './PaymentRefund';

export const OP_KIND_RENDERERS: Record<number, OpKindRenderer> = {
  // … existing entries …
  30: PaymentEscrowRedeemRenderer,
  31: PaymentDirectRenderer,
  32: PaymentRefundRenderer,  // ← new
  // … rest …
};
```

#### B3. Verify the Unknown(byte) fallback path

The UI's audit-row component dispatches via the registry. A missing entry MUST render `<UnknownByteRenderer />` (which shows envelope-level fields + the op_kind byte + a raw `op_body` expander). Add a Storybook story that renders an envelope with `op_kind=250` and an unknown body — the story is the visual regression guard.

### C. Shared cross-language test vectors

To prevent encoder drift between Rust (agentKeys), Go (subscan-essentials), and TypeScript (subscan-essentials-ui-react), maintain a small **shared test-vector file** that all three repos consume:

- Location (canonical): [`crates/agentkeys-core/src/audit/test-vectors/`](../../crates/agentkeys-core/src/audit/) (TBD — to be added in a follow-up PR alongside the next new op_kind).
- Format: JSON files, one per op_kind, with `{envelope_json, canonical_cbor_hex, envelope_hash_hex}`.
- All three repos read these files and verify their encoder produces matching `canonical_cbor_hex` + `envelope_hash_hex` from the JSON.

Tracked in [subscan-essentials#12](https://github.com/litentry/subscan-essentials/issues/12). Until the test vectors land, the cross-language determinism is verified ad-hoc per op_kind (Test #3 in §A4 above).

### Phasing

The explorer-side PRs are **deliberately asynchronous** with the agentKeys-side PR:

| | T=0 (agentKeys PR ships) | T+days (subscan PR ships) | T+more (UI PR ships) |
|---|---|---|---|
| Operator emit-site | Emits new op_kind ✅ | (unchanged) | (unchanged) |
| Chain event log | `AuditAppendedV2(opKind=32, ...)` ✅ | (unchanged) | (unchanged) |
| Worker `/v1/audit/envelope/<hash>` | Returns canonical CBOR ✅ | (unchanged) | (unchanged) |
| Indexer REST API | `op_kind=32 → unknown` row | `op_kind=32 → payment.refund` typed ✅ | (unchanged) |
| Operator-facing UI | Generic `Unknown(32)` card | Generic card | Typed `PaymentRefund` card ✅ |

At every column, nothing crashes, nothing is dropped, and the chain commitment is verifiable. The only visible-to-operator change between columns is "uglier UI temporarily for old explorers" — exactly the trade-off captured in the 8 non-break invariants.

## PR checklist

Three parallel PRs total — one against agentKeys, one against subscan-essentials, one against subscan-essentials-ui-react. The first ships independently; the latter two can land afterward on their own cadence (per the non-break design — old explorers gracefully degrade to `Unknown(byte)`).

### agentKeys-side PR ([`litentry/agentKeys`](https://github.com/litentry/agentKeys))

- [ ] Bytes claimed in the right family range; never reused; never reordered.
- [ ] [`docs/arch.md`](../arch.md) §15.3a canonical table row appended.
- [ ] [`crates/agentkeys-core/src/audit/op_kind.rs`](../../crates/agentkeys-core/src/audit/op_kind.rs) variant + `from_u8` arm + `label` arm added.
- [ ] [`crates/agentkeys-core/src/audit/bodies.rs`](../../crates/agentkeys-core/src/audit/bodies.rs) typed body struct + serde derives + (optional) roundtrip test.
- [ ] [`crates/agentkeys-core/src/audit/mod.rs`](../../crates/agentkeys-core/src/audit/mod.rs) `TypedAuditBody` variant + `from_envelope` arm + re-export.
- [ ] Emit site wired in the appropriate worker / broker / signer / hook.
- [ ] `cargo test -p agentkeys-core --lib audit` passes (the `all_byte_values_unique` test catches collisions).
- [ ] `ENVELOPE_VERSION` UNCHANGED — adding an op_kind never bumps the envelope version.
- [ ] Cross-language test-vector file added/updated (see §C above) so the explorer can pin against the same canonical CBOR + hash.

### Indexer-side PR ([`litentry/subscan-essentials`](https://github.com/litentry/subscan-essentials))

- [ ] Op_kind registered in the byte→decoder map (`indexer/agentkeys/op_kinds.go`).
- [ ] Typed `XxxDecoder` implementing `OpKind() / Label() / Decode() / RestShape()` (per §A2 above).
- [ ] Three tests in `_test.go`: canonical-fixture decode, unknown-byte non-break, cross-language hash match against the shared test vector.
- [ ] REST shape documented — what JSON fields the explorer surfaces for this op_kind.
- [ ] No changes to the generic `AuditAppendedV2` event handler (the dispatch table change is the only wiring; the handler stays op-kind-agnostic).
- [ ] Companion subscan-essentials issue referenced ([subscan-essentials#12](https://github.com/litentry/subscan-essentials/issues/12)).

### UI-side PR ([`litentry/subscan-essentials-ui-react`](https://github.com/litentry/subscan-essentials-ui-react))

- [ ] New `<XxxRenderer />` component (per §B1 above) that displays the body fields in human-readable form.
- [ ] Component registered in `OP_KIND_RENDERERS` map (per §B2).
- [ ] Storybook story for the new renderer + a story for `<UnknownByteRenderer />` against the same op_kind (verifies the fallback path stays functional).
- [ ] Visual regression check passes — the new op_kind row should look consistent with sibling op_kinds in the same family.
- [ ] No changes to the audit-row dispatcher — adding the renderer is purely additive.

## What you DON'T need to do

- ❌ **Redeploy `CredentialAudit.sol`.** The contract is op-kind-agnostic. New op_kinds need ZERO contract redeploys.
- ❌ **Bump `ENVELOPE_VERSION`.** That field is reserved for envelope-level breakage (adding / removing top-level fields). New op_kinds stay at v1.
- ❌ **Migrate existing envelopes.** The new op_kind is additive — pre-existing envelopes are unaffected.
- ❌ **Coordinate a synchronous rollout across all components.** The non-break design is asynchronous: workers can emit new op_kinds immediately; old explorers gracefully `Unknown(byte)`-render; new explorers ship later with the typed renderer. Each component upgrades on its own cadence.

## K11 WebAuthn intent rendering (for master-mutation op_kinds)

If your new op_kind authorizes a master mutation (scope, device, K10 rotation, recovery), the call site MUST also call `assert_webauthn_*_with_intent` so the operator sees a human-readable intent on the K11 confirmation page — not just the 32-byte challenge hex. The same `intent_text` value populates both the WebAuthn page AND the audit envelope's `intent_text` + `intent_commitment` fields, so the chain commitment binds to exactly what the operator saw.

See [`wiki/k11-webauthn-intent-rendering.md`](./k11-webauthn-intent-rendering.md) for the full design + worked examples.

## Where to look for cross-references

- [`docs/arch.md`](../arch.md) §15.3a — canonical schema, op_kind table, 8 non-break invariants, 6-phase migration plan.
- [`docs/arch.md`](../arch.md) §15.3b — the 5-step ritual (a more concise summary of this page).
- [`crates/agentkeys-core/src/audit/mod.rs`](../../crates/agentkeys-core/src/audit/mod.rs) — `AuditEnvelope` struct + `commit_intent` helper.
- [`crates/agentkeys-core/src/audit/client.rs`](../../crates/agentkeys-core/src/audit/client.rs) — `AuditClient` HTTP wrapper + `envelope_for` builder.
- [`crates/agentkeys-chain/src/CredentialAudit.sol`](../../crates/agentkeys-chain/src/CredentialAudit.sol) — `appendV2` + `appendRootV2` on-chain surface.
- [agentKeys#97](https://github.com/litentry/agentKeys/issues/97) — implementation tracking issue for Phases B + C + F.
- [subscan-essentials#12](https://github.com/litentry/subscan-essentials/issues/12) — explorer tracking issue for Phases D + E.
