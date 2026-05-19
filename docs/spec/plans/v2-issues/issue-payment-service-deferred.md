# GH issue body — payment-service worker (deferred from v2 main scope)

**Title**: payment-service worker — deferred from v2 main scope

**File via**:
```bash
gh issue create \
  --title "payment-service worker — deferred from v2 main scope" \
  --label "documentation,enhancement" \
  --body-file docs/spec/plans/v2-issues/issue-payment-service-deferred.md
```

---

Track payment-service design + implementation as a follow-on to the v2 credential architecture. Deferred from stage 1 + stage 2 because payment is structurally different (irreversible upstream effects → requires different security primitives) and the design isn't on the critical path for v2 credential storage.

## Why deferred

The v2 credential architecture (stages 1 + 2) handles **reversible** upstream operations (LLM API calls, memory R/W, audit appends, email send). Payment is the only **irreversible** category — a USDC transfer or Stripe charge can't be unsent. This requires:
- Strict one-shot CAS-burn cap-tokens (vs TTL-bounded multi-use caps for other workers)
- Tight per-cap + per-period quotas enforced at multiple layers
- Distinct wallet-exposure model (operator can choose: service-pool, escrow, or direct)

These constraints justify treating payment-service as its own design + implementation track.

## Three operational modes

| Mode | Wallet that signs payments | master_wallet on chain? | Trust model | Best for |
|---|---|---|---|---|
| **P-1 — Service-account-wallet** (default) | Service-operated payment-pool wallet; operator pre-deposits funds | Once at deposit, then never | Operator trusts service-wallet operator with custody float; mitigate via multisig pool or TEE-attested smart contract | Routine LLM API payments (low value, high frequency) |
| **P-2 — On-chain escrow + signer-signed redemption** | Operator's master_wallet deposits to escrow contract once; payment-service redeems via signer-signed token | Once at deposit, then escrow contract is visible mover | Operator controls escrow; signer signs each redemption with operator's K3-derived key | Medium-value payments where operator wants self-custody without ongoing master_wallet exposure |
| **P-3 — Direct from operator wallet** | master_wallet directly signs each payment tx | EVERY payment | Operator fully custodial; payments fully transparent on chain | High-value one-off payments where on-chain transparency is required; operators who don't care about pseudonymity |

## Required security properties (all modes)

1. **Strict one-shot CAS-burn semantics** — Every payment cap carries a unique nonce. Broker mints, payment-service redeems with atomic CAS. Replay attempts return `cap_already_consumed`.
2. **Tight per-cap + per-period quotas** — Scope entry for payment-service includes `max_per_call` + `max_per_period` + `max_total`. Quotas enforced at broker on cap-mint AND at payment-service on cap-redeem (defense in depth).
3. **K11 user-presence required for high-value payments** — Operator-configurable threshold. Above it, cap-mint requires K11 WebAuthn assertion in addition to K10 device-key sig.

## Wire shape

```
payment-service /v1/pay
  Body: {
    cap: {request, k10_sig, broker_sig, k11_assertion_if_high_value},
    payment_intent: {recipient, amount, asset, idempotency_key, memo}
  }

payment-service:
  1. Verify cap signatures (K10 + broker_sig)
  2. If payment_intent.amount > operator.k11_threshold:
       verify cap.k11_assertion is present and valid over payment_intent hash
  3. CAS-burn cap.nonce against payment-service's burn-table
  4. Quota check: spend_window[operator_omni].current + amount <= scope.max_per_period
  5. Execute payment (mode-dependent):
     - P-1: charge service-pool wallet (multisig signs)
     - P-2: signer redeems escrow slot via signer-signed token
     - P-3: signer signs payment tx with operator's K3-derived key
  6. Record audit event: PaymentExecuted(operator_omni, recipient, amount, asset,
                                         idempotency_key, tx_hash, k3_epoch)
  7. Return receipt
```

## Dependencies

- Depends on: v2 stage 1 (sidecar + cap-token model + on-chain SidecarRegistry)
- Depends on: v2 stage 2 (K11 WebAuthn binding for high-value payment threshold)
- Optional: ZK-rollup escrow primitive for P-2 mode at scale

## Out of scope of this issue

- Specific upstream payment integrations (Stripe, USDC, etc.) — separate per-upstream issues
- Chain choice for escrow contract — operator deployment decision
- Multi-sig escrow contract design — separate issue once filed
