# Sponsored-gas credit & reimbursement model

**Status:** two layers, different maturity. The **on-chain gasless sponsorship** layer
is LIVE on Heima mainnet. The **off-chain prepaid-credit & reimbursement** layer
(fiat → credits → deposit top-up) is **DESIGN — not built**; this doc specs how it sits
on top of the live layer and where the two meet.

**Scope:** the technical structure only — how a credit-based business layer maps onto the
existing ERC-4337 sponsorship (paymaster / bundler / EntryPoint). **Explicitly out of
scope** (a separate concern, not addressed here and not legal/financial advice): foreign
exchange, KYC/AML, payment-rail integration, custody licensing, and any regulatory or tax
treatment of taking fiat and converting to crypto.

**Anchors:** [`arch.md`](../arch.md) (ERC-4337 master account + `agentkeys-bundler`),
[`chain-setup.md` §Wallets](../chain-setup.md#wallets-contracts--funding-map-prod--test)
(the funding map + tooling), [`deployed-contracts.md`](deployed-contracts.md).

## Which address do I fund? (read this first)

Two on-chain things hold/spend native gas, and they are funded by **two different
mechanisms**. Mixing them up is the #1 confusion — and a plain transfer to the paymaster
**loses the funds**.

[![Which address do I fund? — the sponsor/bundler EOA (plain transfer) vs the paymaster deposit (deposit()), with the runtime flow and the plain-transfer-to-paymaster footgun](../assets/gas-funding-map.svg)](../assets/gas-funding-map.svg)

| # | Fund THIS | Address | How — the ONLY correct way | What it does / drains | If it runs dry |
|---|---|---|---|---|---|
| **①** | **Sponsor / Bundler EOA** | `0x0298…944DA` (= `BROKER_SPONSOR_SIGNER_ADDRESS_HEIMA`) | **plain native transfer** (the fund-account helper, operator-internal) | fronts the outer `handleOps` tx gas; the EntryPoint refunds it as beneficiary, so it ~cycles but must keep a working float | broker can't broadcast → accepts fail at submit |
| **②** | **Paymaster DEPOSIT** (inside the EntryPoint) | the deposit keyed by the **VerifyingPaymaster** — resolve the paymaster from [`heima.json`](../../crates/agentkeys-core/chain-profiles/heima.json) | **`deposit()` call** (the deploy-paymaster helper, operator-internal) | the actual sponsorship budget; DRAINS as ops are sponsored, never refilled by the cycle | EntryPoint reverts `AA31 paymaster deposit too low` → accepts fail |

**Is `BROKER_SPONSOR_SIGNER` the bundler wallet? — Yes, today.** It is **one EOA wearing two
hats**: (a) the **bundler submitter** that signs + broadcasts `EntryPoint.handleOps` (the
bundler reads `AGENTKEYS_BUNDLER_SIGNER_KEY`, falling back to `BROKER_SPONSOR_SIGNER_KEY` —
the *same* key, [`agentkeys-bundler/src/server.rs`](../../crates/agentkeys-bundler/src/server.rs)),
and (b) the **paymaster co-signer** that authorizes each sponsorship (the VerifyingPaymaster
verifies `recover(paymasterAndData.sig) == brokerSigner`) and is the `handleOps` *beneficiary*
(receives the gas refund — [`handlers/accept.rs`](../../crates/agentkeys-broker-server/src/handlers/accept.rs)).
Splitting them later is a one-line change (set a separate `AGENTKEYS_BUNDLER_SIGNER_KEY`); until
then **fund the one EOA**.

**Footgun (why the two are NOT interchangeable):** the paymaster contract pays sponsored gas
**only** from its **deposit held inside the EntryPoint** (`EntryPoint.balanceOf(paymaster)`),
credited via `paymaster.deposit()`. A plain transfer to the paymaster **address** lands in its
*raw* balance, which the EntryPoint never touches — the money is stuck. The paymaster's raw
balance is ~0 **by design**.

**See the live numbers** (deposit + every wallet) any time:
`bash scripts/utils/check-wallet-balances.sh` — it prints `sponsor/bundler` (①), `paymaster raw`
(the ~0 footgun balance), and `paymaster DEPOSIT` (②) as distinct rows. *(Snapshot
2026-06-13: ① ≈ 9.8 HEI, ② deposit ≈ 2.08 HEI, paymaster raw = 0.)*

## The two layers

```mermaid
flowchart TB
  subgraph biz["Layer 2 — off-chain business (DESIGN, not built)"]
    direction LR
    U["User pays fiat<br/>(e.g. 100 CNY via Alipay)"]
    LEDGER["Credit ledger<br/>(server-owned: 1000 credits)"]
    XCHG["Exchange / reimbursement server<br/>(fiat → HEI at a margin)"]
    U --> LEDGER
    U --> XCHG
  end

  subgraph chain["Layer 1 — on-chain gasless sponsorship (LIVE)"]
    direction LR
    BROKER["Broker co-sign<br/>(Sybil gate — the authz seam)"]
    PM["VerifyingPaymaster<br/>+ EntryPoint deposit (the pool)"]
    BUNDLER["Bundler<br/>(fronts handleOps gas)"]
    ACC["Master P256Account<br/>(gasless op)"]
    BROKER --> PM
    BUNDLER --> PM
    PM --> ACC
  end

  LEDGER -->|"credit check gates the co-sign"| BROKER
  XCHG -->|"deposit() top-up (the funding seam)"| PM
```

The two layers meet at exactly **two seams** — an authorization seam (the broker co-sign)
and a funding seam (the paymaster deposit). Everything else is independent.

## Layer 1 — on-chain gasless sponsorship (LIVE)

Per sponsored op (today, no credit layer):

1. User signs once with the K11 passkey (Touch ID) — **pays nothing, no gas**.
2. **Broker co-signs** the paymaster `getHash` approval — the Sybil gate (threat-model §5):
   the paymaster sponsors *only* ops the broker approved. ([`handlers/cap.rs`](../../crates/agentkeys-broker-server/src/handlers/cap.rs) / the accept handler.)
3. **Bundler** broadcasts `EntryPoint.handleOps`, fronting the outer-tx gas from its
   submitter EOA.
4. **EntryPoint** runs the op, **charges the paymaster's deposit** for the gas, and
   **refunds the bundler EOA**.

The **deposit** (held inside the EntryPoint, keyed by the paymaster address) is the real
cost-bearer; it is pre-funded in bulk by the operator. The bundler EOA roughly cycles
(its gas is refunded out of the deposit). See the funding map for addresses + custody.

## Layer 2 — off-chain prepaid credit & reimbursement (DESIGN)

The business layer the operator runs *beside* the chain, never on it:

1. **Fiat in → credits.** User pays fiat (e.g. 100 CNY via Alipay) to the operator's
   account; the **exchange server** detects the inflow and credits the user N ops in a
   **server-owned credit ledger** (e.g. 1000 credits). Credits are an off-chain
   entitlement — the chain never sees fiat.
2. **Spend → op.** The user spends a credit to trigger a sponsored op. The credit check
   is enforced at the **authz seam** (next section) before the broker co-signs.
3. **Reimbursement top-up.** The exchange server converts part of the fiat reserve to HEI
   **at a margin** and calls `deposit()` to keep the paymaster pool above its floor. The
   margin (fiat charged − HEI gas cost − fees) is the revenue; the deposit is both the
   gas buffer and where the proceeds land.

This is the "Alipay" model: prepaid credits backed by a fiat→HEI reimbursement loop. The
per-op mechanics of layer 1 are unchanged — the user is still gasless on-chain; the credit
is purely the operator's accounting of *who is allowed* to consume sponsorship.

## The seams (where layer 2 hooks into layer 1)

| Seam | Layer-1 component | What layer 2 does | Build state |
|---|---|---|---|
| **Authorization** | broker co-sign (Sybil gate) | gate the co-sign on a credit balance: no credit → broker declines → paymaster won't sponsor → op fails (or falls back to user-paid). The broker is the only place that can refuse before gas is spent. | co-sign LIVE (gates device/scope today, **not credits**); the credit hook is **not built** |
| **Funding** | paymaster EntryPoint deposit | the exchange server's *only* on-chain write — `deposit()` top-ups from converted fiat | `deposit()` LIVE (via the deploy-paymaster helper, operator-internal); automated reimbursement is **not built** |
| **Reconciliation** | deposit drawdown ↔ credit ledger | operator reconciles Σ sponsored ops (deposit drawdown, observable via the monitor) against credits spent | manual; no automated reconciliation built |

## Implemented vs not — read this before quoting the model

| Piece | State |
|---|---|
| ERC-4337 sponsorship (paymaster + bundler + EntryPoint), gasless accept | **LIVE** (Heima mainnet) |
| Broker co-sign Sybil gate | **LIVE** — gates on device binding + service scope |
| Credit ledger / fiat gateway / exchange-reimbursement server | **NOT BUILT** (design) |
| Credit → broker-co-sign authorization hook | **NOT BUILT** (design) |
| Automated fiat→HEI → `deposit()` reimbursement | **NOT BUILT** — today the deposit is topped up manually via `heima-deploy-paymaster.sh` |

Do not describe the credit/fiat layer as shipped. The chain side is real today; the
business side is an architecture, not code.

## Economic shape (illustrative — not committed pricing)

The deposit is a buffer, not a per-op settlement: the operator funds it ahead of demand
and refills as it drains. Profitability holds when, over a window, `fiat collected −
(HEI cost of the sponsored ops + conversion/rail fees) > 0`. The credit:op ratio
(1 credit = 1 op, or weighted by an op's gas) and the fiat price per credit are operator
policy set in the exchange server — not on-chain, not fixed here.

## Operational tie-ins

- **Fund the pool** (the only correct way): the deploy-paymaster helper (operator-internal)
  calls `deposit()`. A plain transfer to the paymaster address does **nothing**. Contract
  addresses live in the chain profile [`heima.json`](../../crates/agentkeys-core/chain-profiles/heima.json)
  and the public [`deployed-contracts.md`](./deployed-contracts.md); the wallet custody /
  funding map is operator-internal (the chain-setup runbook §Wallets).
- **Monitor the pool + wallets:** [`check-wallet-balances.sh`](../../scripts/utils/check-wallet-balances.sh)
  prints the deposit + every wallet (the signal the reimbursement loop would watch to
  decide when to top up).
- The sponsor/bundler EOA is funded by a plain transfer (`heima-fund-account.sh`); only
  the **deposit** uses `deposit()`.
