# AgentKeys — Open-Source Posture, Licensing, and Release Security

**Date:** 2026-04-08 (Round 11 of auth-layer sub-interview)
**Updated:** 2026-04-09 (Round 13 — monorepo structure per architecture.md, threat model cross-ref, revocation priority)
**Scope:** the open/closed source decision for every AgentKeys component, the licensing choice, reproducible-build and release-signing plans, supply-chain security, vulnerability disclosure, and the connection to the research-artifact credibility story.

**Sibling docs:**
- [`../arch.md`](../arch.md) — Rust/TypeScript component split and Cargo workspace layout (read this first for the 13-component inventory)
- [`./1-step-analysis.md`](./1-step-analysis.md) — auth-layer sub-analysis (threat model lives in §3.3c)
- [`./plans/design-spec.md`](../archived/design-spec.md) — original product vision (historical)
- `./plans/ceo-plan.md` (operator-internal) — v0 implementation plan (canonical)
- [`./heima-open-questions.md`](./heima-open-questions.md) — Kai meeting agenda (Q9 is the top priority dependency)

**Prior interview reference:**
- [`/Users/hanwencheng/Projects/project-life/.omc/specs/deep-interview-agentkeys.md`](../../../../.omc/specs/deep-interview-agentkeys.md)

---

## 1. The security-first principle (counter-intuitive to non-experts)

**For security-critical software, open source is MORE secure than closed source, not less.**

Non-specialists sometimes assume closed source protects secrets. In reality:

- **Kerckhoffs's principle (1883):** a cryptographic system should be secure even if everything about it is public knowledge, except the key. This principle has been the foundation of modern cryptography for 150 years.
- **Schneier's Law:** any person can invent a security system so clever that they themselves cannot think of how to break it. Independent review is the only reliable check.
- **Empirical track record:** every serious security tool of the past 30 years is open source — OpenSSH, OpenSSL (and its fork BoringSSL), age, Signal, WireGuard, KeePassXC, Bitwarden, rage, Tailscale control-plane protocol, Sigstore, etc. Closed-source security tools (1Password, Dashlane, LastPass) are routinely criticized for exactly this, and their closed-source nature has repeatedly delayed vulnerability discovery.

**Why open source is actually more secure for this class of software:**

1. **Many-eyes audit.** Independent researchers can find bugs the original team missed. AgentKeys is security-critical — a buggy session-key handling routine is a serious vulnerability. More reviewers = more bugs found.
2. **Reproducible builds.** Users can build the daemon from source and verify byte-by-byte that the binary distributed on github.com/agentkeys/... matches. This is impossible with closed source — the user has to trust the publisher's build pipeline isn't injecting backdoors.
3. **Supply chain transparency.** Every dependency and its transitive graph is visible. `cargo audit` / `cargo deny` / `cargo vet` actually work. Closed-source supply chains are opaque.
4. **Incident response velocity.** Public CVEs, public patches, public post-mortems. Closed-source vulnerabilities often stay hidden during the gap between discovery and fix.
5. **No "security through obscurity."** Motivated attackers reverse closed binaries in days. Closed source only deters lazy attackers — exactly the attackers who aren't a real threat.

**Closed source is actually MORE secure only in these narrow cases:**
- The code contains literal secrets baked in (which is itself a bug — keys belong in KMS/secrets stores, not in binaries).
- The code is temporary exploit mitigation awaiting coordinated disclosure (time-limited, irrelevant here).
- Legal/regulatory compliance mandates confidentiality (not applicable to AgentKeys).

**None of these apply to AgentKeys.** Every security-critical component benefits from being open.

## 2. The research-artifact imperative

Even setting aside the generic security argument, **a closed-source research artifact is an oxymoron.** The writeup wants to make these claims:

> *"Your Google account, not a bearer token, is the root of trust for your agent's credentials. Your secrets are held in TEE-gated ciphertext on a public chain. No centralized operator can read your secrets. Your agent sandboxes can be revoked instantly."*

None of these claims is honestly defensible if there's closed-source code in the trust path. A user who can't read the daemon's source has to *trust AgentKeys the organization* to not exfiltrate their session keys — which is exactly the single point of trust the whole architecture is supposed to eliminate.

**The rule for AgentKeys:** every component inside the trust boundary is open source, no exceptions. Closed source is reserved for components that (a) have a specific legal/abuse reason, and (b) never hold cryptographic material the user depends on.

## 3. Component-by-component classification

Using the 13-component inventory from [`../arch.md`](../arch.md) §2. All Rust components live in a single monorepo (`agentkeys/agentkeys`) as crates in a Cargo workspace. See [`../arch.md`](../arch.md) §6 for the workspace layout.

| # | Component | Trust boundary? | Source | License | Location (monorepo) |
|---|---|---|---|---|---|
| 1 | Master CLI | ✅ inside | **Open** | `MIT OR Apache-2.0` | `crates/agentkeys-cli/` |
| 2 | agentkeys-daemon (runs as `gem` UID, no dedicated UID, session at `$HOME/.agentkeys/session`) ⭐ | ✅ inside | **Open** ⭐ | `MIT OR Apache-2.0` | `crates/agentkeys-daemon/` |
| 3 | MCP adapter | ✅ inside | **Open** | `MIT OR Apache-2.0` | `crates/agentkeys-daemon/` (same process) |
| 4 | CLI adapter | ✅ inside | **Open** | `MIT OR Apache-2.0` | `crates/agentkeys-daemon/` (same process) |
| 5 | Heima RPC client / shared types | ✅ inside | **Open** | `MIT OR Apache-2.0` | `crates/agentkeys-core/` |
| 6 | x402 / EVM library | ✅ inside | **Open** | `MIT OR Apache-2.0` | `crates/agentkeys-core/` |
| 7 | Provisioner orchestrator (Rust, exposed as MCP tool `agentkeys.provision`) | ✅ inside | **Open** | `MIT OR Apache-2.0` | `crates/agentkeys-provisioner/` |
| 8 | **Browser automation scripts (TS)** | ⚠️ carve-out | **Open logic, private tuning** (see §4) | `MIT` (open parts) | `provisioner-scripts/` (separate npm package) |
| 9 | Ephemeral email integration (TS) | outside | **Open** | `MIT` | `provisioner-scripts/` |
| 10 | Audit indexer | outside | **Open** | `MIT OR Apache-2.0` | `indexer/` (v0.1, Subsquid) |
| 11 | Web GUI (post-MVP) | ✅ partially inside | **Open** | `MIT OR Apache-2.0` | TBD post-MVP |
| 12 | **Heima TEE worker extensions** | ✅ inside ⭐ | **Open ideally — depends on Kai** (see §5) | Match Heima's license | PR to `github.com/litentry/heima` |
| 13 | New Heima pallets | ✅ inside | **Open** | Match Heima (`GPL-3.0-or-later`) | PR to `github.com/litentry/heima` |
| M | **Mock backend service (v0 only)** | ✅ inside | **Open** | `MIT OR Apache-2.0` | `crates/agentkeys-mock-server/` |

**Summary:** 12 of 13 permanent components are unambiguously open source. Components #8 and #12 have specific carve-outs handled below. The mock backend (#M) is temporary and fully open.

## 4. The one judgment call — component #8 (browser automation scripts)

This is the only component where there's a real argument for keeping something private. Both sides laid out explicitly:

### Arguments for fully open sourcing

- Users can audit what the scraper does to third-party services on their behalf with their burner email and their x402 funds.
- Community contributions extend support to new services over time.
- Demo reproducibility — any reviewer of the research artifact can fork and rerun.
- Defense-in-depth audit of the email verification code extraction (a bug there could leak a verification code to an attacker).
- Security-tool publication norms favor open review.

### Arguments for partial/closed source

- **Bot-detection arms race.** If services see AgentKeys' exact Playwright script publicly, they can add a specific signature to detect and block it. The signup scripts stop working the day after publication. This is not hypothetical — it's how every stealth-scraping project works.
- **Terms-of-service risk.** Some target services' ToS explicitly prohibit automated signups (Twitter/X most famously). Publishing turnkey scripts that violate those ToS creates legal exposure and gives the service a clear target to block.
- **Weaponization.** Open-source signup automation can be repurposed for abuse at scale — account farming, spam, astroturfing, coordinated inauthentic behavior. "AgentKeys enabled push-button Twitter signup" is a terrible headline for a security research artifact.
- **Privacy norms.** Services have legitimate interests in rate-limiting automated signups to prevent abuse. AgentKeys exists to solve a real user problem (credential provisioning for agents), not to enable abuse.

### The compromise: "open logic, private tuning"

Separate the *logic* (what the scraper does, auditable for trust) from the *tuning* (how it evades detection, the arms-race surface).

**Open (committed to the public repo):**
- The signup flow logic for each service.
- The email verification code extraction.
- The integration with the Rust orchestrator (stdio IPC protocol).
- The encryption step (API key → Heima shielding key).
- The structure of per-service scrapers.

**Private (per-deployer config, gitignored):**
- Specific user-agent strings.
- Behavioral timing values (delays between actions).
- Viewport sizes, locale overrides, geolocation spoofing.
- Stealth plugin configurations (`playwright-extra` options).
- Proxy rotation policies.
- CAPTCHA solver API keys.

**Rationale:** the *logic* is what determines whether the scraper is trustworthy — users and reviewers care about this. The *tuning values* are what determines whether services detect it — deployers care about this, users don't. Separating them lets us be fully open about the trust-relevant parts while keeping the arms-race parts as deployment configuration.

### Repo layout for `provisioner-scripts`

```
provisioner-scripts/
├── package.json
├── tsconfig.json
├── README.md                  # honest note on ToS concerns
├── LICENSE                    # MIT
├── scrapers/                  # COMMITTED — signup flow logic
│   ├── openrouter.ts          # Tier 1 (ToS-tolerant)
│   ├── brave.ts               # Tier 1
│   ├── notion.ts              # Tier 2 (gray area, "reference only" disclaimer)
│   └── openai.ts              # Tier 2
│   # NOTE: twitter.ts and google.ts are NOT in the public repo
│   # (Tier 3 — see §4.2 below)
├── lib/
│   ├── email.ts               # COMMITTED — IMAP / burner email client
│   ├── orchestrator-ipc.ts    # COMMITTED — stdio JSON protocol w/ Rust
│   ├── stealth-defaults.ts    # COMMITTED — safe default stealth config
│   └── cdp-encrypt.ts         # COMMITTED — shielding-key encryption
├── config/
│   ├── default.ts             # COMMITTED — safe defaults
│   ├── .stealth.local.ts      # GITIGNORED — deployer tuning
│   └── .env.example           # COMMITTED — shows what goes in .env
├── tests/
│   └── smoke/                 # CI against real signup flows (Tier 1 only)
└── .gitignore                 # ignores .stealth.local.ts, .env, proxy configs
```

### §4.2 Tier 3 services (Twitter, Google) are explicitly NOT distributed

Twitter and Google both explicitly ban automated signups in their ToS. Distributing turnkey scripts for these services would be:
1. **Legally exposed** — the AgentKeys project could face C&D or direct legal action from Twitter/X Corp or Google.
2. **Abuse-enabling** — the same scripts would immediately be forked for spam account farming.
3. **Arms-race-losing** — Twitter specifically will block any public signup automation within days.

**Policy:**
- The **writeup describes the approach at a high level** for these services — browser automation + CAPTCHA handling + email + phone verification — so the research contribution is intact.
- The **exact scripts, selectors, stealth patterns, and CAPTCHA integration are held privately** and not published.
- **Demo footage may be included** (recorded video showing the flow) but not a turnkey script.
- The writeup is **explicit and honest** about this: *"AgentKeys demonstrates that credential provisioning can be automated for services that permit it (Tier 1), is viable-with-caveats for services in a gray area (Tier 2), and is technically possible for services that forbid it (Tier 3) — but we do not distribute turnkey tools for Tier 3 because of legal and abuse concerns. The research contribution is the architecture, not the bypass techniques."*

### §4.3 Tier classification

| Tier | Services | Distribution | CI tested? |
|---|---|---|---|
| **Tier 1 — ToS-tolerant** | OpenRouter, Brave Search API, Anthropic, OpenAI (arguably) | **Fully open source in `provisioner-scripts` repo, Apache-2.0** | Yes — weekly CI against real signup flows |
| **Tier 2 — gray area** | Notion, some niche APIs | **Open source as "reference implementations"** with a disclaimer, no production CI | No — manual smoke test before release |
| **Tier 3 — ToS violation** | Twitter / X, Google consumer accounts, Facebook/Meta | **NOT distributed.** Described in writeup abstractly only. | No |

## 5. Component #12 — the Heima TEE worker dependency

This is the thorniest question in the entire open-source conversation and **a direct input to the Kai meeting** ([`heima-open-questions.md`](./heima-open-questions.md) Q11).

### The current state (from `heima-auth.md` research)

The Heima TEE worker that holds the real passkey verification code is **not fully in the public `litentry/heima` repo**. Kai holds parts of it. Some pieces (`tee-worker/identity`, `omni-executor` on the public repo) are open, but the AgentKeys-relevant pieces — particularly any additions made for AgentKeys — are at Kai and Litentry's discretion.

### The direct problem for AgentKeys' security story

If AgentKeys' trust chain terminates at a closed-source TEE worker, the writeup has to say:

> *"Everything from the user's laptop down to the Heima TEE is open-source and auditable. The TEE worker itself is a closed-source dependency held by Litentry, with a publicly documented interface contract but closed implementation."*

That's honest. It's also weaker than the ideal claim, and it makes the TEE worker the single trust dependency a reader cannot verify.

### What to push for in the Kai meeting

1. **AgentKeys-specific additions contributed as a PR to `litentry/heima`** rather than held as private Kai-code. This is the ideal outcome — it makes every AgentKeys-related line of TEE-worker code public.
2. **Full public interface contract** at minimum — API schema, session key semantics, scope enforcement rules, audit event format. Even if the implementation stays closed, the *contract* must be publicly documented so third parties can verify what AgentKeys is depending on.
3. **Aspirational: full open-sourcing of the TEE worker** over time. This may be outside Kai's personal control (it's a Litentry business decision), but asking is worth it.

### Fallback posture if #12 stays closed

- The writeup explicitly lists the TEE worker as a closed-source dependency in the threat model.
- The threat model document acknowledges: *"TEE worker integrity is a trust assumption. AgentKeys users trust Litentry's TEE worker the same way they would trust Intel's SGX implementation itself — both are closed-source trust roots that can in principle hide vulnerabilities or backdoors. We recommend independent audits of the TEE worker before relying on AgentKeys for production secrets."*
- The writeup claims: *"Your laptop is auditable, the chain is auditable, the daemon is auditable — the TEE worker is trusted to the same standard as the underlying hardware enclave."*
- This is strictly weaker than a fully-open story but still strictly better than 1Password's "trust our cloud" model.

### Action item

Highlight Q11 in [`heima-open-questions.md`](./heima-open-questions.md) alongside Q1, Q2, and especially **Q9 (revocation latency — now the top priority)** as the most important outcomes to push for in the Kai meeting.

## 6. Licensing recommendation

**`MIT OR Apache-2.0` dual license** for all AgentKeys-authored open-source code (SPDX: `MIT OR Apache-2.0`).

### Why dual MIT/Apache-2.0

- **Rust community standard.** `cargo new` scaffolds with dual MIT/Apache-2.0 by default. Nearly every crate on crates.io uses it. Downstream Rust projects expect it and integrate cleanly.
- **Maximum permissive.** Allows commercial use, modification, and redistribution without forcing downstream disclosure.
- **Patent protection via Apache-2.0's patent grant clause.** MIT alone does not have an explicit patent grant; Apache-2.0 does. Dual-licensing gives users the MIT simplicity + the Apache-2.0 patent protection.
- **Compatible with the Rust ecosystem** — every dependency is MIT/Apache, every downstream can use our code without license friction.

### Heima-facing components (#12, #13)

For components that are PRs to `litentry/heima`, the license is whatever the upstream chooses — as of the last check on [`/lifeKnowledge/heima.md`](../../../lifeKnowledge/heima.md), Heima's pallets and runtime are `GPL-3.0-or-later` (Substrate convention). Our contributions to that repo inherit that license.

**This does not infect AgentKeys' own code** because:
- AgentKeys' Rust crates interact with Heima only over RPC/extrinsic calls, not by linking Heima's code into our binary.
- GPL copyleft propagates through linking, not through network communication. Our daemon calls Heima over wss — no linking, no copyleft infection.
- The `subxt` crate (our Heima client) is itself `GPL-3.0-or-later` for some parts — we'd need to check whether any of its types or macros force our crates into GPL. **Open TODO: verify `subxt`'s licensing and choose an alternative if it forces GPL on consumers.**

### Alternatives considered and rejected

- **AGPL-3.0** — would force any modified AgentKeys deployed as a hosted service to disclose its source. Attractive for preventing "embrace and extend," but restricts commercial adoption and is arguably overkill for v0. Can switch to AGPL later if the project becomes commercially valuable.
- **Business Source License (BSL)** — time-delayed open source, used by companies that want initial commercial protection. Overkill for a research artifact; AgentKeys has no commercial-protection goal.
- **Permissive-only (MIT)** — no patent grant, leaves the project exposed to patent trolling. Apache-2.0 addendum avoids this.
- **GPL-3.0** — forces users of AgentKeys-derived work to disclose. More viral than we want; would scare off commercial adopters who might otherwise integrate AgentKeys.

## 7. Reproducible builds

Open source is necessary but not sufficient for verifiability. **Reproducible builds** close the loop: a user can build the daemon from source and verify the binary exactly matches the one published on GitHub Releases.

### Concrete requirements for v0

- **`Cargo.lock` committed** to the repo. All transitive dependency versions pinned.
- **`rust-toolchain.toml` file** pinning the exact Rust compiler version.
- **All builds use `cargo build --release --locked`** — fails if `Cargo.lock` is out of sync.
- **Published SHA256 hashes** of release binaries in the GitHub Release notes, alongside the source git tag.
- **`cross` or similar** for deterministic cross-compilation to the three OS targets (macOS, Linux, Windows).
- **Documented build steps in `BUILDING.md`** — "to verify our binary: clone at tag vX.Y.Z, run these commands, compare sha256sum."

### Aspirational for v0.1+

- **Nix flake** for fully reproducible builds. `nix build` produces byte-identical output on any machine.
- **Sigstore cosign** signatures on release artifacts. Users can verify the signature came from the AgentKeys maintainer's public key and not an attacker who took over the GitHub org.
- **SLSA attestations** (level 3+) via GitHub Actions trusted publishing.

### Why this matters for the security claim

Without reproducible builds, "open source" is only half the win. A malicious publisher could:
- Publish clean source on GitHub.
- Build a subtly different binary with backdoors inserted during the build.
- Ship that binary to users.
- Users read the source and see nothing wrong; the backdoor is in the binary alone.

Reproducible builds make this attack impossible by letting any user rebuild and bit-compare.

## 8. Release signing

Every release artifact must be signed with a well-known key.

**Minimum for v0:** `minisign` or `GPG` detached signatures, public key published in the README and on a .well-known endpoint on agentkeys.dev, signatures attached to every GitHub Release.

**Better for v0.1+:** Sigstore cosign with keyless signing via GitHub OIDC. Automatically binds the signature to a specific GitHub Actions run, no private key to manage or lose.

**Best for mainnet production:** hardware-backed signing key (YubiKey or similar). Multi-signature release approval if the project grows past one maintainer.

## 9. Supply chain security

Rust dependencies are a real attack surface. Every `Cargo.toml` entry is an opportunity for a malicious package to sneak into the trust boundary.

### Required for v0

- **`cargo audit`** in CI — fails the build on any known-vulnerable dependency.
- **`cargo deny`** configuration — explicit allow-list of licenses, deny-list of known-bad crates, deny copyleft unless intentional.
- **Dependency review discipline** — every new crate added to `Cargo.toml` gets a manual review of (a) its maintainer reputation, (b) its download count and activity, (c) its recent commits, (d) its own dependencies.
- **No wildcards** — all versions pinned (`1.2.3`, not `^1.2` or `*`).
- **Low transitive count** — prefer crates with small dependency trees.

### Better for v0.1+

- **`cargo vet`** — maintain a trust network for every dependency, with signed audits from the AgentKeys team (or from other trusted auditors).
- **Private Rust registry mirror** — pin the entire dependency graph to a snapshot, isolate from crates.io changes.
- **SBOM (Software Bill of Materials)** published with every release in SPDX or CycloneDX format.

## 10. Third-party security audit

Before any "v0 is stable" public release, the AgentKeys code path **should be audited by an independent security firm.**

### Candidate auditors

- **Trail of Bits** — extensive Rust and crypto experience, audited Sigstore, Diem, many Substrate projects.
- **NCC Group** — broad security practice, has audited Wireguard and other security tools.
- **Cure53** — web/browser security specialists; especially relevant if the Web GUI ships.
- **Kudelski Security** — blockchain-focused, has audited Substrate-derived projects.
- **Least Authority** — smaller, specialized in cryptographic protocols.

### Scope

At minimum: the `agentkeys-daemon` crate + `agentkeys-core` crate + the Heima RPC client interactions. Optionally: the Heima TEE worker integration, if it's open-sourced by then.

### Honest caveat for v0

**A full audit is a v0.1 requirement, not a v0 requirement.** Audits cost $50K–$200K and take weeks to months. For v0 research-artifact release, the writeup should explicitly say:

> *"AgentKeys v0 is a research artifact and has NOT been independently audited. Do not use v0 to manage production secrets. A security audit is planned before any stable release. Until then, users who adopt it do so at their own risk and are encouraged to audit the source code themselves."*

This is how every responsible new security tool ships.

## 11. Vulnerability disclosure policy

Every security-sensitive project needs a clear disclosure channel. Publish `SECURITY.md` in the repo root containing:

- **Reporting channel** — a dedicated email address (`security@agentkeys.dev` or similar) with a published PGP key, OR use GitHub Security Advisories.
- **Response SLA** — commit to an initial response within 72 hours, acknowledgement of valid reports within a week.
- **Coordinated disclosure window** — typical 90 days from initial report to public disclosure, extendable by mutual agreement.
- **Safe harbor** — explicit statement that researchers acting in good faith will not be pursued legally for their reports.
- **Scope** — what's in-scope (daemon, CLI, core library, Heima client) and out-of-scope (third-party services AgentKeys provisions accounts on, Heima TEE worker unless we own it).
- **Hall of fame / acknowledgements** — credit for researchers who report valid issues.

## 12. Threat model

See [`./1-step-analysis.md`](./1-step-analysis.md) §3.3c.4 and §3.3c.6 for the canonical v0 threat model on stock agent-infra/sandbox. That analysis is authoritative; this document defers to it.

## 13. "Operationally self-sovereign," made specific

What the writeup can honestly claim, given everything above:

1. **Every component on the user's machine is open-source and auditable.** ✅
2. **Every component on the sandbox is open-source and auditable.** ✅
3. **The network path terminates at a public blockchain you can query independently.** ✅
4. **The ONE trust dependency beyond your direct audit is the Heima TEE worker**, which is either:
   - (a) open-source like the rest of `litentry/heima` — ideal. Or
   - (b) closed-source but with a publicly documented interface contract — acceptable, documented as a trust assumption. ⚠️ → push to resolve in the Kai meeting.
5. **The TypeScript provisioner is quarantined** to a disposable sandbox and never touches cryptographic material. "Rust end-to-end" still holds for everything in the trust boundary.
6. **Browser automation scripts are open in logic, private in tuning.** The writeup is explicit and honest about this split and about the ToS/abuse considerations.
7. **Binaries are reproducibly built and signed.** Users can verify byte-for-byte that the published daemon matches the open source.
8. **The project commits to independent security audit before any "stable" release.** Until then, v0 is labeled research-use-only.

## 14. Open TODOs for v0 release security

- [ ] Set up `cargo audit` + `cargo deny` + `cargo vet` in CI
- [x] Commit `Cargo.lock`, pin `rust-toolchain.toml` (pinned to a concrete version; gated by `scripts/utils/check-toolchain-pin.sh` in CI)
- [ ] Document reproducible-build steps in `BUILDING.md`
- [ ] Publish SHA256 hashes with every release
- [ ] Set up `minisign` or cosign for release signing, publish public key
- [ ] Write `SECURITY.md` with disclosure policy and reporting channel
- [ ] Write `THREAT-MODEL.md` expanding on `1-step-analysis.md` §3.3c
- [ ] Check `subxt` license compatibility with `MIT OR Apache-2.0`
- [ ] Create the `agentkeys` GitHub org and reserve the 7 repositories
- [ ] Reserve `agentkeys.dev` domain for documentation + release hosting
- [ ] Draft the Tier 1/2/3 service classification in `provisioner-scripts` README
- [ ] Prepare for Kai meeting: **Q9 (revocation latency) is the top priority** — revocation is the ONLY defense on stock sandbox (Round 13 finding). Also push Q1, Q2, Q11.
- [ ] Budget for v0.1 security audit (even if deferred, get estimates now)
- [ ] Hardened fork of `agent-infra/sandbox` — see `agent-infra-sandbox-runtime-probe.md` (operator-internal) §8 for the full TODO list

## 15. Cross-references

- **Component inventory and language choices:** [`../arch.md`](../arch.md) §2, §3
- **Kernel hardening threat model:** [`./1-step-analysis.md`](./1-step-analysis.md) §3.3c
- **Multi-repo structure:** `./plans/ceo-plan.md` (operator-internal) §"Repository structure"
- **TEE worker Kai questions:** [`./heima-open-questions.md`](./heima-open-questions.md) Q9 (top priority), Q11, Q1, Q2
- **Heima parachain licensing:** see `/lifeKnowledge/heima.md`
- **User flows showing trust boundaries in action:** [`./1-step-analysis.md`](./1-step-analysis.md) §4
- **Hardened sandbox TODO list:** `../research/aiosandbox/agent-infra-sandbox-runtime-probe.md` (operator-internal) §8

---

*Living document. Update when the component classification changes or when the Kai meeting resolves the TEE worker open-source status.*
