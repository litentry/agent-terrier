# AgentKeys / Heima CLI — Exploration of a Blockchain-Backed 1Password CLI Replacement

> **ARCHIVED** — This was the initial exploration document (2026-04-07). All questions below have been resolved. See [`plans/ceo-plan.md`](../plan/ceo-plan.md) for the v0 plan, and [`credential-backend-interface.md`](credential-backend-interface.md) for the trait spec.

**Status:** archived exploration draft, 2026-04-07
**Inputs:** [`lifeKnowledge/heima.md`](heima.md) (Heima capability analysis), 1Password CLI feature inventory (research summary), reference site https://agentvault-site.vercel.app/
**Audience:** founder + future engineering team, pre-spec stage

---

## Why this matters

Spinning up a fresh agent machine — sandbox, ephemeral VM, cloud worker, container — has a chicken-and-egg auth problem. The agent needs SSH keys, API tokens, cloud credentials, git signing keys, model API keys. Those secrets live in some vault. To reach the vault, the agent needs a credential. To get that credential safely into a brand-new machine without a human watching, you fall back to a long-lived bearer token that defeats the entire point.

1Password's answer is the **Service Account Token**: one `OP_SERVICE_ACCOUNT_TOKEN=ops_…` env var, full vault access, manual rotation, no per-call signing, no device binding, audit log says "service account X did Y" — not "agent abc-123 on VM def-456 did Y on behalf of user U". This is the gap.

---

## 1Password CLI in one page (so we can compare)

| Surface | What `op` does | Used by agents? |
|---|---|---|
| `op signin` | Desktop biometric IPC, or interactive secret-key+master-password | No (human only) |
| **Service account token** | Long-lived JWT bearer in `OP_SERVICE_ACCOUNT_TOKEN` | **Yes — the only headless path** |
| `op connect` | Self-hosted REST cache server | Sometimes (heavy, k8s) |
| `op read op://Vault/Item/Field` | Resolve one secret reference | Yes |
| `op inject -i tmpl -o out` | Template-substitute secrets into a file | Yes |
| `op run -- cmd` | Spawn child with env-injected secrets, masked stdout | Yes (most common) |
| `op item create/get/edit/delete` | CRUD on items | Yes |
| `op vault create/list/grant` | Vault CRUD + ACL grants | Limited (SAs can't manage) |
| `op document` | File-attachment items | Yes |
| `op user` / `op group` | Org admin | No (humans only) |
| SSH agent socket | Backed-by-vault SSH agent | Desktop only |
| Git signing | SSH-signed commits via 1P helper | Desktop only |
| Shell plugins | Wraps `aws`/`gh`/`stripe`/etc. with biometric gating | Desktop only |
| Events API | Audit stream → SIEM | Admin only |

### The pain points 1Password cannot fix without breaking its model
1. **Bearer-token bootstrap** — leaks via env, /proc, ps, CI logs.
2. **Immutable SA scope** — can't add a vault to an existing service account.
3. **Manual rotation** — every machine touched by hand.
4. **No agent identity** — audit log can't distinguish two agents sharing one token.
5. **Centralized trust** — AgileBits' cloud is the single point of compromise and availability.
6. **No device binding** — token works from anywhere on Earth.
7. **100 SAs/org cap** — hostile to many-agent fleets.
8. **SSH agent / git signing locked to desktop app** — remote agents can't sign commits.
9. **Lock-in** — proprietary `op://` refs, JSON schema, token format.

These are the openings.

---

## Five blockchain-native moves that 1Password structurally cannot make

These are the parts worth being creative about. Each one solves a specific 1Password limitation.

### 1. Attested-bootstrap, no bearer token ever

**Problem solved:** the chicken-and-egg of getting credentials into a fresh VM.

**How:** when a new agent machine starts, it boots a Gramine enclave shipping the official `omni-executor` image (or a slimmed `agent-executor`). Enclave generates an ephemeral keypair, requests a DCAP quote from Intel, posts the quote + pubkey to Heima. `pallet-teebag` already validates DCAP quotes and enforces an MRENCLAVE allow-list. If the quote is valid and the MRENCLAVE matches, the chain mints a short-lived **session capability** bound to (MRENCLAVE, ephemeral_pubkey, owner_omniaccount). The agent now has access **without ever holding a long-lived secret**. If the machine is destroyed, the capability dies with it.

**Why 1Password can't do this:** they have no remote attestation primitive; their auth is bearer-token-shaped at the protocol level.

### 2. ACL as a first-class on-chain object with TTL and rate limits

**Problem solved:** immutable service-account scope; manual rotation; coarse audit.

**How:** capabilities are explicit rows: `(vault_id, secret_id, grantee_identity, action_set, valid_until, max_uses, used_so_far)`. Anyone with `manage_vault` can add/revoke capabilities by extrinsic. Revocation is instant and global — there is no cached token to invalidate.

**Why 1Password can't do this:** their ACL lives in their cloud as opaque DB rows; you can't add a vault to an existing SA.

### 3. Self-sovereign vault: ciphertext is portable, you own the keys

**Problem solved:** centralized trust on AgileBits' cloud; lock-in.

**How:** secrets are stored as RSA-OAEP / AES-GCM ciphertext directly on Heima. The decryption key lives inside the TEE worker; the shielding-key public half is on chain. If Litentry/Heima vanish tomorrow, you can run your own omni-executor on your own SGX hardware, fork the chain, or fall back to the encrypted local export — because the format is open.

**Why 1Password can't do this:** their ciphertext lives in their cloud; their format is proprietary; their key derivation requires their account servers.

### 4. Per-call cryptographic provenance — audit log that can't lie

**Problem solved:** audit log says "service account X" instead of "agent instance abc on VM def".

**How:** every `read_secret` is an extrinsic signed by the agent's ephemeral session key. The block explorer shows: `agent_pubkey 0xabc… (MRENCLAVE 0xdef…, owner OmniAccount 0x123…) read secret S at block N`. This is cryptographic, not log-shaped. Forging it requires breaking SR25519.

**Why 1Password can't do this:** Events API is a centralized log stream from a centralized DB.

### 5. Capability delegation across identity protocols

**Problem solved:** no way to grant "this Github user" or "this EVM address" temporary access without creating an account.

**How:** because the `Identity` enum already accepts Substrate / EVM / BTC / Solana / Twitter / Github / Google / Email, a vault grant can be addressed to any of these. The grantee proves ownership at read time via the corresponding signature scheme.

**Why 1Password can't do this:** they have one identity model — a 1P account.

---

## Advantages of the Heima approach (the elevator pitch)

| Property | 1Password CLI | Heima CLI |
|---|---|---|
| Bootstrap secret needed on new VM | **Yes** (`OP_SERVICE_ACCOUNT_TOKEN`) | **No** — TEE attestation replaces it |
| Trust root | AgileBits' cloud + your master password | Your wallet seed + Intel SGX attestation |
| Audit log | Centralized DB (Events API), admin-only | Public chain extrinsics, cryptographically signed, queryable by anyone with capability |
| Per-call signing | No (bearer token) | Yes (ephemeral session keypair) |
| Device binding | No | Yes (capability bound to MRENCLAVE + ephemeral pubkey) |
| Revocation propagation | Manual; rotate token, redeploy | Instant; one extrinsic |
| ACL granularity | Per-vault, action flags, frozen post-create | Per-secret, per-grantee, TTL, use limits, mutable |
| Cross-protocol identity | 1P accounts only | Any of 9 identity types via OmniAccount |
| Headless SSH / git signing | Requires desktop app | Native (TEE-held key, intent-signed) |
| Lock-in | Proprietary format, proprietary cloud | Open ciphertext format, public chain, forkable |
| Many-agent fleets | 100 SA/org cap | Unlimited capabilities; cost = chain fees |

### Honest disadvantages (don't pretend they don't exist)
- **Latency:** every read is at minimum a chain RTT (~6s block time on Heima) unless we add an off-chain fast-path. 1Password is sub-100ms via Connect.
- **Cost:** chain fees per operation. Probably negligible per call but real at agent-fleet scale.
- **Complexity:** SGX dependency (and SGX has a checkered history — supply chain attacks, microcode bugs).
- **Bootstrapping the developer:** wallet seed UX is worse than master password for non-crypto users.
- **Heima dependency:** if Litentry stops shipping, we inherit the parachain.

---

## References
- `lifeKnowledge/heima.md` — full Heima capability analysis
- 1Password CLI reference: https://developer.1password.com/docs/cli/reference
- 1Password service accounts: https://developer.1password.com/docs/service-accounts/
- AgentVault site: https://agentvault-site.vercel.app/
