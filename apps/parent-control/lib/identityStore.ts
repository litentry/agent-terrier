// Chain-scoped browser store for the master identity pointers.
//
// The daemon/broker/chain stack switches between Heima and Base (the fleet `c`
// stack picker injects AGENTKEYS_CHAIN → dev.sh sources the matching
// scripts/operator-workstation.<chain>.env). The browser's master pointers must
// switch WITH it: a Base master's credentialId/omni must never be offered while
// the daemon is on Heima. They share three un-suffixed keys today, so after a
// switch the other chain's pointer lingers and the omni-match guard rejects it —
// which is exactly what suppressed the "Sign back in with Touch ID" button and
// made onboarding look broken. Keying every pointer by the active chain name
// isolates the two identities.
//
// `ak_active_chain` mirrors the live daemon chain to localStorage so the keys
// resolve synchronously across reloads; `ensureActiveChain()` refreshes it from
// the daemon on each load (a stack switch is a full reload, which re-derives it).
// Pre-namespacing pointers (the bare keys) migrate into the first chain the
// daemon reports, then are removed.

const ACTIVE_CHAIN_KEY = 'ak_active_chain';
const CRED_ID = 'ak_master_cred_id';
const OMNI = 'ak_master_omni';
const ONBOARDED = 'ak_onboarded';
const NAMESPACED = [CRED_ID, OMNI, ONBOARDED];

// In-memory cache of the active chain — authoritative once `setActiveChain` has
// run this page load; falls back to the localStorage mirror for the synchronous
// reads that fire before the daemon chain has been fetched.
let activeChain = '';

function store(): Storage | null {
  try {
    return typeof localStorage !== 'undefined' ? localStorage : null;
  } catch {
    return null;
  }
}

function currentChain(): string {
  if (activeChain) return activeChain;
  const s = store();
  if (!s) return '';
  try {
    return s.getItem(ACTIVE_CHAIN_KEY) || '';
  } catch {
    return '';
  }
}

// `<base>:<chain>` once the chain is known; the bare legacy key until then, so a
// pre-namespacing identity still reads on the very first load (before migration).
function scopedKey(base: string): string {
  const c = currentChain();
  return c ? `${base}:${c}` : base;
}

function read(base: string): string {
  const s = store();
  if (!s) return '';
  try {
    return s.getItem(scopedKey(base)) || '';
  } catch {
    return '';
  }
}

function write(base: string, value: string): void {
  const s = store();
  if (!s) return;
  try {
    s.setItem(scopedKey(base), value);
  } catch {
    /* storage unavailable / quota — non-fatal, matches prior best-effort writes */
  }
}

function clear(base: string): void {
  const s = store();
  if (!s) return;
  try {
    s.removeItem(scopedKey(base));
  } catch {
    /* non-fatal */
  }
}

export function getMasterCredId(): string {
  return read(CRED_ID);
}

export function setMasterCredId(value: string): void {
  write(CRED_ID, value);
}

export function getMasterOmni(): string {
  return read(OMNI);
}

export function setMasterOmni(value: string): void {
  write(OMNI, value);
}

export function getOnboardedFlag(): boolean {
  return read(ONBOARDED) === '1';
}

export function setOnboardedFlag(on: boolean): void {
  if (on) write(ONBOARDED, '1');
  else clear(ONBOARDED);
}

// Per-chain wipe (reset master): clears only the ACTIVE chain's pointers, so a
// reset on one chain leaves the other chain's master untouched.
export function clearMasterIdentity(): void {
  clear(CRED_ID);
  clear(OMNI);
  clear(ONBOARDED);
}

// Bind subsequent reads/writes to `chain` and migrate any pre-namespacing
// pointers into it. One-shot: the bare keys are removed after adoption, so a
// later switch to another chain can't re-adopt them. A mis-attributed legacy
// identity (bare keys that actually belonged to the other chain) is harmless —
// the omni-match guard rejects a pointer whose omni ≠ the daemon's master.
export function setActiveChain(chain: string): void {
  if (!chain) return;
  activeChain = chain;
  const s = store();
  if (!s) return;
  try {
    s.setItem(ACTIVE_CHAIN_KEY, chain);
  } catch {
    /* non-fatal */
  }
  for (const base of NAMESPACED) {
    try {
      const legacy = s.getItem(base);
      if (legacy === null) continue;
      const scoped = `${base}:${chain}`;
      if (s.getItem(scoped) === null) s.setItem(scoped, legacy);
      s.removeItem(base);
    } catch {
      /* non-fatal */
    }
  }
}

// Resolve the live daemon chain once per page load and bind the store to it.
// No memoization on failure: it retries until a non-empty chain is returned, so
// a daemon that connects after first paint still binds. A stack switch is a full
// reload, which resets `activeChain` and re-derives it here.
export async function ensureActiveChain(getChain: () => Promise<string | null>): Promise<void> {
  if (activeChain) return;
  let chain: string | null = null;
  try {
    chain = await getChain();
  } catch {
    chain = null;
  }
  if (chain) setActiveChain(chain);
}
