// Identity pointers are scoped to both chain and broker.
const ACTIVE_CHAIN_KEY = 'ak_active_chain';
const ACTIVE_BROKER_KEY = 'ak_active_broker';
const CRED_ID = 'ak_master_cred_id';
const OMNI = 'ak_master_omni';
const ONBOARDED = 'ak_onboarded';
const NAMESPACED = [CRED_ID, OMNI, ONBOARDED];

// In-memory cache of the active stack — authoritative once `setActiveStack`
// has run this page load; falls back to the localStorage mirrors for the
// synchronous reads that fire before the daemon has been fetched.
let activeChain = '';
let activeBroker = '';

function store(): Storage | null {
  try {
    return typeof localStorage !== 'undefined' ? localStorage : null;
  } catch {
    return null;
  }
}

function mirror(key: string): string {
  const s = store();
  if (!s) return '';
  try {
    return s.getItem(key) || '';
  } catch {
    return '';
  }
}

function currentChain(): string {
  return activeChain || mirror(ACTIVE_CHAIN_KEY);
}

function currentBroker(): string {
  return activeBroker || mirror(ACTIVE_BROKER_KEY);
}

// The broker's identity for namespacing: its host (incl. port — a
// localhost:8091 dev broker stays distinct). Falls back to the raw string so
// an unparseable value still namespaces rather than silently collapsing two
// stacks into one key.
export function brokerScope(brokerUrl: string): string {
  const raw = brokerUrl.trim();
  if (!raw) return '';
  try {
    return new URL(raw).host || raw;
  } catch {
    return raw;
  }
}

// `<base>:<chain>@<broker-host>` once the stack is known; `<base>:<chain>`
// while only the chain is (brokerless daemon = the pre-#373 keying); the bare
// legacy key until the very first bind (pre-#313 identities still read before
// migration).
function scopedKey(base: string): string {
  const c = currentChain();
  if (!c) return base;
  const b = currentBroker();
  return b ? `${base}:${c}@${b}` : `${base}:${c}`;
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

// Per-stack wipe (reset master): clears only the ACTIVE (chain, broker)
// pointers, so a reset on one stack leaves every other stack's master
// untouched — including the same chain behind another broker.
export function clearMasterIdentity(): void {
  clear(CRED_ID);
  clear(OMNI);
  clear(ONBOARDED);
}

// Bind subsequent reads/writes to (chain, brokerUrl) and migrate any
// pre-namespacing pointers into it. One-shot per generation: for each base
// key, the newest existing generation wins and older ones are removed after
// adoption, so a later switch to another stack can't re-adopt them.
// A brokerless daemon binds chain-only (the pre-#373 behavior, no broker
// migration — chain-scoped keys stay authoritative for it).
export function setActiveStack(chain: string, brokerUrl: string): void {
  if (!chain) return;
  activeChain = chain;
  activeBroker = brokerScope(brokerUrl);
  const s = store();
  if (!s) return;
  try {
    s.setItem(ACTIVE_CHAIN_KEY, chain);
    if (activeBroker) s.setItem(ACTIVE_BROKER_KEY, activeBroker);
    else s.removeItem(ACTIVE_BROKER_KEY);
  } catch {
    /* non-fatal */
  }
  for (const base of NAMESPACED) {
    try {
      const target = scopedKey(base);
      // Older-generation keys, newest first: chain-scoped (pre-#373), bare
      // (pre-#313). Adopt the newest present into the target, then remove
      // every older generation so it can't be re-adopted by another stack.
      const legacyKeys = [`${base}:${chain}`, base].filter((k) => k !== target);
      const adopted = legacyKeys
        .map((k) => ({ k, v: s.getItem(k) }))
        .find((e) => e.v !== null);
      if (adopted && s.getItem(target) === null) s.setItem(target, adopted.v as string);
      if (adopted) for (const k of legacyKeys) s.removeItem(k);
    } catch {
      /* non-fatal */
    }
  }
}

// Back-compat shim for chain-only callers (kept so a brokerless code path
// still binds; new code passes the broker via setActiveStack).
export function setActiveChain(chain: string): void {
  setActiveStack(chain, '');
}

// Resolve the live daemon stack once per page load and bind the store to it.
// No memoization on failure: it retries until a non-empty chain is returned,
// so a daemon that connects after first paint still binds. A stack switch is
// a full reload, which resets the cache and re-derives it here.
export async function ensureActiveStack(
  getStack: () => Promise<{ chain: string | null; brokerUrl: string | null }>,
): Promise<void> {
  if (activeChain) return;
  let stack: { chain: string | null; brokerUrl: string | null };
  try {
    stack = await getStack();
  } catch {
    stack = { chain: null, brokerUrl: null };
  }
  if (stack.chain) setActiveStack(stack.chain, stack.brokerUrl || '');
}

// Test-only: drop the in-memory binding so each test rebinds from scratch
// (module state would otherwise leak across cases).
export function resetActiveStackForTests(): void {
  activeChain = '';
  activeBroker = '';
}
