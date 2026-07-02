// #373 stack-isolation negative tests: the master identity pointers must be
// namespaced per (chain, broker) — the SAME chain behind a DIFFERENT broker
// (Heima-AWS vs Heima-VE) must never see the other stack's credId / omni /
// onboarded flag. Plus the one-shot migration ladder: bare pre-#313 keys and
// chain-only pre-#373 keys adopt into the first (chain, broker) bound, then
// disappear.
import { beforeEach, describe, expect, it } from 'vitest';
import {
  brokerScope,
  clearMasterIdentity,
  getMasterCredId,
  getMasterOmni,
  getOnboardedFlag,
  resetActiveStackForTests,
  setActiveChain,
  setActiveStack,
  setMasterCredId,
  setMasterOmni,
  setOnboardedFlag,
} from '../identityStore';

// Minimal in-memory localStorage — identityStore only needs get/set/remove.
function freshStorage(): Storage {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => (m.has(k) ? (m.get(k) as string) : null),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: (i: number) => Array.from(m.keys())[i] ?? null,
    get length() {
      return m.size;
    },
  } as Storage;
}

const AWS = 'https://broker.litentry.org';
const VE = 'https://broker.agentterrier.ai';

beforeEach(() => {
  (globalThis as { localStorage?: Storage }).localStorage = freshStorage();
  resetActiveStackForTests();
});

describe('stack-scoped identity isolation (#373)', () => {
  it('same chain, different broker: pointers never leak across (Heima-AWS ↔ Heima-VE)', () => {
    setActiveStack('heima', AWS);
    setMasterCredId('cred-aws');
    setMasterOmni('0xaaa');
    setOnboardedFlag(true);

    // reload onto the VE stack (a stack switch is a full reload)
    resetActiveStackForTests();
    setActiveStack('heima', VE);
    expect(getMasterCredId()).toBe('');
    expect(getMasterOmni()).toBe('');
    expect(getOnboardedFlag()).toBe(false);

    setMasterCredId('cred-ve');
    setMasterOmni('0xbbb');

    // back to AWS: its identity is intact, not overwritten by the VE one
    resetActiveStackForTests();
    setActiveStack('heima', AWS);
    expect(getMasterCredId()).toBe('cred-aws');
    expect(getMasterOmni()).toBe('0xaaa');
    expect(getOnboardedFlag()).toBe(true);
  });

  it('reset wipes only the active stack, not the same chain on another broker', () => {
    setActiveStack('heima', AWS);
    setMasterCredId('cred-aws');
    resetActiveStackForTests();
    setActiveStack('heima', VE);
    setMasterCredId('cred-ve');

    clearMasterIdentity(); // active = Heima-VE

    expect(getMasterCredId()).toBe('');
    resetActiveStackForTests();
    setActiveStack('heima', AWS);
    expect(getMasterCredId()).toBe('cred-aws');
  });

  it('different chains stay isolated regardless of broker (the #313 guarantee holds)', () => {
    setActiveStack('heima', AWS);
    setMasterCredId('cred-heima');
    resetActiveStackForTests();
    setActiveStack('base', AWS);
    expect(getMasterCredId()).toBe('');
  });
});

describe('one-shot migration ladder', () => {
  it('adopts a chain-only pre-#373 pointer into the first (chain, broker), then removes it', () => {
    localStorage.setItem('ak_master_cred_id:heima', 'legacy-chain-scoped');

    setActiveStack('heima', AWS);
    expect(getMasterCredId()).toBe('legacy-chain-scoped');
    expect(localStorage.getItem('ak_master_cred_id:heima')).toBeNull();

    // a LATER bind to the VE stack cannot re-adopt it
    resetActiveStackForTests();
    setActiveStack('heima', VE);
    expect(getMasterCredId()).toBe('');
  });

  it('adopts a bare pre-#313 pointer and removes every older generation', () => {
    localStorage.setItem('ak_master_omni', '0xlegacy');

    setActiveStack('heima', AWS);
    expect(getMasterOmni()).toBe('0xlegacy');
    expect(localStorage.getItem('ak_master_omni')).toBeNull();
  });

  it('the chain-scoped generation outranks the bare one when both linger', () => {
    localStorage.setItem('ak_master_cred_id', 'bare');
    localStorage.setItem('ak_master_cred_id:heima', 'chain-scoped');

    setActiveStack('heima', AWS);
    expect(getMasterCredId()).toBe('chain-scoped');
    expect(localStorage.getItem('ak_master_cred_id')).toBeNull();
    expect(localStorage.getItem('ak_master_cred_id:heima')).toBeNull();
  });

  it('never clobbers an existing stack-scoped value with a legacy one', () => {
    localStorage.setItem(`ak_master_cred_id:heima@broker.litentry.org`, 'current');
    localStorage.setItem('ak_master_cred_id:heima', 'stale-legacy');

    setActiveStack('heima', AWS);
    expect(getMasterCredId()).toBe('current');
  });
});

describe('brokerless daemon (pre-#373 behavior preserved)', () => {
  it('keys stay chain-scoped and legacy chain keys are NOT broker-migrated', () => {
    setActiveChain('heima'); // no broker known
    setMasterCredId('cred-dev');
    expect(localStorage.getItem('ak_master_cred_id:heima')).toBe('cred-dev');
  });
});

describe('brokerScope', () => {
  it('namespaces by host incl. port, falling back to the raw string', () => {
    expect(brokerScope('https://broker.agentterrier.ai')).toBe('broker.agentterrier.ai');
    expect(brokerScope('http://localhost:8091/')).toBe('localhost:8091');
    expect(brokerScope('not a url')).toBe('not a url');
    expect(brokerScope('  ')).toBe('');
  });
});
