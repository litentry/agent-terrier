import type { MasterMemoryEntry } from '@/lib/client/types';

// The canonical PREPARED memory archive the operator imports on first run.
//
// This is NOT display mock data (the kind stripped from demoData.ts). It is the
// real, documented demo dataset that the rest of the system already uses — the
// "Chengdu trip" the agent-side wire demo seeds (e2e/suite-5-wire-real.sh
// SEED_MEMORY_CONTENT) plus the per-namespace composition from the IAM strategy
// (docs/agent-iam-strategy.md §3.5). The plant button POSTs these entries through
// the real client seam → daemon `POST /v1/master/memory/plant` (content-hash
// dedup, idempotent) → master memory store. Re-planting is a server-side no-op.
const RAW: { ns: MasterMemoryEntry['ns']; key: string; title: string; body: string; updated: string }[] = [
  { ns: 'travel', key: 'chengdu-trip', title: 'Chengdu trip', body: 'Chengdu trip — Apr 12 to 16, hotpot at Yulin.', updated: '2026-04-02' },
  { ns: 'travel', key: 'chengdu-customs', title: 'Chengdu customs clearance', body: 'Asked about Chengdu customs clearance for the trip.', updated: '2026-04-02' },
  { ns: 'personal', key: 'profile', title: 'Profile', body: 'Lives in Shanghai, allergic to peanuts.', updated: '2026-04-01' },
  { ns: 'family', key: 'anniversary', title: 'Anniversary dinner', body: 'Anniversary dinner reservation 2026-06-15.', updated: '2026-04-01' },
];

const byteLen = (s: string): number =>
  typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(s).length : s.length;

export const PREPARED_MEMORY: MasterMemoryEntry[] = RAW.map((r) => ({
  ns: r.ns,
  key: r.key,
  title: r.title,
  body: r.body,
  preview: r.body,
  version: 'v1',
  updated: r.updated,
  bytes: byteLen(r.body),
}));
