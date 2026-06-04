import type { ChipKind, Namespace } from '@/app/_components/types';

export const NAMESPACES: Namespace[] = ['personal', 'family', 'work', 'travel'];

// The cap/scope "service" string for a memory namespace is namespace-qualified
// (arch.md §896, issue #147): `memory:<ns>`. It is a SIGNED cap field — the
// broker hashes it (`keccak`) for `isServiceInScope`, the worker keys storage
// off it (`bots/<actor>/memory/memory:<ns>.enc`), and the grant must match
// exactly. A bare `memory` never matches a `memory:<ns>` grant →
// `service_not_in_scope`. Use this wherever a memory cap/scope service is built
// (pairing claim `requested_scope`, scope grant, cap-mint `req.service`).
export function memoryService(ns: string): string {
  return `memory:${ns}`;
}

export const CHIP_STYLES: Record<ChipKind, string> = {
  default: 'chip',
  ok: 'chip ok',
  warn: 'chip warn',
  bad: 'chip bad',
  memory: 'chip',
  creds: 'chip',
  audit: 'chip',
  broker: 'chip',
  chain: 'chip ok',
  payment: 'chip warn',
  revoke: 'chip bad',
  scope: 'chip',
  device: 'chip',
  k11: 'chip',
};
