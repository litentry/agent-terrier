import type { ChipKind, Namespace } from '@/app/_components/types';

export const NAMESPACES: Namespace[] = ['personal', 'family', 'work', 'travel'];

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
