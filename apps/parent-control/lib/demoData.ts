// Config + the one allowed mock (audit tx-decode, tracked in GH #153).
// ALL fabricated user data (actors, audit events, memory, pairing requests,
// vault) was removed — the app is now driven entirely by the lib/client seam
// (real daemon data, empty states otherwise). See docs/plan/web-flow/issue-9step-flow.md.

import type { CeremonyStep, ChainProfile } from '@/app/_components/types';

// Pairing ceremony narration (the §10.2 master-claim → bind → grant steps).
// Process text only — shown while the real on-chain bind/grant runs.
export const PAIRING_STEPS: CeremonyStep[] = [
  { label: 'Verify pairing code', sub: 'broker matches the agent-shown code → unbound request (method A)', onchain: false },
  { label: 'Attest agent device', sub: 'fetch D_pub_agent · verify pop_sig (proof-of-possession)', onchain: false },
  { label: 'Derive child actor', sub: 'HDKD //label → O_master//label · public + recomputable', onchain: false },
  { label: 'Register agent device', sub: 'SidecarRegistry.registerAgentDevice(tier=AGENT, roles=CAP_MINT)', onchain: true, fn: 'registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)' },
  { label: 'Grant scope (Touch ID)', sub: 'AgentKeysScope.setScopeWithWebauthn(... requested scope ...)', onchain: true, fn: 'setScopeWithWebauthn(bytes32,bytes32,bytes,bytes)' },
  { label: 'Mint initial cap-tokens', sub: 'scoped cap-token · ttl 900s', onchain: false },
  { label: 'Ack binding', sub: 'POST /v1/agent/pending-bindings/ack → clears the rendezvous', onchain: false },
];

// Chain deployment config (real Heima params; contract addresses are filled by
// the operator's deployment — informational, used for explorer links in the
// audit tx-decode modal below).
export const CHAIN_PROFILE: ChainProfile = {
  name: 'heima',
  display: 'Heima Network · Litentry parachain mainnet',
  chainId: 212013,
  kind: 'substrate-frontier',
  rpc: 'https://rpc.heima.network',
  wss: 'wss://rpc.heima.network',
  substrateWss: 'wss://rpc.heima.network',
  explorer: 'https://explorer.heima.network',
  tokenSymbol: 'HEI',
  tokenDecimals: 18,
  finality: 'latest (instant)',
  block: '—',
  contracts: [
    { name: 'AgentKeysScope', addr: '—', deployedAt: '—', purpose: 'per-actor scope grants — services, namespaces, time-windows' },
    { name: 'SidecarRegistry', addr: '—', deployedAt: '—', purpose: 'D_pub ↔ (operator_omni, actor_omni, roles) bindings + K11 cred storage' },
    { name: 'K3EpochCounter', addr: '—', deployedAt: '—', purpose: 'current K3 epoch; bumps trigger KEK derivation rotation' },
    { name: 'CredentialAudit', addr: '—', deployedAt: '—', purpose: 'per-actor audit log + tier-2 Merkle root anchor every 2 min' },
  ],
};

// ─── Audit tx-decode — the ONE retained mock (real decode = GH #153) ──
// Deterministic placeholder tx hash + a kind→selector/signature map, used by
// the audit page's decode modal until the real CBOR + ABI decoder lands (#153).
export function txHash(seed: string): string {
  let h = 0;
  const s = String(seed);
  for (let i = 0; i < s.length; i++) h = (((h << 5) - h + s.charCodeAt(i)) | 0);
  const hex = (n: number) => Math.abs(n).toString(16).padStart(8, '0');
  return '0x' + hex(h) + hex(h * 7 + 13) + hex(h * 31 + 5) + hex(h * 131 + 9);
}

const CALLDATA_MAP: Record<string, { sel: string; fn: string }> = {
  'memory.read': { sel: '0x6c1a9f33', fn: 'memoryRead(bytes32,bytes32)' },
  'memory.write': { sel: '0x9d2bce10', fn: 'memoryWrite(bytes32,bytes32,bytes32)' },
  'cred.fetch': { sel: '0x3a7f10cd', fn: 'credentialFetch(bytes32,bytes32)' },
  'cap.mint': { sel: '0x1f4c0a92', fn: 'capMint(bytes32,uint8,uint64)' },
  'cap.revoked': { sel: '0xa98bbce0', fn: 'capRevoke(bytes32,bytes32)' },
  'device.revoked': { sel: '0xd34c7e11', fn: 'revokeDevice(bytes32,bytes[])' },
  'audit.append': { sel: '0x0c44b209', fn: 'append(bytes32,bytes32,bytes32)' },
  'anchor.batch': { sel: '0x77ae5d8c', fn: 'appendRoot(bytes32,uint32)' },
  'cap.pair': { sel: '0x2bd1f409', fn: 'registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)' },
  'device.paired': { sel: '0x2bd1f409', fn: 'registerAgentDevice(bytes32,bytes32,bytes32,bytes,bytes)' },
  'scope.grant': { sel: '0x8e21c4aa', fn: 'setScopeWithWebauthn(bytes32,bytes32,bytes,bytes)' },
  'payment.attempt': { sel: '0x4f0ab219', fn: 'paymentExecute(bytes32,uint256,bytes32)' },
};

// MOCK calldata decode (event-kind → selector + signature). Real decode = GH #153.
export function decodeCalldata(ev: { kind: string }): { sel: string; fn: string } {
  return CALLDATA_MAP[ev.kind] || { sel: '0x00000000', fn: (ev.kind || 'event') + '(bytes)' };
}

export const ONCHAIN_KINDS = new Set<string>([
  'anchor.batch', 'cap.mint', 'cap.revoked', 'device.revoked', 'cap.pair', 'scope.grant', 'audit.append',
]);

export function contractFor(kind: string): string {
  if (kind === 'anchor.batch' || kind === 'audit.append') return 'CredentialAudit';
  if (kind === 'scope.grant') return 'AgentKeysScope';
  if (kind === 'cap.pair' || kind === 'device.revoked') return 'SidecarRegistry';
  return 'Broker';
}
