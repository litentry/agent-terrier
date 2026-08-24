/**
 * #617 — the owner-facing permission surfaces.
 *
 * Three pure helpers carry the load-bearing rules, so they are tested directly:
 *   · capabilityGrantCommit — a capability toggle must actually TAKE (set-replace
 *     means the preserve set has to subtract the capability hashes, exactly as
 *     the #541 channel commit subtracts channel hashes)
 *   · TOOL_CLASSES / isPluginService — only what the guard understands is
 *     toggleable; plugin mounts are disclosure, never a switch
 *   · runtimeActivityLine — denials are SHOWN, in owner language
 */
import { describe, expect, it } from 'vitest';
import {
  capabilityGrantCommit,
  isCapabilityService,
  isPluginService,
  runtimeActivityLine,
  TOOL_CLASSES,
  toolService,
  OP_KIND_RUNTIME_APPROVAL,
  OP_KIND_RUNTIME_TOOL_RESULT,
} from '../../app/_components/types';

const actor = (over: Record<string, unknown> = {}): any => ({
  scope: { travel: { read: true, write: false } },
  services: ['tool:web', 'plugin:openviking-memory', 'channel-pub:cam', 'openrouter'],
  scopeCapabilityServiceIds: ['0xcap-web'],
  scopeChannelServiceIds: ['0xchan'],
  scopeUnknownServiceIds: ['0xcap-web', '0xchan', '0xcred'],
  ...over,
});

describe('capabilityGrantCommit (#617)', () => {
  it('subtracts capability hashes from preserve so a switch-OFF actually takes', () => {
    // staging an EMPTY tool set = the owner turned web off
    const { services, preserve } = capabilityGrantCommit(actor(), []);
    expect(services).not.toContain('tool:web');
    // the hash must NOT be echoed back, or setScope would re-add the grant
    expect(preserve).not.toContain('0xcap-web');
    // ...while every other preserved hash survives untouched
    expect(preserve).toEqual(expect.arrayContaining(['0xchan', '0xcred']));
  });

  it('restates memory, channels, creds and plugin mounts it does not own', () => {
    const { services } = capabilityGrantCommit(actor(), ['tool:web']);
    expect(services).toContain('memory:travel'); // from scope bits
    expect(services).toContain('channel-pub:cam');
    expect(services).toContain('openrouter');
    expect(services).toContain('plugin:openviking-memory'); // built-with rides along
    expect(services).toContain('tool:web');
  });

  it('adds a newly staged class without disturbing the rest', () => {
    const { services } = capabilityGrantCommit(actor(), ['tool:web', 'tool:schedule']);
    expect(services).toEqual(expect.arrayContaining(['tool:web', 'tool:schedule', 'memory:travel']));
  });

  it('writes inbox:<ns> for a write bit, mirroring the memory panel', () => {
    const { services } = capabilityGrantCommit(
      actor({ scope: { work: { read: true, write: true } } }),
      [],
    );
    expect(services).toEqual(expect.arrayContaining(['memory:work', 'inbox:work']));
  });
});

describe('toggleable surface (#617)', () => {
  it('offers exactly the classes the guard understands', () => {
    expect([...TOOL_CLASSES]).toEqual(['web', 'code', 'schedule']);
    for (const cls of TOOL_CLASSES) {
      expect(isCapabilityService(toolService(cls))).toBe(true);
      expect(isPluginService(toolService(cls))).toBe(false);
    }
  });

  it('treats plugin mounts as the read-only half', () => {
    expect(isPluginService('plugin:openviking-memory')).toBe(true);
    expect(isCapabilityService('plugin:openviking-memory')).toBe(true);
  });
});

describe('runtimeActivityLine (#617)', () => {
  it('names an allowed tool use plainly', () => {
    expect(runtimeActivityLine({ op_kind: OP_KIND_RUNTIME_TOOL_RESULT, op_body: { tool: 'web_fetch' }, result: 0 }))
      .toEqual({ text: 'Used web_fetch', denied: false });
  });

  it('shows failures and every non-grant outcome as denied', () => {
    expect(runtimeActivityLine({ op_kind: OP_KIND_RUNTIME_TOOL_RESULT, op_body: { tool: 'bash', is_error: true }, result: 1 })?.denied).toBe(true);
    for (const outcome of ['rejected', 'cancelled', 'unavailable']) {
      const line = runtimeActivityLine({ op_kind: OP_KIND_RUNTIME_APPROVAL, op_body: { tool: 'bash', outcome }, result: 1 });
      expect(line?.denied).toBe(true);
      expect(line?.text).toMatch(/bash/);
    }
  });

  it('renders the one-shot grant as a grant', () => {
    const line = runtimeActivityLine({ op_kind: OP_KIND_RUNTIME_APPROVAL, op_body: { tool: 'web_fetch', outcome: 'allowed-once' }, result: 0 });
    expect(line).toEqual({ text: 'Asked to use web_fetch — you allowed it once', denied: false });
  });

  it('leaves every other op_kind to the generic decode rows', () => {
    expect(runtimeActivityLine({ op_kind: 90, op_body: { tool: 'x' } })).toBeUndefined();
    expect(runtimeActivityLine({ op_kind: OP_KIND_RUNTIME_APPROVAL, op_body: {} })?.text).toMatch(/a tool/);
  });
});
