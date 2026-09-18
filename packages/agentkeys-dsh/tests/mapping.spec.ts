import { describe, expect, it } from 'vitest';
import { classifyTool } from '../src/mapping.js';
import { decide } from '../src/guard.js';
import { answer, proposeBody } from '../src/answerer.js';

const view = (...services: string[]) => new Set(services.map((s) => s.toLowerCase()));

describe('classifyTool', () => {
  it('splits baseline / classed / unmapped', () => {
    expect(classifyTool('read')).toEqual({ kind: 'baseline' });
    expect(classifyTool('viking_search')).toEqual({ kind: 'baseline' });
    expect(classifyTool('mcp__openviking__read')).toEqual({ kind: 'baseline' });
    expect(classifyTool('web_fetch')).toEqual({ kind: 'classed', toolClass: 'web', service: 'tool:web' });
    expect(classifyTool('bash')).toEqual({ kind: 'classed', toolClass: 'code', service: 'tool:code' });
    expect(classifyTool('schedule_create').kind).toBe('classed');
    expect(classifyTool('made_up_tool')).toEqual({ kind: 'unmapped' });
    // an MCP tool from a NON-openviking server is unmapped -> denied
    expect(classifyTool('mcp__github__create_issue')).toEqual({ kind: 'unmapped' });
  });
  it('honors config overrides', () => {
    const cfg = { toolClasses: { web: ['my_fetch'] }, baseline: ['only_this'] };
    expect(classifyTool('only_this', cfg)).toEqual({ kind: 'baseline' });
    expect(classifyTool('my_fetch', cfg).kind).toBe('classed');
    expect(classifyTool('read', cfg)).toEqual({ kind: 'unmapped' });
  });
});

describe('decide (guard core)', () => {
  it('allows baseline regardless of grant view', () => {
    expect(decide('read', view(), false, {})).toEqual({ kind: 'allow' });
  });
  it('fails closed while the grant view is unavailable', () => {
    const d = decide('web_fetch', view(), false, {});
    expect(d.kind).toBe('deny');
  });
  it('allows a granted class and asks for an ungranted one', () => {
    expect(decide('web_fetch', view('tool:web'), true, {})).toEqual({ kind: 'allow' });
    const d = decide('web_fetch', view('tool:code'), true, {});
    expect(d.kind).toBe('ask');
    expect((d as { reason?: string }).reason).toContain('tool:web');
  });
  it('denies unmapped tools by absence', () => {
    const d = decide('made_up_tool', view('tool:web'), true, {});
    expect(d.kind).toBe('deny');
    expect((d as { reason: string }).reason).toContain('deny by absence');
  });
});

describe('answer (answerer core)', () => {
  const cfg = { proposeCommand: '' } as never;
  it('grants once for a granted class and records the callId', () => {
    const recorded: string[] = [];
    const out = answer('web_fetch', 'call1', view('tool:web'), true, cfg, {
      record: (id) => recorded.push(id),
      propose: () => {
        throw new Error('must not propose when granted');
      },
    });
    expect(out).toBe('allowed-once');
    expect(recorded).toEqual(['call1']);
  });
  it('proposes then rejects for an ungranted class', () => {
    const proposed: string[] = [];
    const out = answer('web_fetch', 'call1', view(), true, cfg, {
      record: () => {
        throw new Error('must not record on reject');
      },
      propose: (s) => proposed.push(s),
    });
    expect(out).toBe('rejected');
    expect(proposed).toEqual(['tool:web']);
  });
  it('rejects unmapped and baseline asks, and never proposes while unavailable', () => {
    const propose = () => {
      throw new Error('no propose');
    };
    expect(answer('made_up', 'c', view(), true, cfg, { record: () => {}, propose })).toBe('rejected');
    expect(answer('read', 'c', view(), true, cfg, { record: () => {}, propose })).toBe('rejected');
    expect(answer('web_fetch', 'c', view(), false, cfg, { record: () => {}, propose })).toBe('rejected');
  });
  it('propose body names the service and the tool', () => {
    const body = proposeBody('tool:web', 'web_fetch');
    expect(body).toContain('tool:web');
    expect(body).toContain('web_fetch');
  });
});

describe('the propose action (propose_to_owner)', () => {
  it('is allowed by any proposal grant, denied without one, and never a class', () => {
    expect(classifyTool('propose_to_owner')).toEqual({ kind: 'propose' });
    expect(decide('propose_to_owner', view('proposal:app-chef'), true, {})).toEqual({ kind: 'allow' });
    expect(decide('propose_to_owner', view('PROPOSAL:family', 'tool:web'), true, {})).toEqual({ kind: 'allow' });
    const none = decide('propose_to_owner', view('tool:web', 'knowledge:family', 'channel-pub:kitchen-display'), true, {});
    expect(none.kind).toBe('deny');
    expect(JSON.stringify(none)).toContain('proposal:<ns> grant');
    expect(decide('propose_to_owner', view('proposal:x'), false, {}).kind).toBe('deny');
    expect(classifyTool('propose_to_owner', { proposeTools: ['other_propose'] })).toEqual({ kind: 'unmapped' });
    expect(classifyTool('other_propose', { proposeTools: ['other_propose'] })).toEqual({ kind: 'propose' });
  });
});

describe('the publish action (publish_to_slot)', () => {
  it('is its own verdict: allowed by ANY channel-pub grant, never by a tool class, denied without one', () => {
    expect(classifyTool('publish_to_slot')).toEqual({ kind: 'publish' });
    expect(decide('publish_to_slot', view('channel-pub:kitchen-display'), true, {})).toEqual({ kind: 'allow' });
    expect(decide('publish_to_slot', view('CHANNEL-PUB:opchat-chef', 'tool:web'), true, {})).toEqual({ kind: 'allow' });
    const none = decide('publish_to_slot', view('tool:web', 'tool:code', 'channel-sub:kitchen-display'), true, {});
    expect(none.kind).toBe('deny');
    expect((none as { reason?: string }).reason).toContain('channel-pub:<feed> grant');
    expect(decide('publish_to_slot', view('channel-pub:x'), false, {}).kind).toBe('deny');
    expect(classifyTool('publish_to_slot', { publishTools: ['other_publish'] })).toEqual({ kind: 'unmapped' });
    expect(classifyTool('other_publish', { publishTools: ['other_publish'] })).toEqual({ kind: 'publish' });
  });
});
