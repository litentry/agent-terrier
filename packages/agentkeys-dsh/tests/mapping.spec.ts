import { describe, expect, it } from 'vitest';
import {
  advertisedGrantPrefix,
  classifyTool,
  holdsGrantWithPrefix,
  PROPOSE_ACTION,
  PROPOSE_SERVICE_PREFIX,
  PUBLISH_ACTION,
  PUBLISH_SERVICE_PREFIX,
  registerAdvertised,
} from '../src/mapping.js';
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
  const cfg = {};
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

describe('advertised actions (the daemon\u2019s verbs)', () => {
  it('the two shipped verbs are advertised by default, each allowed by ANY grant of its family, never by a tool class', () => {
    expect(classifyTool('propose_to_owner')).toEqual({ kind: 'advertised', requiresPrefix: 'proposal:' });
    expect(classifyTool('publish_to_slot')).toEqual({ kind: 'advertised', requiresPrefix: 'channel-pub:' });
    expect(decide('propose_to_owner', view('proposal:app-chef'), true, {})).toEqual({ kind: 'allow' });
    expect(decide('propose_to_owner', view('PROPOSAL:family', 'tool:web'), true, {})).toEqual({ kind: 'allow' });
    expect(decide('publish_to_slot', view('channel-pub:kitchen-display'), true, {})).toEqual({ kind: 'allow' });
    expect(decide('publish_to_slot', view('CHANNEL-PUB:opchat-chef', 'tool:web'), true, {})).toEqual({ kind: 'allow' });
    const noProposal = decide('propose_to_owner', view('tool:web', 'knowledge:family', 'channel-pub:kitchen-display'), true, {});
    expect(noProposal.kind).toBe('deny');
    expect(JSON.stringify(noProposal)).toContain('proposal:<\u2026> grant');
    const noFeed = decide('publish_to_slot', view('tool:web', 'tool:code', 'channel-sub:kitchen-display'), true, {});
    expect(noFeed.kind).toBe('deny');
    expect((noFeed as { reason?: string }).reason).toContain('channel-pub:<\u2026> grant');
    // fail closed without a grant view
    expect(decide('propose_to_owner', view('proposal:x'), false, {}).kind).toBe('deny');
    expect(decide('publish_to_slot', view('channel-pub:x'), false, {}).kind).toBe('deny');
    // never asked: an allow-once cannot mint a feed or a namespace
    expect(answer('publish_to_slot', 'c', view(), true, {}, { record: () => {}, propose: () => { throw new Error('no propose'); } })).toBe('rejected');
  });

  it('the daemon\u2019s advertisement REPLACES the seeded set (name \u2192 grant family)', () => {
    registerAdvertised([
      { name: 'publish_to_slot', requires_grant_prefix: 'channel-pub:' },
      { name: 'file_to_inbox', requires_grant_prefix: 'Proposal:' },
    ]);
    try {
      expect(classifyTool('file_to_inbox')).toEqual({ kind: 'advertised', requiresPrefix: 'proposal:' });
      expect(advertisedGrantPrefix('propose_to_owner')).toBeUndefined();
      expect(classifyTool('propose_to_owner')).toEqual({ kind: 'unmapped' });
      expect(holdsGrantWithPrefix(view('proposal:app-chef'), 'PROPOSAL:')).toBe(true);
      expect(holdsGrantWithPrefix(view('knowledge:app-chef'), 'proposal:')).toBe(false);
    } finally {
      registerAdvertised([
        { name: PUBLISH_ACTION, requires_grant_prefix: PUBLISH_SERVICE_PREFIX },
        { name: PROPOSE_ACTION, requires_grant_prefix: PROPOSE_SERVICE_PREFIX },
      ]);
    }
  });
});

describe('hidden tools (#726)', () => {
  it('remember is hidden, not baseline, while the other OpenViking tools stay baseline', () => {
    expect(classifyTool('mcp__openviking__remember')).toEqual({ kind: 'hidden' });
    expect(classifyTool('viking_remember')).toEqual({ kind: 'hidden' });
    expect(classifyTool('mcp__openviking__write')).toEqual({ kind: 'baseline' });
    expect(classifyTool('mcp__openviking__search')).toEqual({ kind: 'baseline' });
  });

  it('the guard denies it whatever the grants, and names the write tool instead', () => {
    const decision = decide('mcp__openviking__remember', view('tool:web', 'tool:code'), true, {});
    expect(decision.kind).toBe('deny');
    expect((decision as { reason?: string }).reason).toMatch(/#726/);
    expect((decision as { reason?: string }).reason).toMatch(/mcp__openviking__write/);
    expect(decide('mcp__openviking__remember', view(), false, {}).kind).toBe('deny');
  });
});
