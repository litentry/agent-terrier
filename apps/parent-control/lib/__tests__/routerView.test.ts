import { describe, expect, it } from 'vitest';
import { normalizeRouterView, type RouterViewWire } from '../routerView';

// The route tab reads contact gates of either version: the console runs from a
// laptop checkout, the gate on the broker host, and they are deployed apart.

const base = {
  ok: true,
  engine: 'jev',
  model: 'kev-9b@2629c06',
  gate_url: 'http://127.0.0.1:8077',
  threshold: 0.5,
  continue_threshold: 0.7,
  ask_ttl_secs: 600,
  describe_photos: true,
  describe_model: 'deepseek-v4-1-flash-260910',
  describe_prompt: '',
  guidance: { destination: '', unclear: '', continues: '', continues_yes: '', continues_no: '', addressee: '' },
  contacts: [],
};

describe('normalizeRouterView', () => {
  it('reads a gate from before the Kev / Jev switch without crashing (the 2026-10-05 VE prod shape)', () => {
    // The keys a pre-#749 gate sends — measured from VE prod's contact gate.
    const old = {
      ...base,
      upstream: { error: 'error sending request for url (http://127.0.0.1:8077/v1/systemone/models)' },
      recent: [
        {
          ts_ms: 1,
          contact: '妈妈',
          tier: 'owner',
          text: '今晚吃什么',
          photo: false,
          request: null,
          probabilities: { 'family-chat/chef': 0.9 },
          verdict: 'route',
          routed_to: 'family-chat',
          answered_by: 'kev-9b@2629c06',
          total_ms: 300,
          delivered: true,
        },
      ],
    } as RouterViewWire;
    const { view, legacy, legacyServer } = normalizeRouterView(old);
    expect(legacy).toBe(true);
    expect(view.models).toEqual([]);
    expect(view.compare).toBe(false);
    expect(view.default_model).toBe('kev-9b@2629c06');
    expect(view.recent[0].compared).toEqual([]);
    expect(view.recent.find((x) => x.compared.length > 0)).toBeUndefined();
    expect(view.models.find((m) => m.active)).toBeUndefined();
    expect(legacyServer?.error).toContain('error sending request');
    expect('upstream' in view).toBe(false);
  });

  it('keeps a reachable pre-switch server as the card shows it', () => {
    const { legacyServer } = normalizeRouterView({
      ...base,
      recent: [],
      upstream: { base_url: 'https://copilot.wildmeta.ai/kev', status: 200, models: { data: [{ id: 'kev-9b' }] } },
    } as RouterViewWire);
    expect(legacyServer).toMatchObject({ configured: true, base_url: 'https://copilot.wildmeta.ai/kev', status: 200 });
  });

  it('passes a current gate through unchanged', () => {
    const current: RouterViewWire = {
      ...base,
      default_model: 'kev-9b@2629c06',
      compare: true,
      models: [
        { model: 'kev-9b@2629c06', provider: 'kev', active: false, stack_default: true, server: { configured: true, status: 200 } },
        { model: 'jev-1.13.0', provider: 'jev', active: true, stack_default: false, server: { configured: true, status: 200 } },
      ],
      recent: [],
    };
    const { view, legacy, legacyServer } = normalizeRouterView(current);
    expect(legacy).toBe(false);
    expect(legacyServer).toBeUndefined();
    expect(view.compare).toBe(true);
    expect(view.models.find((m) => m.active)?.model).toBe('jev-1.13.0');
  });
});
