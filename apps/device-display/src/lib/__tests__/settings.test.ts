import { describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS, loadSettings, normalizeBrokerUrl, normalizeId, saveSettings, SETTINGS_KEY } from '../settings';

function memStorage() {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), map: m };
}

describe('settings', () => {
  it('normalizes the broker URL and ids', () => {
    expect(normalizeBrokerUrl(' https://test-broker.agentterrier.cn/ ')).toBe('https://test-broker.agentterrier.cn');
    expect(normalizeBrokerUrl('http://localhost:8091')).toBe('http://localhost:8091');
    expect(normalizeBrokerUrl('broker.example.test')).toBe('');
    expect(normalizeBrokerUrl('https://a.test/v1')).toBe('');
    expect(normalizeId(' Kitchen-Display ')).toBe('kitchen-display');
    expect(normalizeId('bad id!')).toBe('');
  });

  it('URL params override stored settings once; defaults fill the rest', () => {
    const st = memStorage();
    saveSettings(st, { ...DEFAULT_SETTINGS, brokerUrl: 'https://old.test', feedId: 'old-feed' });
    const s = loadSettings(st, '?broker=https://test-broker.agentterrier.cn/&feed=Kitchen-Display&lang=zh&theme=forest');
    expect(s).toEqual({
      brokerUrl: 'https://test-broker.agentterrier.cn',
      feedId: 'kitchen-display',
      label: 'kitchen-display',
      locale: 'zh',
      theme: 'forest',
    });
    expect(loadSettings(st, '')).toMatchObject({ brokerUrl: 'https://old.test', feedId: 'old-feed' });
    expect(loadSettings(null, '')).toEqual(DEFAULT_SETTINGS);
    expect(st.map.has(SETTINGS_KEY)).toBe(true);
  });
});
