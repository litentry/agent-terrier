// The display's operator-editable settings — kept in localStorage, overridable
// once from the URL (`?broker=…&feed=…&label=…&lang=zh`) so a tablet can be
// provisioned by opening one link. No default broker: an unconfigured display
// shows the settings screen instead of silently pointing at some stack.

export type Locale = 'en' | 'zh';
export type ThemeName = 'meadow' | 'terracotta' | 'forest';

export interface Settings {
  /** The broker base URL, e.g. https://test-broker.agentterrier.cn */
  brokerUrl: string;
  /** The display feed this device listens on + commands into (the app's display slot). */
  feedId: string;
  /** The device label the owner will see when claiming the pairing code. */
  label: string;
  locale: Locale;
  theme: ThemeName;
}

export const SETTINGS_KEY = 'agentkeys.display.settings';

export const DEFAULT_SETTINGS: Settings = {
  brokerUrl: '',
  feedId: 'kitchen-display',
  label: 'kitchen-display',
  locale: 'en',
  theme: 'meadow',
};

type StorageLike = Pick<Storage, 'getItem' | 'setItem'>;

/** `https://host[:port]` — trimmed, no trailing slash, http(s) only; '' when invalid. */
export function normalizeBrokerUrl(raw: string): string {
  const s = raw.trim().replace(/\/+$/, '');
  if (!/^https?:\/\/[^/\s]+$/.test(s)) return '';
  return s;
}

/** A feed / label id: lowercase `[a-z0-9-]`, 1–48 chars; '' when invalid. */
export function normalizeId(raw: string): string {
  const s = raw.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9-]{0,47}$/.test(s) ? s : '';
}

export function loadSettings(storage: StorageLike | null, search: string): Settings {
  let stored: Partial<Settings> = {};
  try {
    const raw = storage?.getItem(SETTINGS_KEY);
    if (raw) stored = JSON.parse(raw) as Partial<Settings>;
  } catch {
    stored = {};
  }
  const q = new URLSearchParams(search);
  const merged: Settings = { ...DEFAULT_SETTINGS, ...stored };
  const broker = q.get('broker');
  if (broker !== null) merged.brokerUrl = normalizeBrokerUrl(broker);
  const feed = q.get('feed');
  if (feed !== null && normalizeId(feed)) merged.feedId = normalizeId(feed);
  const label = q.get('label');
  if (label !== null && normalizeId(label)) merged.label = normalizeId(label);
  const lang = q.get('lang');
  if (lang === 'en' || lang === 'zh') merged.locale = lang;
  const theme = q.get('theme');
  if (theme === 'meadow' || theme === 'terracotta' || theme === 'forest') merged.theme = theme;
  return merged;
}

export function saveSettings(storage: StorageLike | null, s: Settings): void {
  try {
    storage?.setItem(SETTINGS_KEY, JSON.stringify(s));
  } catch {
    /* private mode / quota — the in-memory copy still drives this session */
  }
}
