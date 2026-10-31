// Agent Terrier · 小荔管家 design tokens — typed export for JS/TS consumers
// (theme switchers, React style props, etc.). Mirrors css/tokens.css + tokens.json.
// Source of truth: design-system/tokens.json.

export type ThemeName = 'meadow' | 'terracotta' | 'forest' | 'github';

export interface Theme {
  name: ThemeName;
  label: string;
  default: boolean;
  primary: string;
  secondary: string;
  background: string;
  onPrimary: string;
}

/** The switchable color sets. Meadow is the brand default; `github` is the
 *  neutral, system-font surface the parent-control console uses (2026-09-16 —
 *  its fonts / neutrals / radii overrides live in tokens.json + tokens.css only).
 *  The array between the @ds-generated markers is written by the curator
 *  (scripts/generate-tokens.mjs, from tokens.json) — don't hand-edit it. */
/* @ds-generated:themes */
export const THEMES: readonly Theme[] = [
  { name: 'meadow', label: 'Meadow', default: true, primary: '#cebd09', secondary: '#7da83e', background: '#fcfff0', onPrimary: '#1c1a08' },
  { name: 'terracotta', label: 'Terracotta', default: false, primary: '#c2622f', secondary: '#3e6fb0', background: '#f5efe4', onPrimary: '#ffffff' },
  { name: 'forest', label: 'Forest', default: false, primary: '#3e7d5b', secondary: '#c2843a', background: '#f1f1e7', onPrimary: '#ffffff' },
  { name: 'github', label: 'GitHub', default: false, primary: '#0969da', secondary: '#1f883d', background: '#ffffff', onPrimary: '#ffffff' },
] as const;
/* @ds-generated:end */

export const DEFAULT_THEME: ThemeName = 'meadow';

/** The brand color sets a product switcher offers — every theme but the
 *  console's `github` surface (the gallery + curator still list all of them). */
export const BRAND_THEMES: readonly Theme[] = THEMES.filter((t) => t.name !== 'github');

export const FONTS = {
  display: "'Bricolage Grotesque', sans-serif",
  body: "'Hanken Grotesk', sans-serif",
  displayCn: "'Noto Serif SC', serif",
  bodyCn: "'Noto Sans SC', sans-serif",
  cn: "'Noto Sans SC', sans-serif",
  mono: 'ui-monospace, Menlo, monospace',
} as const;

/** Permission-state semantics (shared across themes). */
export const SEMANTIC = {
  allow: '#2f7d5b',
  ask: '#b07a1e',
  off: '#9a9087',
  blocked: '#b4472e',
} as const;

/** Fixed identity color per permission category (independent of active theme). */
export const CATEGORY_COLORS = {
  personal: '#3e7d5b',
  family: '#4f86c6',
  work: '#8a6fb0',
  travel: '#2ba39b',
  spending: '#c2622f',
  email: '#b0843a',
  smarthome: '#6e8b3d',
} as const;
export type CategoryKey = keyof typeof CATEGORY_COLORS;

export const RADII = {
  tile: '8px',
  field: '11px',
  card: '14px',
  panel: '18px',
  hero: '24px',
  pill: '999px',
} as const;

/** Apply a theme by setting `data-theme` on an element (default: <html>). */
export function applyTheme(name: ThemeName, el: { dataset: DOMStringMap } = document.documentElement): void {
  el.dataset.theme = name;
}
