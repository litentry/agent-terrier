// Regenerate the theme region of css/tokens.css + tokens.ts from tokens.json.
// tokens.json `themes` is the SOURCE OF TRUTH for theme colors; this keeps the
// CSS custom-property blocks and the typed THEMES array in sync. Run directly
// (`npm run generate`), or import { writeThemes } from the gallery curator's
// save endpoint. `onPrimary` is derived from the primary's luminance, so the
// curator only edits primary / secondary / background.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FILES = {
  json: resolve(DS, 'tokens.json'),
  css: resolve(DS, 'css/tokens.css'),
  ts: resolve(DS, 'tokens.ts'),
};
const START = '/* @ds-generated:themes */';
const END = '/* @ds-generated:end */';

const lum = (hex) => {
  const h = hex.replace('#', '');
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  return (r * 299 + g * 587 + b * 114) / 1000;
};
/** Dark ink on light primaries, white on dark. */
export const onPrimaryFor = (hex) => (lum(hex) > 150 ? '#1c1a08' : '#ffffff');

// A theme is a color trio by default; it MAY also carry its own fonts,
// neutrals, permission semantics and radii (the `github` theme does — a
// neutral, system-font surface the three brand themes never needed). Each
// optional group maps onto the shared --ds-* tokens, so a consumer that reads
// the tokens re-skins completely under [data-theme='<name>'].
const EXTRA = {
  fonts: { display: '--ds-font-display', body: '--ds-font-body' },
  paper: {
    card: '--ds-card', bar: '--ds-bar', tile: '--ds-tile', field: '--ds-field',
    border: '--ds-border', borderStrong: '--ds-border-strong',
    borderDashed: '--ds-border-dashed', borderSecondary: '--ds-border-secondary',
  },
  text: { default: '--ds-text', muted: '--ds-text-muted', faint: '--ds-text-faint' },
  semantic: {
    allow: '--ds-allow', ask: '--ds-ask', off: '--ds-off', blocked: '--ds-blocked',
    askTint: '--ds-ask-tint', offTint: '--ds-off-tint',
  },
  radii: {
    tile: '--ds-r-tile', field: '--ds-r-field', card: '--ds-r-card',
    panel: '--ds-r-panel', hero: '--ds-r-hero', pill: '--ds-r-pill',
  },
};

const cssBlock = (selector, t) => {
  const lines = [
    `  --ds-primary: ${t.primary};`,
    `  --ds-secondary: ${t.secondary};`,
    `  --ds-background: ${t.background};`,
    `  --ds-on-primary: ${t.onPrimary};`,
  ];
  for (const [group, map] of Object.entries(EXTRA)) {
    for (const [key, cssVar] of Object.entries(map)) {
      const v = t[group]?.[key];
      if (v != null) lines.push(`  ${cssVar}: ${v};`);
    }
  }
  return `${selector} {\n${lines.join('\n')}\n}`;
};

function cssRegion(themes) {
  const names = Object.keys(themes);
  const defName = names.find((n) => themes[n].default) ?? names[0];
  return [cssBlock(':root', themes[defName]), ...names.map((n) => cssBlock(`[data-theme='${n}']`, themes[n]))].join('\n');
}

function tsRegion(themes) {
  const rows = Object.entries(themes)
    .map(
      ([name, t]) =>
        `  { name: '${name}', label: '${t.label}', default: ${!!t.default}, ` +
        `primary: '${t.primary}', secondary: '${t.secondary}', background: '${t.background}', onPrimary: '${t.onPrimary}' },`,
    )
    .join('\n');
  return `export const THEMES: readonly Theme[] = [\n${rows}\n] as const;`;
}

function spliceRegion(text, replacement) {
  const s = text.indexOf(START);
  const e = text.indexOf(END);
  if (s === -1 || e === -1) throw new Error('@ds-generated markers not found — cannot regenerate');
  return text.slice(0, s + START.length) + '\n' + replacement + '\n' + text.slice(e);
}

/** Rewrite the generated regions in tokens.css + tokens.ts from tokens.json. */
export function regenerate() {
  const json = JSON.parse(readFileSync(FILES.json, 'utf8'));
  const { themes } = json;
  for (const t of Object.values(themes)) t.onPrimary = onPrimaryFor(t.primary);
  writeFileSync(FILES.css, spliceRegion(readFileSync(FILES.css, 'utf8'), cssRegion(themes)));
  writeFileSync(FILES.ts, spliceRegion(readFileSync(FILES.ts, 'utf8'), tsRegion(themes)));
  return themes;
}

/** Persist edited theme colors → tokens.json, then regenerate css + ts. Used by
 *  the curator save endpoint. `updates` = { <themeName>: { primary, secondary, background } }. */
export function writeThemes(updates) {
  const json = JSON.parse(readFileSync(FILES.json, 'utf8'));
  for (const [name, colors] of Object.entries(updates ?? {})) {
    const cur = json.themes[name];
    if (!cur) continue;
    cur.primary = colors.primary ?? cur.primary;
    cur.secondary = colors.secondary ?? cur.secondary;
    cur.background = colors.background ?? cur.background;
    cur.onPrimary = onPrimaryFor(cur.primary);
  }
  writeFileSync(FILES.json, `${JSON.stringify(json, null, 2)}\n`);
  regenerate();
  return json.themes;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  regenerate();
  // eslint-disable-next-line no-console
  console.log('✓ regenerated tokens.css + tokens.ts theme region from tokens.json');
}
