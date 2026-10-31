// Agent Terrier · 小荔管家 — shared React component library.
// Thin, typed wrappers over the design-system CSS kit (css/components.css), so
// every app renders the same primitives from one place. React is an OPT-IN peer:
// the framework-free CSS/token core stays portable; this `/react` subpath is the
// React layer. Import: `import { Button, ThemeSwitcher } from '@agentkeys/design-system/react'`.

import type { ButtonHTMLAttributes, HTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';
import { BRAND_THEMES } from '../tokens';
import type { CategoryKey, Theme, ThemeName } from '../tokens';
import { Icon } from './icons';
import type { IconName } from './icons';

// Re-export the token core + icons so consumers have one import surface.
export * from '../tokens';
export { Icon, TerrierLogo, ICON_NAMES } from './icons';
export type { IconName } from './icons';

const cx = (...parts: Array<string | false | undefined>) => parts.filter(Boolean).join(' ');

// ── Buttons ──────────────────────────────────────────────────────────────────
export type ButtonVariant = 'primary' | 'secondary' | 'ink' | 'add' | 'destructive';
export function Button({
  variant = 'secondary',
  className,
  ...props
}: { variant?: ButtonVariant } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button className={cx('ds-btn', `ds-btn--${variant}`, className)} {...props} />;
}

// ── Badges & status ──────────────────────────────────────────────────────────
export function Badge({
  kind = 'high',
  className,
  ...props
}: { kind?: 'high' | 'ai' } & HTMLAttributes<HTMLSpanElement>) {
  return <span className={cx('ds-badge', `ds-badge--${kind}`, className)} {...props} />;
}

export function Status({ tone, children }: { tone: 'allow' | 'blocked'; children: ReactNode }) {
  return <span className={cx('ds-status', `ds-status--${tone}`)}>{children}</span>;
}

export type ValueTone = 'read' | 'ask' | 'off';
export function ValuePill({ tone, children }: { tone: ValueTone; children: ReactNode }) {
  return <span className={cx('ds-val', `ds-val--${tone}`)}>{children}</span>;
}

// ── Surfaces ─────────────────────────────────────────────────────────────────
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cx('ds-card', className)} {...props} />;
}
export function Panel({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cx('ds-panel', className)} {...props} />;
}

// ── Toggle ───────────────────────────────────────────────────────────────────
export function Toggle({ checked, onChange }: { checked: boolean; onChange?: (next: boolean) => void }) {
  return (
    <button type="button" role="switch" aria-checked={checked} className="ds-toggle" onClick={() => onChange?.(!checked)}>
      <span />
    </button>
  );
}

// ── Segmented control ────────────────────────────────────────────────────────
export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: Array<{ value: T; label: string }>;
  value: T;
  onChange?: (next: T) => void;
}) {
  return (
    <div className="ds-seg">
      {options.map((o) => (
        <button key={o.value} aria-selected={o.value === value} onClick={() => onChange?.(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

// ── Inputs ───────────────────────────────────────────────────────────────────
export function TextInput({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx('ds-input', className)} {...props} />;
}
export function SearchField({ placeholder = 'Search' }: { placeholder?: string }) {
  return (
    <span className="ds-search">
      <Icon name="search" size={16} />
      {placeholder}
    </span>
  );
}

// ── Category tile + permission row ───────────────────────────────────────────
const CATEGORY_ICON: Record<CategoryKey, IconName> = {
  personal: 'person',
  family: 'people',
  work: 'briefcase',
  travel: 'pin',
  spending: 'spend',
  email: 'email',
  smarthome: 'home',
};

export function CategoryTile({ category }: { category: CategoryKey }) {
  return (
    <span className={cx('ds-cat', `ds-cat--${category}`)}>
      <Icon name={CATEGORY_ICON[category]} size={18} />
    </span>
  );
}

export function PermissionRow({
  category,
  name,
  sub,
  value,
  valueTone,
  high,
  highLabel = 'HIGH',
}: {
  category: CategoryKey;
  name: string;
  sub?: string;
  value: string;
  valueTone: ValueTone;
  high?: boolean;
  highLabel?: string;
}) {
  return (
    <div className="ds-perm-row">
      <span className={cx('ds-perm-row__tile', `ds-cat--${category}`)}>
        <Icon name={CATEGORY_ICON[category]} size={17} />
      </span>
      <div className="ds-perm-row__body">
        <div className="ds-perm-row__name">
          {name}
          {high && <Badge kind="high">{highLabel}</Badge>}
        </div>
        {sub && <div className="ds-perm-row__sub">{sub}</div>}
      </div>
      <ValuePill tone={valueTone}>{value}</ValuePill>
      <span className="ds-perm-row__chev">›</span>
    </div>
  );
}

// ── Theme switcher ───────────────────────────────────────────────────────────
/** The color-set swatches a product offers — the brand sets by default; pass
 *  `themes` (e.g. `THEMES`) to offer every set, the console's surface included. */
export function ThemeSwitcher({ value, onChange, themes = BRAND_THEMES }: { value: ThemeName; onChange: (theme: ThemeName) => void; themes?: readonly Theme[] }) {
  return (
    <div role="group" aria-label="Theme" style={{ display: 'inline-flex', gap: 8 }}>
      {themes.map((t) => (
        <button
          key={t.name}
          title={t.label}
          aria-pressed={t.name === value}
          onClick={() => onChange(t.name)}
          style={{
            width: 26,
            height: 26,
            borderRadius: 8,
            background: t.primary,
            cursor: 'pointer',
            border: t.name === value ? '2px solid var(--ds-text)' : '2px solid var(--ds-border-strong)',
          }}
        />
      ))}
    </div>
  );
}

// ── Language switcher (EN ⇄ 中文) ─────────────────────────────────────────────
export type Locale = 'en' | 'zh';
export const LANGS: ReadonlyArray<{ value: Locale; label: string }> = [
  { value: 'en', label: 'EN' },
  { value: 'zh', label: '中文' },
];

/** EN ⇄ 中文 segmented switch — the shared language toggle for every app.
 *  Labels default to "EN" / "中文"; pass `labels` to localize them. */
export function LangSwitcher({
  value,
  onChange,
  labels,
}: {
  value: Locale;
  onChange: (next: Locale) => void;
  labels?: Record<Locale, string>;
}) {
  const ls = labels ?? { en: 'EN', zh: '中文' };
  return (
    <div className="ds-seg" role="group" aria-label="Language">
      {(['en', 'zh'] as Locale[]).map((loc) => (
        <button key={loc} aria-selected={value === loc} onClick={() => onChange(loc)}>
          {ls[loc]}
        </button>
      ))}
    </div>
  );
}

// Shared card renderer.
export { CardView, CARD_TAP_HOLD_MS, cardAge, cardTapGate, cardText } from './card-view';
export type {
  CardLocale,
  CardViewAction,
  CardViewAlert,
  CardViewDocument,
  CardViewItem,
  CardViewMetric,
  CardViewSection,
} from './card-view';
