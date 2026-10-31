import type { CSSProperties } from 'react';

// Shared icons inherit the surrounding text color.
const PATHS = {
  person: '<circle cx="12" cy="8" r="4"/><path d="M5 21c0-4 3.5-6 7-6s7 2 7 6"/>',
  people:
    '<circle cx="9" cy="8" r="3.2"/><path d="M2.5 20c0-3.5 3-5 6.5-5s6.5 1.5 6.5 5"/><path d="M16 5.2A3.2 3.2 0 0 1 16 11.6M22 20c0-2.6-1.4-4.2-4-4.7"/>',
  briefcase:
    '<rect x="3" y="7.5" width="18" height="12" rx="2.2"/><path d="M8.5 7.5V6a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v1.5"/>',
  pin: '<path d="M12 21c4-4.5 7-8 7-11a7 7 0 1 0-14 0c0 3 3 6.5 7 11Z"/><circle cx="12" cy="10" r="2.5"/>',
  spend: '<rect x="2.5" y="6" width="19" height="12" rx="2.4"/><path d="M2.5 10h19"/>',
  email: '<rect x="3" y="5.5" width="18" height="13" rx="2.2"/><path d="M4 7l8 6 8-6"/>',
  home: '<path d="M4 11.5 12 4l8 7.5"/><path d="M6 10.5V20h12v-9.5"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.2-3.2"/>',
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  size = 20,
  stroke = 1.8,
  style,
}: {
  name: IconName;
  size?: number;
  stroke?: number;
  style?: CSSProperties;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ display: 'inline-flex', ...style }}
      dangerouslySetInnerHTML={{ __html: PATHS[name] }}
    />
  );
}

export const ICON_NAMES = Object.keys(PATHS) as IconName[];

/** The Agent Terrier line-art terrier mark (uses currentColor, so it themes). */
export function TerrierLogo({ size = 40, style }: { size?: number; style?: CSSProperties }) {
  return (
    <svg width={size} height={size} viewBox="0 0 1024 1024" fill="none" role="img" aria-label="Agent Terrier" style={style}>
      <g fill="none" stroke="currentColor" strokeWidth={22} strokeLinecap="round" strokeLinejoin="round">
        <path id="ds-terrier-ear" strokeLinecap="butt" d="M253 373c-33 5-54 70-80 152-34 108-60 200-68 278-4 42 21 76 61 88s102 2 130-76" />
        <use href="#ds-terrier-ear" transform="matrix(-1 0 0 1 1024 0)" />
        <path d="M260 374C260 226 372 124 512 124s252 102 252 250c0 25-6 51-17 74 11 52 26 118 35 178 14 94-11 150-54 189-51 43-127 61-216 61s-165-18-216-61c-43-39-68-95-54-189 9-60 24-126 35-178-11-23-17-49-17-74Z" />
      </g>
      <ellipse cx="352" cy="466" rx="29" ry="43" fill="currentColor" />
      <ellipse cx="673" cy="466" rx="29" ry="43" fill="currentColor" />
      <path d="M431 744c-4-18 22-26 81-26s85 8 81 26c-7 38-51 87-81 92-30-5-74-54-81-92Z" fill="currentColor" />
    </svg>
  );
}
