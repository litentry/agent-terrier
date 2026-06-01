'use client';

import { useState } from 'react';
import { Panel, PageHead } from './shared';

type MarkProps = { size?: number; color?: string; stroke?: number };

// ─── V1 — Profile (the iconic Bedlington view) ───────────────────
function MarkProfile({ size = 320, color = '#1a1815', stroke = 1.5 }: MarkProps) {
  return (
    <svg width={size} height={size * 0.85} viewBox="0 0 240 204" fill="none" aria-label="Bedlington profile">
      <g stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M 58 130 C 50 110, 46 88, 50 70 C 38 58, 48 28, 78 26 C 86 12, 110 12, 118 24 C 130 12, 156 18, 158 42 C 168 44, 174 56, 172 68 C 172 78, 170 86, 174 92 C 188 98, 208 116, 218 138 C 222 148, 218 154, 210 154 L 200 152 C 196 158, 188 162, 178 161 L 152 158 C 138 158, 128 156, 118 152 L 96 148 C 84 144, 72 138, 58 130 Z" />
        <path d="M 62 50 C 70 38, 82 38, 88 46" />
        <path d="M 94 32 C 100 24, 112 24, 118 32" />
        <path d="M 128 36 C 138 30, 152 38, 152 50" />
        <path d="M 78 60 C 86 56, 96 58, 100 64" />
        <path d="M 78 92 C 60 100, 50 124, 56 152 C 60 170, 76 184, 92 188 C 96 178, 96 168, 94 160" />
        <path d="M 70 116 C 66 136, 70 156, 80 172" opacity="0.55" />
        <path d="M 60 184 L 56 196" />
        <path d="M 70 192 L 70 202" />
        <path d="M 82 192 L 86 202" />
        <path d="M 130 78 C 138 74, 148 74, 156 80" opacity="0.55" />
        <path d="M 170 144 C 178 148, 188 148, 196 144" opacity="0.55" />
      </g>
      <ellipse cx="148" cy="88" rx="3" ry="4.5" transform="rotate(-15 148 88)" fill={color} />
      <path d="M 208 134 C 208 130, 218 130, 218 134 C 218 140, 213 144, 213 144 C 213 144, 208 140, 208 134 Z" fill={color} />
    </svg>
  );
}

// ─── V2 — Front-cute ─────────────────────────────────────────────
function MarkFrontCute({ size = 320, color = '#1a1815', stroke = 1.5 }: MarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 200 200" fill="none" aria-label="Bedlington front cute">
      <g stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M 50 78 C 46 60, 54 46, 64 44 C 60 28, 78 22, 88 30 C 92 18, 108 18, 112 30 C 122 22, 140 28, 136 44 C 146 46, 154 60, 150 78" />
        <path d="M 60 60 C 66 56, 74 56, 78 60" opacity="0.6" />
        <path d="M 92 48 C 98 44, 102 44, 108 48" opacity="0.6" />
        <path d="M 122 60 C 126 56, 134 56, 140 60" opacity="0.6" />
        <path d="M 50 78 C 48 96, 50 116, 58 134" />
        <path d="M 150 78 C 152 96, 150 116, 142 134" />
        <path d="M 58 134 C 64 146, 76 152, 86 150" />
        <path d="M 142 134 C 136 146, 124 152, 114 150" />
        <path d="M 86 150 C 90 158, 100 162, 114 150" />
        <path d="M 50 102 C 32 110, 22 132, 28 156 C 32 172, 44 180, 56 178" />
        <path d="M 36 178 C 32 184, 32 190, 34 194" />
        <path d="M 46 184 C 44 192, 46 198, 48 200" />
        <path d="M 54 182 C 56 190, 58 196, 60 198" />
        <path d="M 150 102 C 168 110, 178 132, 172 156 C 168 172, 156 180, 144 178" />
        <path d="M 164 178 C 168 184, 168 190, 166 194" />
        <path d="M 154 184 C 156 192, 154 198, 152 200" />
        <path d="M 146 182 C 144 190, 142 196, 140 198" />
        <path d="M 88 122 C 88 140, 94 148, 100 152 C 106 148, 112 140, 112 122" opacity="0.85" />
        <path d="M 92 142 C 96 146, 104 146, 108 142" opacity="0.7" />
      </g>
      <ellipse cx="78" cy="106" rx="3.5" ry="5" transform="rotate(-12 78 106)" fill={color} />
      <ellipse cx="122" cy="106" rx="3.5" ry="5" transform="rotate(12 122 106)" fill={color} />
      <circle cx="76.5" cy="103.5" r="0.9" fill="#fff" opacity="0.95" />
      <circle cx="120.5" cy="103.5" r="0.9" fill="#fff" opacity="0.95" />
      <path d="M 94 128 C 94 125, 106 125, 106 128 C 106 134, 100 138, 100 138 C 100 138, 94 134, 94 128 Z" fill={color} />
    </svg>
  );
}

// ─── V3 — Cloud ──────────────────────────────────────────────────
function MarkCloud({ size = 320, color = '#1a1815', stroke = 1.5 }: MarkProps) {
  return (
    <svg width={size} height={size * 0.9} viewBox="0 0 200 180" fill="none" aria-label="Bedlington cloud">
      <g stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M 40 110 C 26 110, 22 88, 36 82 C 30 60, 56 50, 66 64 C 70 42, 100 36, 108 56 C 122 44, 146 58, 142 76 C 162 76, 168 100, 156 112 C 164 124, 158 144, 144 144 C 140 158, 124 162, 116 152 C 110 162, 90 162, 84 152 C 76 162, 60 158, 56 144 C 42 144, 36 124, 44 114 Z" />
        <path d="M 56 80 C 62 76, 70 78, 72 84" opacity="0.4" />
        <path d="M 92 60 C 98 56, 106 58, 110 64" opacity="0.4" />
        <path d="M 130 78 C 134 74, 140 76, 142 82" opacity="0.4" />
        <path d="M 50 130 C 54 128, 60 130, 62 134" opacity="0.4" />
        <path d="M 130 134 C 134 130, 142 132, 144 136" opacity="0.4" />
      </g>
      <circle cx="82" cy="106" r="3.2" fill={color} />
      <circle cx="118" cy="106" r="3.2" fill={color} />
      <ellipse cx="100" cy="124" rx="3.5" ry="2.5" fill={color} />
    </svg>
  );
}

// ─── V4 — Monogram ──────────────────────────────────────────────
function MarkMonogram({ size = 320, color = '#1a1815' }: MarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 200 200" fill="none" aria-label="Bedlington monogram">
      <text
        x="58"
        y="160"
        fontFamily="'IBM Plex Serif', serif"
        fontStyle="italic"
        fontWeight="500"
        fontSize="170"
        fill={color}
        letterSpacing="-0.04em"
      >
        k
      </text>
      <g stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M 90 56 C 84 38, 96 22, 110 26 C 108 14, 130 12, 134 26 C 144 22, 152 36, 146 50" />
        <path d="M 100 42 C 104 36, 112 36, 114 42" opacity="0.5" />
      </g>
      <circle cx="78" cy="86" r="3" fill={color} />
    </svg>
  );
}

// ─── V5 — Seal ───────────────────────────────────────────────────
function MarkSeal({ size = 320, color = '#1a1815', stroke = 1.5 }: MarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 200 200" fill="none" aria-label="Bedlington seal">
      <circle cx="100" cy="100" r="92" stroke={color} strokeWidth={stroke} fill="none" />
      <circle cx="100" cy="100" r="86" stroke={color} strokeWidth="0.6" fill="none" opacity="0.5" />
      <g transform="translate(38 30) scale(0.55)" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M 58 130 C 50 110, 46 88, 50 70 C 38 58, 48 28, 78 26 C 86 12, 110 12, 118 24 C 130 12, 156 18, 158 42 C 168 44, 174 56, 172 68 C 172 78, 170 86, 174 92 C 188 98, 208 116, 218 138 C 222 148, 218 154, 210 154 L 200 152 C 196 158, 188 162, 178 161 L 152 158 C 138 158, 128 156, 118 152 L 96 148 C 84 144, 72 138, 58 130 Z" />
        <path d="M 78 92 C 60 100, 50 124, 56 152 C 60 170, 76 184, 92 188 C 96 178, 96 168, 94 160" />
        <path d="M 60 184 L 56 196" />
        <path d="M 70 192 L 70 202" />
      </g>
      <ellipse cx="119.4" cy="78.4" rx="2" ry="3" transform="rotate(-15 119.4 78.4)" fill={color} />
      <path d="M 152 104 C 152 102, 157 102, 157 104 C 157 107, 154.5 110, 154.5 110 C 154.5 110, 152 107, 152 104 Z" fill={color} />
      <defs>
        <path id="ringText" d="M 100 100 m -72 0 a 72 72 0 1 1 144 0 a 72 72 0 1 1 -144 0" />
      </defs>
      <text fill={color} fontFamily="'IBM Plex Mono', monospace" fontSize="10" letterSpacing="4">
        <textPath href="#ringText" startOffset="0%">
          agentkeys · sovereign keys for agents ·
        </textPath>
      </text>
    </svg>
  );
}

// ─── V6 — Icon ───────────────────────────────────────────────────
function MarkIcon({ size = 320, color = '#1a1815' }: MarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 200 200" fill="none" aria-label="Bedlington icon">
      <path
        d="M 58 100 C 54 64, 76 38, 100 38 C 124 38, 146 64, 142 100 C 142 140, 122 162, 100 162 C 78 162, 58 140, 58 100 Z"
        fill={color}
      />
      <path
        d="M 60 90 C 38 96, 28 122, 36 152 C 40 168, 52 176, 64 174 C 68 162, 66 144, 64 132 Z"
        fill={color}
        opacity="0.92"
      />
      <path
        d="M 140 90 C 162 96, 172 122, 164 152 C 160 168, 148 176, 136 174 C 132 162, 134 144, 136 132 Z"
        fill={color}
        opacity="0.92"
      />
      <g stroke={color} strokeWidth="2.5" strokeLinecap="round" fill="none">
        <path d="M 44 176 L 42 188" />
        <path d="M 52 180 L 52 192" />
        <path d="M 156 176 L 158 188" />
        <path d="M 148 180 L 148 192" />
      </g>
      <g stroke="#f6f3ec" strokeWidth="3" fill="none" strokeLinecap="round">
        <path d="M 72 54 C 72 38, 128 38, 128 54" />
        <path d="M 82 46 C 86 36, 114 36, 118 46" />
        <path d="M 92 40 C 96 34, 104 34, 108 40" />
      </g>
      <ellipse cx="84" cy="96" rx="3.5" ry="5.5" transform="rotate(-12 84 96)" fill="#f6f3ec" />
      <ellipse cx="116" cy="96" rx="3.5" ry="5.5" transform="rotate(12 116 96)" fill="#f6f3ec" />
      <path
        d="M 90 122 C 90 138, 96 148, 100 152 C 104 148, 110 138, 110 122 L 108 120 C 106 132, 102 138, 100 140 C 98 138, 94 132, 92 120 Z"
        fill="#f6f3ec"
      />
      <path d="M 94 142 Q 100 146, 106 142" stroke={color} strokeWidth="1.5" fill="none" strokeLinecap="round" />
      <path d="M 95 124 C 95 122, 105 122, 105 124 C 105 128, 100 132, 100 132 C 100 132, 95 128, 95 124 Z" fill={color} />
    </svg>
  );
}

type VariantId = 'profile' | 'front' | 'cloud' | 'monogram' | 'seal' | 'icon';
type BgId = 'cream' | 'ink' | 'amber' | 'sage' | 'indigo';

const VARIANTS: { id: VariantId; name: string; sub: string; comp: (p: MarkProps) => JSX.Element }[] = [
  { id: 'profile', name: 'profile', sub: 'side view · iconic', comp: MarkProfile },
  { id: 'front', name: 'front-cute', sub: 'big eyes · sheep face', comp: MarkFrontCute },
  { id: 'cloud', name: 'cloud', sub: 'minimal · just fluff', comp: MarkCloud },
  { id: 'monogram', name: 'monogram', sub: 'serif K · topknot curl', comp: MarkMonogram },
  { id: 'seal', name: 'seal', sub: 'badge · circular', comp: MarkSeal },
  { id: 'icon', name: 'icon', sub: 'solid · for apps', comp: MarkIcon },
];

const BG_MAP: Record<BgId, { bg: string; ink: string }> = {
  cream: { bg: '#f6f3ec', ink: '#1a1815' },
  ink: { bg: '#1a1815', ink: '#f6f3ec' },
  amber: { bg: 'oklch(0.55 0.15 50)', ink: '#f6f3ec' },
  sage: { bg: 'oklch(0.5 0.12 145)', ink: '#f6f3ec' },
  indigo: { bg: 'oklch(0.5 0.12 240)', ink: '#f6f3ec' },
};

export function LogoPage() {
  const [selected, setSelected] = useState<VariantId>('profile');
  const [bg, setBg] = useState<BgId>('cream');

  const current = VARIANTS.find((v) => v.id === selected)!;
  const Big = current.comp;
  const palette = BG_MAP[bg];

  return (
    <>
      <PageHead
        crumb="brand · mark · variants"
        title={
          <>
            <span className="muted serif">/</span> bedlington
          </>
        }
        desc="Six directions for the AgentKeys mark. Profile is the most Bedlington-recognizable — the high topknot and arched roman nose only read in side view. Pick a direction and we'll refine."
      />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
          gap: 12,
          marginBottom: 22,
        }}
      >
        {VARIANTS.map((v) => {
          const C = v.comp;
          const isSelected = selected === v.id;
          return (
            <button
              key={v.id}
              onClick={() => setSelected(v.id)}
              style={{
                background: isSelected ? '#1a1815' : '#f6f3ec',
                color: isSelected ? '#f6f3ec' : '#1a1815',
                border: `1px solid ${isSelected ? '#1a1815' : 'var(--rule-soft)'}`,
                padding: 14,
                cursor: 'pointer',
                fontFamily: 'inherit',
                textAlign: 'left',
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
              }}
            >
              <div
                style={{
                  background: isSelected ? '#f6f3ec' : 'var(--bg-elev)',
                  padding: 14,
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  aspectRatio: '1 / 1',
                }}
              >
                <C size={140} color="#1a1815" />
              </div>
              <div>
                <div className="serif" style={{ fontStyle: 'italic', fontSize: 16 }}>
                  {v.name}
                </div>
                <div
                  style={{
                    fontSize: 10.5,
                    opacity: 0.7,
                    letterSpacing: '0.04em',
                    textTransform: 'uppercase',
                    marginTop: 2,
                  }}
                >
                  {v.sub}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      <Panel
        title={`── focus · ${current.name}`}
        right={
          <div style={{ display: 'flex', gap: 6 }}>
            {(Object.keys(BG_MAP) as BgId[]).map((b) => (
              <button key={b} className={`btn sm ${bg === b ? 'primary' : ''}`} onClick={() => setBg(b)}>
                {b}
              </button>
            ))}
          </div>
        }
      >
        <div
          style={{
            background: palette.bg,
            padding: 48,
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            border: '1px solid var(--rule-soft)',
          }}
        >
          <Big size={320} color={palette.ink} />
        </div>
      </Panel>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: 12,
          marginBottom: 22,
        }}
      >
        {[96, 48, 32, 16].map((s) => (
          <Panel key={s} title={`── ${s}px`}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'center',
                padding: 14,
                background: 'var(--bg-elev)',
                minHeight: s + 28,
                alignItems: 'center',
              }}
            >
              <Big size={s} color="#1a1815" />
            </div>
          </Panel>
        ))}
      </div>

      <Panel title="── wordmark lockup">
        <div
          style={{
            display: 'flex',
            gap: 28,
            alignItems: 'center',
            padding: 24,
            background: 'var(--bg-elev)',
            border: '1px solid var(--rule-soft)',
          }}
        >
          <Big size={88} color="#1a1815" />
          <div>
            <div
              className="serif"
              style={{ fontSize: 36, fontStyle: 'italic', lineHeight: 1, letterSpacing: '-0.02em' }}
            >
              agentKeys
            </div>
            <div
              style={{
                fontSize: 10.5,
                color: 'var(--ink-dim)',
                marginTop: 6,
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
              }}
            >
              sovereign keys · for agents
            </div>
          </div>
        </div>
      </Panel>

      <Panel title="── why this breed">
        <div style={{ fontSize: 12.5, lineHeight: 1.7, color: 'var(--ink-dim)' }}>
          The Bedlington Terrier was bred by Northumbrian miners to guard livestock and hunt vermin underground. It
          looks like a lamb. It moves like a greyhound. It fights like a terrier. The whole brand promise of AgentKeys
          lives in that contradiction — your agents look soft, the master holds the teeth, the keys never leave their
          hardware.
          <br />
          <br />
          The mark commits to <strong>side profile</strong> as primary because that&apos;s where the arched roman nose
          and the towering topknot do the work. Front view, cloud, monogram, seal, and solid icon are derived
          application forms.
        </div>
      </Panel>
    </>
  );
}
