'use client';

// The header's search box (#695 §9): type a name, pick a hit, land on it.
// `/` or ⌘K / Ctrl+K focuses it from anywhere that is not another field;
// ↑ ↓ move, Enter picks, Esc clears. The ranking lives in lib/client/search.ts.

import { useEffect, useMemo, useRef, useState } from 'react';
import { searchEntries, type SearchEntry, type SearchKind } from '@/lib/client/search';

const KIND_LABEL: Record<SearchKind, string> = {
  page: 'page',
  repository: 'repository',
  actor: 'actor',
  channel: 'channel',
  credential: 'credential',
};

export function HeaderSearch({ entries, onPick }: { entries: SearchEntry[]; onPick: (e: SearchEntry) => void }) {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const hits = useMemo(() => searchEntries(entries, q), [entries, q]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      const typing = !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
      if ((e.key === '/' && !typing) || ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k')) {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
        setOpen(true);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, []);

  useEffect(() => {
    setIdx(0);
  }, [q]);

  const pick = (e: SearchEntry) => {
    onPick(e);
    setQ('');
    setOpen(false);
    inputRef.current?.blur();
  };

  return (
    <div className="head-search" ref={boxRef} role="search">
      <input
        ref={inputRef}
        value={q}
        placeholder="search…   /"
        aria-label="search the console"
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            setOpen(false);
            setQ('');
            inputRef.current?.blur();
          } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            setIdx((i) => Math.min(i + 1, Math.max(hits.length - 1, 0)));
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setIdx((i) => Math.max(i - 1, 0));
          } else if (e.key === 'Enter' && hits[idx]) {
            e.preventDefault();
            pick(hits[idx]);
          }
        }}
      />
      {open && q.trim() && (
        <div className="head-search-menu" role="listbox">
          {hits.length === 0 && <div className="muted" style={{ padding: '8px 10px', fontSize: 12 }}>nothing matches</div>}
          {hits.map((h, i) => (
            <div
              key={`${h.kind}:${h.id}`}
              role="option"
              aria-selected={i === idx}
              className={`head-search-hit${i === idx ? ' active' : ''}`}
              onMouseEnter={() => setIdx(i)}
              onMouseDown={(e) => {
                e.preventDefault();
                pick(h);
              }}
            >
              <span className="chip">{KIND_LABEL[h.kind]}</span>
              <span style={{ fontWeight: 600, marginLeft: 8 }}>{h.label}</span>
              {h.hint && <span className="muted" style={{ marginLeft: 8, fontSize: 11.5 }}>{h.hint}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
