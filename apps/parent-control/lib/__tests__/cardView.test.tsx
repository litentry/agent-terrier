import { describe, expect, it } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { renderToStaticMarkup } from 'react-dom/server';
import { CardView, cardAge, cardText } from '@agentkeys/design-system/react';
import type { CardViewDocument } from '@agentkeys/design-system/react';
import type { CardDocument } from '../generated/CardDocument';

// #670 — the card-contract renderer's SNAPSHOT test: every golden fixture
// under e2e/fixtures/cards/ renders (en + zh) to the HTML golden beside it.
// The protocol crate pins the same fixtures' parse + plain-text rendering
// (agentkeys-protocol::card tests). `UPDATE_CARD_GOLDENS=1 npm test` rewrites.

const FIXTURES = join(__dirname, '..', '..', '..', '..', 'e2e', 'fixtures', 'cards');
const CARDS = ['chef-day'] as const;
// The fixture's own `updated_at` + 12 min — a stable staleness line.
const NOW = 1788976800 + 12 * 60;

// The generated wire type (ONE owner: agentkeys-protocol::card, ts-rs) must
// stay assignable to the design system's structural twin — a Rust-side field
// change that the renderer cannot take is a compile error here.
const _assignable = (c: CardDocument): CardViewDocument => c;
void _assignable;

function render(card: CardDocument, locale: 'en' | 'zh'): string {
  return renderToStaticMarkup(<CardView card={card} locale={locale} now={NOW} />);
}

describe('CardView golden fixtures (#670)', () => {
  for (const name of CARDS) {
    for (const locale of ['en', 'zh'] as const) {
      it(`renders ${name} (${locale}) to its golden`, () => {
        const card = JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), 'utf8')) as CardDocument;
        const html = render(card, locale);
        const golden = join(FIXTURES, `${name}.${locale}.html`);
        if (process.env.UPDATE_CARD_GOLDENS === '1') writeFileSync(golden, html + '\n');
        expect(html + '\n').toBe(readFileSync(golden, 'utf8'));
      });
    }
  }

  it('the rendered card carries the action ids + commands a renderer publishes back', () => {
    const card = JSON.parse(readFileSync(join(FIXTURES, 'chef-day.json'), 'utf8')) as CardDocument;
    const html = render(card, 'en');
    expect(html).toContain('data-action-id="dinner.swap"');
    expect(html).toContain('data-command="fridge.request-photo"');
    expect(html).toContain('data-card-schema="1"');
    expect(html).toContain('12 min ago');
  });

  it('localizes with fallback and reports staleness', () => {
    expect(cardText('zh', 'Milk', '牛奶')).toBe('牛奶');
    expect(cardText('zh', 'Milk', '')).toBe('Milk');
    expect(cardText('en', 'Milk', '牛奶')).toBe('Milk');
    expect(cardAge(undefined, 10)).toBe('');
    expect(cardAge(100, 130)).toBe('just now');
    expect(cardAge(100, 100 + 15 * 60)).toBe('15 min ago');
    expect(cardAge(100, 100 + 3 * 3600)).toBe('3 h ago');
  });
});
