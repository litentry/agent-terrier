import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { renderToStaticMarkup } from 'react-dom/server';
import { CardView } from '@agentkeys/design-system/react';
import type { CardViewDocument } from '@agentkeys/design-system/react';

// The display renders the SAME golden fixtures the console + the protocol pin
// (e2e/fixtures/cards) in the kiosk `big` scale: every action id + command the
// device publishes back must be on screen, in both locales.
const FIXTURES = join(__dirname, '..', '..', '..', '..', '..', 'e2e', 'fixtures', 'cards');

describe('kitchen display renders the golden card', () => {
  const card = JSON.parse(readFileSync(join(FIXTURES, 'chef-day.json'), 'utf8')) as CardViewDocument;
  it('big mode, both locales, actions intact', () => {
    const en = renderToStaticMarkup(<CardView card={card} locale="en" big now={1788976800 + 720} />);
    expect(en).toContain('data-action-id="dinner.swap"');
    expect(en).toContain('data-action-id="fridge.request-photo"');
    expect(en).toContain('Chef · today');
    const zh = renderToStaticMarkup(<CardView card={card} locale="zh" big now={1788976800 + 720} />);
    expect(zh).toContain('家庭厨师 · 今天');
    expect(zh).toContain('换个晚餐');
  });
});
