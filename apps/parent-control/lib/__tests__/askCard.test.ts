import { describe, expect, it } from 'vitest';
import { cardAsks, GENERIC_CARD_ASK, onDemandTurnText } from '../client/askCard';

describe('ask for the card now', () => {
  it('tags the turn as on-demand with the entry label and a local stamp, then the prompt verbatim', () => {
    const t = onDemandTurnText({ label: ' Morning plan ', prompt: '  Compose today’s meal plan.  ' }, new Date(2026, 8, 17, 9, 5));
    expect(t).toBe('[on demand · Morning plan · 09-17 09:05 · asked from the console, run it now]\nCompose today’s meal plan.');
  });

  it('offers the template schedule entries, else the one generic ask', () => {
    const morning = { cron: '0 7 * * *', label: 'Morning plan', label_zh: '早间计划', prompt: 'a' };
    const dinner = { cron: '0 16 * * *', label: 'Dinner plan', label_zh: '晚餐计划', prompt: 'b' };
    expect(cardAsks([morning, dinner]).map((e) => e.label)).toEqual(['Morning plan', 'Dinner plan']);
    expect(cardAsks([])).toEqual([GENERIC_CARD_ASK]);
    expect(cardAsks(undefined)).toEqual([GENERIC_CARD_ASK]);
  });
});
