// "Ask for the card now" (Applications → the display panel): the owner runs a
// template schedule entry on demand — the same prompt the in-sandbox clock
// would hand the delegate at its cron minute, tagged so the delegate (and the
// transcript) can tell an on-demand ask from a scheduled tick. Pure text
// shaping here; the send is the ordinary chat turn on the app's opchat feed.

import type { PresetSchedule } from '../generated/PresetSchedule';

/** The turn text: a provenance tag the runner's clock tag mirrors
 *  (`[clock · <label> · <stamp> · scheduled turn, not a person]`), then the
 *  entry's prompt verbatim. `stamp` = the household's local `MM-DD HH:mm`. */
export function onDemandTurnText(entry: Pick<PresetSchedule, 'label' | 'prompt'>, now: Date = new Date()): string {
  const p = (n: number) => String(n).padStart(2, '0');
  const stamp = `${p(now.getMonth() + 1)}-${p(now.getDate())} ${p(now.getHours())}:${p(now.getMinutes())}`;
  return `[on demand · ${entry.label.trim()} · ${stamp} · asked from the console, run it now]\n${entry.prompt.trim()}`;
}

/** The generic ask for a template without schedule entries. */
export const GENERIC_CARD_ASK: Pick<PresetSchedule, 'label' | 'prompt'> = {
  label: 'card',
  prompt: 'Publish your current card to the display now: today’s summary and the actions you offer.',
};

/** The entries the display panel offers as buttons: the template's schedule
 *  entries when it has any, else the one generic ask. */
export function cardAsks(schedule: PresetSchedule[] | undefined): Pick<PresetSchedule, 'label' | 'prompt'>[] {
  return schedule && schedule.length > 0 ? schedule : [GENERIC_CARD_ASK];
}
