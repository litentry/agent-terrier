import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { capabilityInfo, scheduleCapability, scheduleSummary, scheduleTasks } from '../client/capabilityView';
import { AnnotationRows, AutonomousCapabilityRow } from '../../app/_components/permissionSheet';
import { TOOL_CLASSES } from '../../app/_components/types';
import { CAPABILITY_CATALOG } from '../generated/capabilityCatalog';
import type { PresetSchedule } from '../generated/PresetSchedule';
import type { ServiceAnnotation } from '../generated/ServiceAnnotation';

// Owner asks 2026-09-24: `tool:schedule` is highlighted on the install sheet
// and opens onto the tasks the app will run on its own; and what the sheet
// says about a capability is catalog DATA (the protocol's
// `CAPABILITY_CLASSES`, generated), never words written in the UI. The cron
// phrases are the protocol's (`describe_cron`, tested in Rust); the broker's
// catalog serves them as each entry's `when`.

const PRESETS = join(__dirname, '..', '..', '..', '..', 'presets');
const scheduleOf = (id: string): PresetSchedule[] =>
  (JSON.parse(readFileSync(join(PRESETS, id, 'preset.json'), 'utf8')).schedule ?? []) as PresetSchedule[];

// chef's schedule as the broker's catalog serves it: `when` derived.
const WHEN: Record<string, { en: string; zh: string }> = {
  '0 7 * * *': { en: 'every day at 07:00', zh: '每天 07:00' },
  '0 16 * * *': { en: 'every day at 16:00', zh: '每天 16:00' },
};
const chef = scheduleOf('chef').map((s) => ({ ...s, when: WHEN[s.cron] }));

const schedule = CAPABILITY_CATALOG.find((c) => c.class === 'schedule')!;

describe('capabilityInfo — the catalog, found by grant or by class', () => {
  it('finds a class by its grant or its bare name, and nothing else', () => {
    expect(capabilityInfo('tool:schedule')?.acts_on_its_own).toBe(true);
    expect(capabilityInfo(' Tool:Web ')?.title).toBe('Web access');
    expect(capabilityInfo('code')?.service).toBe('tool:code');
    expect(capabilityInfo('tool:teleport')).toBeUndefined();
    expect(capabilityInfo('channel-sub:opchat-chef')).toBeUndefined();
  });

  it('the console class list is the catalog, and one class acts on its own: the one schedules run under', () => {
    expect([...TOOL_CLASSES]).toEqual(CAPABILITY_CATALOG.map((c) => c.class));
    expect(CAPABILITY_CATALOG.filter((c) => c.acts_on_its_own).map((c) => c.service)).toEqual(['tool:schedule']);
    expect(scheduleCapability()?.service).toBe('tool:schedule');
  });
});

describe('scheduleTasks / scheduleSummary', () => {
  it('turns a template schedule into readable rows: label, when (served by the catalog), the exact instruction', () => {
    const tasks = scheduleTasks(chef);
    expect(tasks.map((t) => [t.label, t.labelZh, t.when, t.whenZh])).toEqual([
      ['Morning plan', '早间计划', 'every day at 07:00', '每天 07:00'],
      ['Dinner plan', '晚餐计划', 'every day at 16:00', '每天 16:00'],
    ]);
    expect(tasks[0].prompt).toMatch(/^Compose today's meal plan/);
    expect(tasks[0].cron).toBe('0 7 * * *');
  });

  it('shows the raw cron when the catalog carries no phrase (an older broker), and counts in both languages', () => {
    const [odd] = scheduleTasks([{ cron: '0 */2 * * *', label: ' Tick ', label_zh: '', prompt: ' p ' }]);
    expect(odd).toMatchObject({ label: 'Tick', labelZh: '', when: 'on the cron schedule 0 */2 * * *', whenZh: '按 cron 计划 0 */2 * * *', prompt: 'p' });
    expect(scheduleTasks(undefined)).toEqual([]);
    expect(scheduleSummary(0)).toEqual({ en: 'no scheduled tasks', zh: '无定时任务' });
    expect(scheduleSummary(1)).toEqual({ en: '1 scheduled task', zh: '1 个定时任务' });
    expect(scheduleSummary(2)).toEqual({ en: '2 scheduled tasks', zh: '2 个定时任务' });
  });
});

describe('AnnotationRows — the sheet reads the catalog', () => {
  const annotations: ServiceAnnotation[] = [
    { service: 'channel-sub:opchat-chef', role: 'opchat' },
    { service: 'knowledge:health', role: 'resource', resource: 'health-notes', sensitivity: 'sensitive' },
    { service: 'tool:web', role: 'tool' },
    { service: 'tool:schedule', role: 'tool' },
    { service: 'plugin:openviking', role: 'plugin' },
  ];
  const html = renderToStaticMarkup(<AnnotationRows annotations={annotations} schedule={chef} />);
  const rowOf = (service: string) => {
    const at = html.indexOf(`data-service="${service}"`);
    expect(at).toBeGreaterThan(-1);
    return html.slice(html.lastIndexOf('<div', at), html.indexOf('</div>', at));
  };

  it('highlights only the capability that acts on its own, closed at first, with the catalog badge', () => {
    expect(html.match(/perm-attention"/g)).toHaveLength(1);
    const row = rowOf('tool:schedule');
    expect(row).toContain('perm-row perm-attention');
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain(`${schedule.badge} · ${schedule.badge_zh}`);
    expect(html).toContain('2 scheduled tasks · 2 个定时任务');
    expect(html).toContain('read ▸');
    expect(html).not.toContain('Compose today');
  });

  it('says what an ordinary capability is in the catalog words; data lines keep their role and sensitivity', () => {
    expect(rowOf('tool:web')).toContain('Web access · 联网访问');
    expect(rowOf('tool:web')).not.toContain('perm-attention');
    expect(rowOf('knowledge:health')).toContain('resource · health-notes');
    expect(html).toContain('SENSITIVE');
    expect(rowOf('plugin:openviking')).toContain('plugin');
  });
});

describe('AutonomousCapabilityRow — opened', () => {
  it('shows each task: when, in both languages, and the exact instruction it will be given', () => {
    const html = renderToStaticMarkup(<AutonomousCapabilityRow service="tool:schedule" info={schedule} schedule={chef} defaultOpen />);
    expect(html).toContain('aria-expanded="true"');
    expect(html).toContain('hide ▾');
    expect(html).toContain('Morning plan');
    expect(html).toContain('早间计划');
    expect(html).toContain('every day at 07:00 · 每天 07:00');
    expect(html).toContain('every day at 16:00 · 每天 16:00');
    expect(html).toContain('Compose today&#x27;s meal plan');
    expect(html).toContain('<code>0 7 * * *</code>');
    expect(html).toContain(schedule.note.slice(0, 40));
    expect(html).toContain(schedule.note_zh.slice(0, 20));
  });

  it('still says what the capability allows when the template schedules nothing', () => {
    const html = renderToStaticMarkup(<AutonomousCapabilityRow service="tool:schedule" info={schedule} schedule={[]} defaultOpen />);
    expect(html).toContain('no scheduled tasks · 无定时任务');
    expect(html).toContain('The template schedules no tasks of its own.');
    expect(html).toContain('set its own reminders');
  });
});
