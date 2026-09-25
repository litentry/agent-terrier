// What the console says about a capability, READ from the catalog the protocol
// owns — `CAPABILITY_CLASSES` in crates/agentkeys-protocol/src/capability_catalog.rs,
// generated into lib/generated/capabilityCatalog.ts — never names or words
// written here (owner ask 2026-09-24: with many applications, a capability's
// metadata lives in one place). What an APPLICATION does with a class is its
// template's data: the scheduled tasks (`schedule[]`), each carrying `when`,
// its cron in plain words, derived by the protocol when the broker builds the
// template catalog. Pure; the sheet component only renders this.
import { CAPABILITY_CATALOG } from '@/lib/generated/capabilityCatalog';
import type { CapabilityClassInfo } from '@/lib/generated/CapabilityClassInfo';
import type { PresetSchedule } from '@/lib/generated/PresetSchedule';

export interface Bilingual {
  en: string;
  zh: string;
}

export interface ScheduleTaskView {
  key: string;
  label: string;
  labelZh: string;
  when: string;
  whenZh: string;
  cron: string;
  prompt: string;
}

/** The catalog entry for a grant (`tool:web`) or a bare class (`web`). */
export function capabilityInfo(serviceOrClass: string): CapabilityClassInfo | undefined {
  const key = serviceOrClass.trim().toLowerCase();
  return CAPABILITY_CATALOG.find((c) => c.service === key || c.class === key);
}

/** The class a template's `schedule[]` runs under: the catalog's one class
 *  that acts on its own (the protocol pins that there is exactly one). */
export function scheduleCapability(): CapabilityClassInfo | undefined {
  return CAPABILITY_CATALOG.find((c) => c.acts_on_its_own);
}

/** The rows the sheet shows for a template's schedule. A catalog from a broker
 *  older than the derived `when` shows the raw cron. */
export function scheduleTasks(schedule: PresetSchedule[] | undefined): ScheduleTaskView[] {
  return (schedule ?? []).map((s, i) => ({
    key: `${i}-${s.cron}`,
    label: s.label.trim(),
    labelZh: (s.label_zh ?? '').trim(),
    when: s.when?.en ?? `on the cron schedule ${s.cron}`,
    whenZh: s.when?.zh ?? `按 cron 计划 ${s.cron}`,
    cron: s.cron,
    prompt: s.prompt.trim(),
  }));
}

/** The collapsed row's count line. */
export function scheduleSummary(count: number): Bilingual {
  if (count === 0) return { en: 'no scheduled tasks', zh: '无定时任务' };
  return { en: count === 1 ? '1 scheduled task' : `${count} scheduled tasks`, zh: `${count} 个定时任务` };
}
