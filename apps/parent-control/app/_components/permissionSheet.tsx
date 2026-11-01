'use client';

// The permissions sheet's grant lines: at install, before the one Touch ID,
// and on the app page afterwards. Data in, words out. Whether a line is
// highlighted, and what a capability line says, come from the capability
// catalog (lib/client/capabilityView). What the application will do on its
// own comes from its template (`schedule[]`). Nothing here names a capability.
import { useId, useState } from 'react';
import { CHIP_STYLES } from '@/lib/constants';
import type { CapabilityClassInfo } from '@/lib/generated/CapabilityClassInfo';
import type { PresetSchedule } from '@/lib/generated/PresetSchedule';
import type { ServiceAnnotation } from '@/lib/generated/ServiceAnnotation';
import { capabilityInfo, scheduleSummary, scheduleTasks } from '@/lib/client/capabilityView';

/** A capability that lets the app act with no one asking (owner ask
 *  2026-09-24): highlighted, and it opens onto the exact tasks the template
 *  will run: when (household time, English + 中文) and the instruction each
 *  run gets. */
export function AutonomousCapabilityRow({
  service,
  info,
  schedule,
  defaultOpen = false,
}: {
  service: string;
  info: CapabilityClassInfo;
  schedule?: PresetSchedule[];
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  const tasks = scheduleTasks(schedule);
  const summary = scheduleSummary(tasks.length);
  return (
    <div className="perm-row perm-attention" data-service={service}>
      <button
        type="button"
        className="perm-attention-toggle"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
      >
        <code style={{ flex: 1 }}>{service}</code>
        <span className={CHIP_STYLES.warn}>
          {info.badge} · {info.badge_zh}
        </span>
        <span className="muted" style={{ fontSize: 11 }}>
          {summary.en} · {summary.zh}
        </span>
        <span className="perm-attention-cue">{open ? 'hide ▾' : 'read ▸'}</span>
      </button>
      {open && (
        <div id={panelId} className="perm-attention-body">
          {tasks.length === 0 ? (
            <p className="muted" style={{ fontSize: 12, margin: '4px 0 0' }}>
              The template schedules no tasks of its own. · 模板没有自带的定时任务。
            </p>
          ) : (
            tasks.map((t) => (
              <div key={t.key} className="schedule-task">
                <div className="schedule-task-head">
                  <strong>{t.label}</strong>
                  {t.labelZh && <span className="muted"> · {t.labelZh}</span>}
                </div>
                <div className="schedule-task-when">
                  {t.when} · {t.whenZh}
                  <span className="muted">
                    {' '}
                    · household time · cron <code>{t.cron}</code>
                  </span>
                </div>
                <blockquote className="schedule-task-prompt">{t.prompt}</blockquote>
              </div>
            ))
          )}
          <p className="muted" style={{ fontSize: 11.5, margin: '8px 0 0' }}>
            {info.note}
          </p>
          <p className="muted" style={{ fontSize: 11.5, margin: '4px 0 0' }}>
            {info.note_zh}
          </p>
        </div>
      )}
    </div>
  );
}

function AnnotationRow({ annotation: a, schedule }: { annotation: ServiceAnnotation; schedule?: PresetSchedule[] }) {
  const info = a.role === 'tool' ? capabilityInfo(a.service) : undefined;
  if (info?.acts_on_its_own) return <AutonomousCapabilityRow service={a.service} info={info} schedule={schedule} />;
  const detail = info
    ? `${info.title} · ${info.title_zh}`
    : `${a.role}${a.slot ? ` · slot ${a.slot}` : ''}${a.resource ? ` · ${a.resource}` : ''}`;
  return (
    <div className="perm-row" data-service={a.service} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px' }}>
      <code style={{ flex: 1 }}>{a.service}</code>
      <span className="muted" style={{ fontSize: 11 }}>{detail}</span>
      {a.sensitivity === 'sensitive' && <span className={CHIP_STYLES.bad}>SENSITIVE</span>}
    </div>
  );
}

/** The sheet's grant lines, in three sections. `schedule` = the template's
 *  schedule entries, which a capability that acts on its own opens onto. */
export function AnnotationRows({ annotations, schedule }: { annotations: ServiceAnnotation[]; schedule?: PresetSchedule[] }) {
  const data = annotations.filter((a) => a.role !== 'tool' && a.role !== 'plugin');
  const tools = annotations.filter((a) => a.role === 'tool');
  const plugins = annotations.filter((a) => a.role === 'plugin');
  const rows = (list: ServiceAnnotation[]) => list.map((a) => <AnnotationRow key={a.service} annotation={a} schedule={schedule} />);
  return (
    <>
      <div className="perm-section-head"><span className="ttl">Data &amp; devices</span><span className="summary">{data.length} grants</span></div>
      <div className="perm-rows">{rows(data)}</div>
      <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">Capabilities</span><span className="summary">{tools.length}</span></div>
      <div className="perm-rows">{rows(tools)}</div>
      <div className="perm-section-head" style={{ marginTop: 14 }}><span className="ttl">Built with</span><span className="summary">{plugins.length}</span></div>
      <div className="perm-rows">{rows(plugins)}</div>
    </>
  );
}
