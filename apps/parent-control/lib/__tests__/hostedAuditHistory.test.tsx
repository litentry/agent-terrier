// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HostedAuditHistory } from '../../app/_components/HostedAuditHistory';
import type { AgentKeysClient, AuditPage, Result } from '../client/types';
import type { AuditEvent } from '../../app/_components/types';

vi.mock('../../app/_components/dashboard', () => ({ AuditFeed: ({ events }: { events: AuditEvent[] }) => <div>{events.map((event) => <span key={event.id}>{event.detail}</span>)}</div> }));
const event = (id: string) => ({ id, ts: id, detail: `event-${id}` }) as AuditEvent;
const page = (events: AuditEvent[], nextCursor: string | null): Result<AuditPage> => ({ ok: true, data: { events, nextCursor } });
let root: Root;
let container: HTMLDivElement;
let read: ReturnType<typeof vi.fn>;
let client: AgentKeysClient;
async function render(actor = 'all', paused = false) {
  await act(async () => root.render(<HostedAuditHistory client={client} events={[]} actorRows={null} status={{ kind: 'connected', via: 'broker', endpoint: 'test' }} onPick={() => {}} paused={paused} onPause={() => {}} actorOptions={[]} actorFilter={actor} onActorFilter={() => {}} />));
}
async function older() {
  await act(async () => container.querySelector<HTMLButtonElement>('button')!.click());
}
beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal('IS_REACT_ACT_ENVIRONMENT', true);
  read = vi.fn();
  client = { listAuditPage: read } as unknown as AgentKeysClient;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
describe('hosted audit history', () => {
  it('continues through an empty window and does not lose older events on refresh or pause', async () => {
    read.mockResolvedValueOnce(page([], '2048-0')).mockResolvedValueOnce(page([event('20')], '1-0'));
    await render();
    expect(container.textContent).toContain('Load older activity');
    await older();
    expect(read).toHaveBeenLastCalledWith({ actorId: undefined, limit: 100, cursor: '2048-0' });
    expect(container.textContent).toContain('event-20');
    await render('all', true);
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(read).toHaveBeenCalledTimes(2);
    expect(container.textContent).toContain('event-20');
    read.mockResolvedValueOnce(page([event('30')], '2048-0'));
    await render();
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(container.textContent).toContain('event-30');
    expect(container.textContent).toContain('event-20');
    read.mockResolvedValueOnce(page([], null));
    await older();
    expect(read).toHaveBeenLastCalledWith({ actorId: undefined, limit: 100, cursor: '1-0' });
    expect(container.textContent).not.toContain('Load older activity');
  });
  it('retains the page and continuation on a failed older read', async () => {
    read.mockResolvedValueOnce(page([event('20')], '10-0')).mockResolvedValueOnce({ ok: false, status: { kind: 'disconnected', detail: 'upstream unavailable' } });
    await render();
    await older();
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('upstream unavailable');
    expect(container.textContent).toContain('event-20');
    read.mockResolvedValueOnce(page([event('5')], null));
    await older();
    expect(read).toHaveBeenLastCalledWith({ actorId: undefined, limit: 100, cursor: '10-0' });
    expect(container.textContent).toContain('event-5');
  });
  it('ignores an older response after the actor changes', async () => {
    let finish: (value: Result<AuditPage>) => void = () => {};
    read.mockResolvedValueOnce(page([event('20')], '10-0')).mockReturnValueOnce(new Promise<Result<AuditPage>>((resolve) => { finish = resolve; }));
    await render('alice');
    await older();
    read.mockResolvedValueOnce(page([event('30')], null));
    await render('bob');
    await act(async () => finish(page([event('5')], null)));
    expect(container.textContent).toContain('event-30');
    expect(container.textContent).not.toContain('event-20');
    expect(container.textContent).not.toContain('event-5');
  });
});
