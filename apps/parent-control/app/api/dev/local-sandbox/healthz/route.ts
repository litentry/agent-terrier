// #631 — server-side proxy to the LOCAL dsh test twin's bridge healthz.
// Server-side fetch: no CORS, and the bridge URL never reaches the browser.
import { NextResponse } from 'next/server';
import { bridgeBase, sandboxDownBody } from '../shared';

export async function GET(): Promise<NextResponse> {
  try {
    const res = await fetch(`${bridgeBase()}/healthz`, {
      cache: 'no-store',
      signal: AbortSignal.timeout(3_000),
    });
    return NextResponse.json(await res.json(), { status: res.status });
  } catch {
    return NextResponse.json(sandboxDownBody(), { status: 503 });
  }
}
