// #631 — server-side proxy to the LOCAL dsh test twin's /v1/chat (non-stream).
import { NextResponse } from 'next/server';
import { bridgeBase, sandboxDownBody } from '../shared';

export async function POST(req: Request): Promise<NextResponse> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'bad request: body must be JSON' }, { status: 400 });
  }
  try {
    const res = await fetch(`${bridgeBase()}/v1/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-store',
      // A real-Ark turn with recall can run well over a minute (tool steps).
      signal: AbortSignal.timeout(180_000),
    });
    return NextResponse.json(await res.json(), { status: res.status });
  } catch {
    return NextResponse.json(sandboxDownBody(), { status: 503 });
  }
}
