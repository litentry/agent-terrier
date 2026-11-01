import { connection } from 'next/server';
import { serverBackendConfiguration } from '@/lib/backendConfiguration';

export async function GET() {
  await connection();
  const instance = process.env.AGENT_TERRIER_WEB_INSTANCE ?? null;
  if (instance !== null && !/^[a-f0-9]{32}$/.test(instance)) throw new Error('Invalid website instance identifier');
  return Response.json({ ready: true, service: 'terrier-console', instance,
    backend: serverBackendConfiguration(process.env) }, { headers: { 'cache-control': 'no-store' } });
}
