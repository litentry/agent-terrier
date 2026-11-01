import type { Metadata, Viewport } from 'next';
import { connection } from 'next/server';
import { BACKEND_CONFIGURATION_ID, serverBackendConfiguration, serializeBackendConfiguration } from '@/lib/backendConfiguration';
import '@agentkeys/design-system/css/tokens.css';
import { ClientProvider } from '@/lib/ClientProvider';
import { ChainBadge } from './_components/ChainBadge';
import './globals.css';

export const metadata: Metadata = {
  title: 'agentKeys · parent control',
  description: 'Phase 1 parent-control UI for AgentKeys — HDKD actor tree, per-namespace scope, live audit feed, on-chain anchor status.',
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  viewportFit: 'cover',
  themeColor: '#ffffff',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  await connection();
  const configuration = serverBackendConfiguration(process.env);
  return (
    <html lang="en" data-theme="github">
      <body>
        <script id={BACKEND_CONFIGURATION_ID} type="application/json" dangerouslySetInnerHTML={{ __html: serializeBackendConfiguration(configuration) }} />
        <ClientProvider configuration={configuration}>
          <ChainBadge />
          {children}
        </ClientProvider>
      </body>
    </html>
  );
}
