import type { Metadata, Viewport } from 'next';
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
  themeColor: '#fcfff0',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="meadow">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,500;12..96,600;12..96,700&family=Hanken+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&family=Noto+Sans+SC:wght@400;500;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <ClientProvider>
          <ChainBadge />
          {children}
        </ClientProvider>
      </body>
    </html>
  );
}
