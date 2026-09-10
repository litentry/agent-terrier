import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

// The parent-control unit tests (`npm test`): plain `.ts` client tests plus
// the #670 CardView snapshot test, which renders the design system's React
// component with react-dom/server (no DOM). Next's tsconfig keeps
// `jsx: preserve` for its own compiler, so vitest gets the automatic runtime
// here (oxc — the rolldown-era transformer); the linked design-system package is inlined so its `.tsx` sources go
// through Vite's transform instead of Node's loader.
export default defineConfig({
  // Vite 7 (rolldown) transforms with oxc; Next's tsconfig says `jsx: preserve`,
  // so the automatic runtime is set here explicitly.
  oxc: { jsx: { runtime: 'automatic' } },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./', import.meta.url)),
    },
    // The linked design-system package declares react as an optional peer;
    // resolve its jsx runtime from THIS app's react (one copy).
    dedupe: ['react', 'react-dom'],
  },
  test: {
    include: ['lib/__tests__/**/*.test.{ts,tsx}'],
    server: { deps: { inline: [/@agentkeys\/design-system/] } },
  },
});
