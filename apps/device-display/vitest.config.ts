import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

// Pure-module tests (feed reducer, pairing state, settings, identity hex) plus
// the CardView render test — none of them load the wasm pkg (that is built by
// dev.sh / CI for typecheck + runtime, never by vitest).
export default defineConfig({
  oxc: { jsx: { runtime: 'automatic' } },
  resolve: {
    alias: { '#': fileURLToPath(new URL('./src', import.meta.url)) },
    dedupe: ['react', 'react-dom'],
  },
  test: {
    include: ['src/**/__tests__/**/*.test.{ts,tsx}'],
    server: { deps: { inline: [/@agentkeys\/design-system/] } },
  },
});
