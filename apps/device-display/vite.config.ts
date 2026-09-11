import { defineConfig } from 'vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// The device-mode web app (#675): same toolchain as apps/mobile-mock (Vite +
// TanStack Start + the linked design system), no devtools — it runs on a shared
// kitchen tablet in kiosk mode.
const config = defineConfig({
  resolve: { tsconfigPaths: true, dedupe: ['react', 'react-dom'] },
  // @agentkeys/design-system is a linked workspace source package — keep Vite's
  // dep optimizer from pre-bundling it (a stale optimize cache surfaces as the
  // spurious "./react is not exported" overlay when the lib's exports change).
  optimizeDeps: { exclude: ['@agentkeys/design-system'] },
  plugins: [tailwindcss(), tanstackStart(), viteReact()],
});

export default config;
