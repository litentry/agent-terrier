import { defineConfig } from 'vite';
import type { Plugin } from 'vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import viteReact from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

function relativeRouteMetadata(): Plugin {
  let sourcePrefix = '';
  return {
    name: 'relative-route-metadata',
    apply: 'build',
    enforce: 'post',
    configResolved(config) {
      sourcePrefix = JSON.stringify(config.root + '/').slice(1, -1);
    },
    transform(source, id) {
      if (!id.endsWith('tanstack-start-manifest:v')) return;
      return { code: source.replaceAll(sourcePrefix, ''), map: null };
    },
  };
}

const config = defineConfig({
  resolve: { tsconfigPaths: true, dedupe: ['react', 'react-dom'] },
  // @agentkeys/design-system is a linked workspace source package — keep Vite's
  // dep optimizer from pre-bundling it (a stale optimize cache surfaces as the
  // spurious "./react is not exported" overlay when the lib's exports change).
  optimizeDeps: { exclude: ['@agentkeys/design-system'] },
  plugins: [tailwindcss(), tanstackStart(), viteReact(), relativeRouteMetadata()],
});

export default config;
