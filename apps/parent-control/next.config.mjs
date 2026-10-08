/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The design system ships TypeScript sources (its /app subpath carries the family-
  // applications fixtures the /dev/applications preview renders) — transpile the linked package.
  transpilePackages: ['@agentkeys/design-system'],
  // #751 step 1 — the hosted console (dashboard.<zone>) is a STATIC export served
  // by nginx on the VE host: no server process, the master plane runs in the
  // browser (arch.md §22c.3). Opt-in for that build only; dev.sh keeps the dev
  // server. Next drops the dev-only /api/dev/* route handlers (the #631
  // local-sandbox proxies) from an export — they need a server — so the hosted
  // site carries no proxy at all.
  ...(process.env.AGENTKEYS_STATIC_EXPORT === '1' ? { output: 'export' } : {}),
};

export default nextConfig;
