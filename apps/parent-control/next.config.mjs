import { fileURLToPath } from 'node:url';

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  turbopack: { root: fileURLToPath(new URL('../../', import.meta.url)) },
  transpilePackages: ['@agentkeys/design-system'],
  ...(process.env.AGENTKEYS_STATIC_EXPORT === '1' ? { output: 'export' } : {}),
};

export default nextConfig;
