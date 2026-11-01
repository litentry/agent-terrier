import { fileURLToPath } from 'node:url';

if (process.env.AGENTKEYS_STATIC_EXPORT === '1') throw new Error('The console requires a Node server for runtime backend configuration; static export is unsupported.');

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  turbopack: { root: fileURLToPath(new URL('../../', import.meta.url)) },
  transpilePackages: ['@agentkeys/design-system'],
};

export default nextConfig;
