/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ['@agentkeys/design-system'],
  // Static hosting is optional; development API routes need the default server mode.
  ...(process.env.AGENTKEYS_STATIC_EXPORT === '1' ? { output: 'export' } : {}),
};

export default nextConfig;
