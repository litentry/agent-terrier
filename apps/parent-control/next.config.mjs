/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The design system ships TypeScript sources (its /app subpath carries the family-
  // applications fixtures the /dev/applications preview renders) — transpile the linked package.
  transpilePackages: ['@agentkeys/design-system'],
};

export default nextConfig;
