/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  ...(process.env.DOCKER_BUILD === '1' ? { output: 'standalone' } : {}),
};

module.exports = nextConfig;
