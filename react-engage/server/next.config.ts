import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // react-engage ships raw TS/TSX (main -> src/index.ts). When consumed from
  // node_modules, Next must be told to transpile it.
  transpilePackages: ['@reactkits.dev/react-engage'],
};

export default nextConfig;
