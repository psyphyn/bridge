import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Proxy API requests to the Bridge control plane in development
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:8080/api/:path*",
      },
    ];
  },
};

export default nextConfig;
