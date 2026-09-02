/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  devIndicators: false,
  env: {
    // Preserve empty relative URL in production so Nginx proxies /api to backend.
    // In local development mode without Nginx, fallback to backend port 8000.
    NEXT_PUBLIC_API_URL:
      process.env.NEXT_PUBLIC_API_URL ||
      (process.env.NODE_ENV === 'development' ? 'http://localhost:8000' : ''),
  },
}

module.exports = nextConfig
