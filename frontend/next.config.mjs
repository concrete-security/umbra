/** @type {import('next').NextConfig} */
const nextConfig = {
  turbopack: {},
  images: {
    unoptimized: true,
  },
  webpack(config, { isServer }) {
    if (isServer) {
      config.externals = Array.isArray(config.externals) ? config.externals : config.externals ? [config.externals] : []
      config.externals.push("tr46")
    }
    return config
  },
  async headers() {
    const isProd = process.env.NODE_ENV === 'production'

    // Content-Security-Policy
    // - In dev we allow inline/eval + localhost for Next.js tooling.
    // - In prod we disallow eval but allow wasm-unsafe-eval for WebAssembly (required by @phala/dcap-qvl-web)
    //   and only allow HTTPS/WSS connects (plus Supabase) to reduce exfil paths.
    // - Allow Vercel Live for preview deployments and Next.js inline scripts
    const devCsp = "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; connect-src 'self' https://*.supabase.co wss://*.supabase.co http://localhost:3000 ws://localhost:3000 https: wss:; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none';";
    const prodCsp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://vercel.live; connect-src 'self' https://*.supabase.co wss://*.supabase.co https://*.trustedservices.intel.com https://*.intel.com https://pccs.phala.network https://*.concrete-security.com wss://*.concrete-security.com https://vercel.live wss://vercel.live; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests";

    // Common security headers
    const commonSecurityHeaders = [
      { key: 'Referrer-Policy', value: 'no-referrer' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
      { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
      { key: 'Permissions-Policy', value: 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()' },
      { key: 'X-DNS-Prefetch-Control', value: 'off' },
    ]

    const headers = [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: isProd ? prodCsp : devCsp },
          ...commonSecurityHeaders,
          // Only enable HSTS in production
          ...(isProd
            ? [{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }]
            : []),
        ],
      },
    ]

    return headers
  },
}

export default nextConfig
