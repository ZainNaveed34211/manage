import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// GitHub Pages + custom domain manage.kluzar.com serves at the root.
// LOCAL ONLY build: no push, no deploy from this checkout.
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    // Local dev only: proxies /api to a local Worker (wrangler dev).
    // Production uses VITE_MANAGE_API_URL, never a relative /api path.
    proxy: {
      '/api': 'http://localhost:8787',
    },
  },
})
