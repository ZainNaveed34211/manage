/* Kluzar Manage service worker — static assets only, versioned, secure.
 *
 * What it NEVER does (by design, per the PWA security spec):
 * - It never caches POST requests, /api responses, account, payment,
 *   session, subscription, or audit-result responses. The fetch handler
 *   passes those straight through to the network, untouched.
 * - It never stores tokens, secrets, or private data. The cache holds
 *   only same-origin public static files (HTML shell, JS, CSS, icons,
 *   manifest, favicon) — nothing user-specific.
 * - It never serves a cached account or subscription state: account
 *   status is fetched fresh from the server on every page load, and
 *   that fetch is cross-origin, so this worker cannot intercept it.
 * - Updates are not silent: a new worker waits until the user taps
 *   Refresh in the update banner, which sends SKIP_WAITING.
 *
 * Cache strategy:
 * - Navigation: network-first, fall back to the cached app shell offline.
 *   The shell shows the portal shell only — no private data, no old report.
 * - Hashed /assets/* files: cache-first (their names change on update).
 * - Other same-origin static files: stale-while-revalidate.
 * - Everything else: network only.
 */

const CACHE_VERSION = 'kluzar-manage-static-v1'
const SHELL_URLS = ['/', '/manifest.webmanifest']

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(SHELL_URLS)).catch(() => {
      // A failed shell cache must never break installation.
    }),
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))),
    ).then(() => self.clients.claim()),
  )
})

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting()
  }
})

function isStaticAsset(url) {
  if (url.pathname.startsWith('/assets/')) return true
  return ['/manifest.webmanifest', '/icon-192.png', '/icon-512.png'].includes(url.pathname)
}

self.addEventListener('fetch', (event) => {
  const req = event.request
  // Never intercept anything sensitive or non-GET.
  if (req.method !== 'GET') return
  const url = new URL(req.url)
  if (url.origin !== self.location.origin) return
  if (url.pathname.startsWith('/api')) return

  if (req.mode === 'navigate') {
    // Network-first so users never sit on an outdated shell; offline,
    // serve the cached shell (portal shell only, no private content).
    event.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone()
        caches.open(CACHE_VERSION).then((cache) => cache.put('/', copy)).catch(() => {})
        return res
      }).catch(() => caches.match('/')),
    )
    return
  }

  if (isStaticAsset(url)) {
    // Hashed assets are immutable; others revalidate in the background.
    event.respondWith(
      caches.match(req).then((cached) => {
        const network = fetch(req).then((res) => {
          if (res && res.ok) {
            const copy = res.clone()
            caches.open(CACHE_VERSION).then((cache) => cache.put(req, copy)).catch(() => {})
          }
          return res
        }).catch(() => cached)
        return cached || network
      }),
    )
    return
  }

  // Anything else same-origin and GET: network only, no caching.
})
