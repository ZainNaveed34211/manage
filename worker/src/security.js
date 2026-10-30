// SSRF + fetch safety — mirrors the SEO Worker policy (the Worker is
// authoritative; the frontend only mirrors it for UX). Hostname /
// IP-literal based blocking. It does NOT prove DNS resolution, because
// Workers fetch() resolves DNS internally and there is no Workers API
// to resolve-then-check before fetch — that residual DNS-rebinding
// risk is documented, never claimed away. Scanned pages are fetched
// as text only; their scripts are NEVER executed, and no exploit
// attempts are ever made.

export const MAX_REDIRECTS = 5
export const FETCH_TIMEOUT_MS = 10_000
export const MAX_BODY_BYTES = 1_500_000

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.lan', '.home', '.corp', '.intranet']
const BLOCKED_HOSTS = new Set(['localhost', 'metadata', 'metadata.google.internal'])

export function isIpv4(host) {
  return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(host)
}

function ipv4Octets(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return null
  const parts = m.slice(1).map(Number)
  if (m.slice(1).some((p) => p.length > 1 && p.startsWith('0'))) return null
  if (parts.some((n) => n < 0 || n > 255)) return null
  return parts
}

export function isPrivateIpv4(host) {
  const o = ipv4Octets(host)
  if (!o) return false
  const [a, b] = o
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 100 && b >= 64 && b <= 127) return true // CGNAT
  if (a === 169 && b === 254) return true // link-local
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 0) return true
  if (a === 192 && b === 168) return true
  if (a === 198 && (b === 18 || b === 19)) return true // benchmarking
  if (a >= 224) return true // multicast + reserved
  return false
}

export function isPrivateIpv6(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '')
  if (h.includes('%')) return true // zone id, never a public page
  if (h === '::1' || h === '::') return true
  if (h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return true
  if (h.startsWith('fc') || h.startsWith('fd')) return true
  if (h.startsWith('::ffff:')) return isPrivateIpv4(h.slice('::ffff:'.length))
  if (h.startsWith('2001:db8')) return true
  if (h.startsWith('64:ff9b:')) return true
  return false
}

export function isBlockedHost(host) {
  const h = host.toLowerCase()
  if (BLOCKED_HOSTS.has(h)) return true
  if (BLOCKED_SUFFIXES.some((s) => h.endsWith(s))) return true
  if (isIpv4(h)) return isPrivateIpv4(h)
  if (h.includes(':')) return isPrivateIpv6(h)
  return false
}

// Validate + normalize a user-supplied target URL. Returns { ok, url }
// or { ok: false, error }. Redirect targets are re-validated by the
// fetcher (see fetchPublic below) — a safe start URL must never be
// allowed to redirect into a private network.
export function normalizeTargetUrl(raw) {
  if (typeof raw !== 'string') return { ok: false, error: 'URL must be a string.' }
  const value = raw.trim()
  if (!value) return { ok: false, error: 'Enter a URL to check.' }
  if (value.length > 2048) return { ok: false, error: 'URL is too long (max 2048 characters).' }
  if (/\s/.test(value)) return { ok: false, error: 'That does not look like a valid URL.' }
  const schemeMatch = value.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/)
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase()
    if (scheme !== 'http' && scheme !== 'https') return { ok: false, error: 'Only http:// and https:// URLs can be checked.' }
  }
  const withScheme = schemeMatch ? value : `https://${value}`
  let url
  try {
    url = new URL(withScheme)
  } catch {
    return { ok: false, error: 'That does not look like a valid URL.' }
  }
  if (url.username || url.password) return { ok: false, error: 'URLs with a username or password are not allowed.' }
  if (url.port && url.port !== '80' && url.port !== '443') return { ok: false, error: 'Only standard web ports (80, 443) are allowed.' }
  if (isBlockedHost(url.hostname)) return { ok: false, error: 'That host cannot be checked (private or internal address).' }
  if (!url.hostname.includes('.') && !isIpv4(url.hostname)) return { ok: false, error: 'That hostname does not look public.' }
  url.hash = ''
  return { ok: true, url: url.toString() }
}

// Fetch a public URL as text with redirect re-validation, timeout,
// and body cap. Never follows more than MAX_REDIRECTS, never fetches
// a blocked host at any hop, never executes anything fetched.
export async function fetchPublic(startUrl, fetchFn = fetch) {
  let current = startUrl
  let res = null
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const parsed = new URL(current)
    if (isBlockedHost(parsed.hostname)) return { ok: false, error: 'Redirect target is not a public address.' }
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
    try {
      res = await fetchFn(current, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'KluzarManage/1.0 (+https://manage.kluzar.com/)', Accept: 'text/html,application/xhtml+xml,*/*' },
      })
    } catch {
      return { ok: false, error: 'The website could not be reached.' }
    } finally {
      clearTimeout(timer)
    }
    if (res.status >= 300 && res.status < 400) {
      const next = res.headers.get('location')
      if (!next) return { ok: false, error: 'The website redirected without a destination.' }
      if (hop === MAX_REDIRECTS) return { ok: false, error: 'Too many redirects.' }
      try {
        current = new URL(next, current).toString()
      } catch {
        return { ok: false, error: 'The website redirected to an invalid URL.' }
      }
      continue
    }
    break
  }
  if (!res) return { ok: false, error: 'The website could not be reached.' }
  const buf = new Uint8Array(await res.arrayBuffer())
  if (buf.length > MAX_BODY_BYTES) return { ok: false, error: 'The page is too large to check.' }
  const text = new TextDecoder('utf-8', { fatal: false }).decode(buf)
  return { ok: true, status: res.status, headers: res.headers, body: text, finalUrl: current }
}

export function randomId() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function nowIso() {
  return new Date().toISOString()
}
