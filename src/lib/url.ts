// URL normalization for tool inputs. Mirrors the Worker policy (the
// Worker is authoritative): only http/https, no credentials in URL,
// no non-80/443 port, no private/localhost hostname, max 2048 chars,
// fragment stripped. This is UX feedback only — the server re-checks.
export function normalizeTargetUrl(raw: string): { ok: true; url: string } | { ok: false; error: string } {
  const value = raw.trim()
  if (!value) return { ok: false, error: 'Enter a website URL to check.' }
  if (value.length > 2048) return { ok: false, error: 'That URL is too long.' }
  if (/\s/.test(value)) return { ok: false, error: 'That does not look like a valid URL. Check for spaces.' }
  const schemeMatch = value.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/)
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase()
    if (scheme !== 'http' && scheme !== 'https') return { ok: false, error: 'Only http:// and https:// URLs can be checked.' }
  }
  const withScheme = schemeMatch ? value : `https://${value}`
  let url: URL
  try {
    url = new URL(withScheme)
  } catch {
    return { ok: false, error: 'That does not look like a valid URL. Try a domain like example.com.' }
  }
  if (url.username || url.password) return { ok: false, error: 'URLs with a username or password are not allowed.' }
  if (url.port && url.port !== '80' && url.port !== '443') return { ok: false, error: 'Only standard web ports (80, 443) are allowed.' }
  url.hash = ''
  return { ok: true, url: url.toString() }
}
