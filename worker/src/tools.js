// Tool checkers — all read-only, non-destructive, no script
// execution, no exploit attempts. Findings carry indicators and
// remediation guidance only. Bodies of probed configuration files are
// NEVER stored or returned — only whether the path is publicly
// reachable (status + size bucket) is reported.

import { fetchPublic, nowIso, randomId } from './security.js'

function finding(id, title, status, severity, detail, recommendation) {
  return { id, title, status, severity, detail, recommendation }
}

function scoreOf(findings) {
  let total = 0
  let max = 0
  for (const f of findings) {
    const points = f.severity === 'high' ? 3 : f.severity === 'medium' ? 2 : 1
    max += points
    if (f.status === 'pass') total += points
  }
  return { total, max }
}

const SECURITY_HEADERS = [
  ['strict-transport-security', 'Strict-Transport-Security (HSTS)', 'high'],
  ['content-security-policy', 'Content-Security-Policy', 'high'],
  ['x-content-type-options', 'X-Content-Type-Options: nosniff', 'medium'],
  ['x-frame-options', 'X-Frame-Options', 'medium'],
  ['referrer-policy', 'Referrer-Policy', 'low'],
  ['permissions-policy', 'Permissions-Policy', 'low'],
]

function headerFindings(headers) {
  const out = []
  const get = (name) => headers.get(name)
  for (const [name, title, severity] of SECURITY_HEADERS) {
    const value = get(name)
    out.push(finding(
      `header-${name}`,
      title,
      value ? 'pass' : 'attention',
      severity,
      value ? `Present: ${String(value).slice(0, 120)}` : 'This header is not set on the response.',
      value ? '' : `Consider setting ${title} on the server. Security headers are applied at the end of a site build, not per page.`,
    ))
  }
  const cto = get('x-content-type-options')
  if (cto && cto.toLowerCase().trim() !== 'nosniff') {
    out.push(finding('header-nosniff-value', 'X-Content-Type-Options value', 'attention', 'medium',
      `Set to "${cto}" instead of "nosniff".`, 'Set the header value to exactly "nosniff".'))
  }
  return out
}

function cookieFindings(headers) {
  const raw = headers.get('set-cookie') || ''
  if (!raw) {
    return [finding('cookies-none', 'Cookie security attributes', 'not_checked', 'low',
      'No Set-Cookie header was observed on this response.',
      'If the site sets cookies, mark session cookies Secure, HttpOnly, and SameSite where appropriate.')]
  }
  const issues = []
  const lower = raw.toLowerCase()
  if (!lower.includes('secure')) issues.push('a cookie without the Secure flag')
  if (!lower.includes('httponly')) issues.push('a cookie without the HttpOnly flag')
  if (!lower.includes('samesite')) issues.push('a cookie without a SameSite attribute')
  return [finding('cookies-flags', 'Cookie security attributes',
    issues.length === 0 ? 'pass' : 'attention', issues.length === 0 ? 'low' : 'medium',
    issues.length === 0 ? 'Observed cookies carry Secure, HttpOnly, and SameSite.' : `Observed ${issues.join(', ')}.`,
    issues.length === 0 ? '' : 'Review cookie flags on session cookies: Secure, HttpOnly, and an explicit SameSite value.')]
}

function htmlFindings(html, isHttps) {
  const out = []
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1])
  const httpScripts = scripts.filter((s) => s.toLowerCase().startsWith('http://'))
  out.push(finding('js-http', 'JavaScript served over HTTPS',
    httpScripts.length === 0 ? 'pass' : 'attention', 'medium',
    httpScripts.length === 0 ? 'No scripts loaded over plain http:// were found in the page.' : `${httpScripts.length} script(s) load over plain http://.`,
    httpScripts.length === 0 ? '' : 'Serve all scripts over https:// to avoid mixed-content and tampering risks.'))
  const mapRefs = (html.match(/\.map(["']|\?)/gi) || []).length
  out.push(finding('sourcemap-refs', 'Source-map references',
    mapRefs === 0 ? 'pass' : 'attention', 'low',
    mapRefs === 0 ? 'No .map references were found in the page.' : `${mapRefs} source-map reference(s) found in the page.`,
    mapRefs === 0 ? '' : 'Check that referenced source maps are not publicly exposing original source code.'))
  const inlineHandlers = (html.match(/\son(click|load|error|submit)\s*=/gi) || []).length
  out.push(finding('inline-handlers', 'Inline event handlers',
    inlineHandlers === 0 ? 'pass' : 'attention', 'low',
    inlineHandlers === 0 ? 'No inline event handlers were found.' : `${inlineHandlers} inline event handler(s) found.`,
    inlineHandlers === 0 ? '' : 'Prefer event listeners in external scripts over inline handlers, and keep a strict Content-Security-Policy.'))
  out.push(finding('https-page', 'Page served over HTTPS',
    isHttps ? 'pass' : 'attention', 'high',
    isHttps ? 'The final URL uses https://.' : 'The final URL uses http://, not https://.',
    isHttps ? '' : 'Serve the site over https:// with a valid certificate and redirect http:// to https://.'))
  return out
}

// Public-configuration reachability probe (deep overview only).
// Read-only GETs to a small fixed set of well-known paths. Only the
// status is recorded — response bodies are discarded immediately and
// never stored, returned, or parsed for secrets.
const CONFIG_PATHS = ['/.env', '/.git/config', '/wp-config.php', '/config.json', '/.DS_Store']
export async function configExposureFindings(baseUrl, fetchFn = fetch) {
  const out = []
  let exposed = 0
  for (const path of CONFIG_PATHS) {
    let status = 0
    try {
      const target = new URL(path, baseUrl).toString()
      const res = await fetchFn(target, { method: 'GET', redirect: 'manual', headers: { 'User-Agent': 'KluzarManage/1.0' } })
      status = res.status
      // Drain without retaining: read and discard.
      await res.arrayBuffer().catch(() => null)
    } catch {
      status = 0
    }
    if (status === 200) exposed++
    out.push(finding(`config-${path}`, `Public exposure: ${path}`,
      status === 200 ? 'attention' : 'pass', status === 200 ? 'high' : 'low',
      status === 200 ? 'This path returned HTTP 200 publicly.' : `This path did not return a public success response (status ${status || 'unreachable'}).`,
      status === 200 ? 'Block public access to this path at the server or CDN level immediately; it must never be web-accessible.' : ''))
  }
  if (exposed === 0) {
    out.push(finding('config-summary', 'Configuration exposure summary', 'pass', 'low',
      'None of the probed well-known configuration paths returned a public success response.', ''))
  }
  return out
}

export async function runSecurityScan(url, opts = {}) {
  const fetched = await fetchPublic(url, opts.fetchFn)
  if (!fetched.ok) return { ok: false, error: fetched.error }
  const isHttps = fetched.finalUrl.toLowerCase().startsWith('https://')
  const findings = [
    ...headerFindings(fetched.headers),
    ...cookieFindings(fetched.headers),
    ...htmlFindings(fetched.body, isHttps),
  ]
  return {
    ok: true, url: fetched.finalUrl, checkedAt: nowIso(),
    score: scoreOf(findings), findings,
  }
}

export async function runSecurityOverview(url, depth, opts = {}) {
  const base = await runSecurityScan(url, opts)
  if (!base.ok) return base
  const findings = [...base.findings]
  const fetched = await fetchPublic(url, opts.fetchFn)
  if (fetched.ok) {
    const tlsNote = fetched.finalUrl.toLowerCase().startsWith('https://')
      ? 'Final URL uses https://. Certificate details are not inspected by this check.'
      : 'Final URL does not use https://.'
    findings.push(finding('tls-indicator', 'TLS / transport indicator', tlsNote.includes('does not') ? 'attention' : 'pass', 'medium', tlsNote,
      tlsNote.includes('does not') ? 'Serve the site over https://.' : ''))
    const serverHeader = fetched.headers.get('server')
    findings.push(finding('server-header', 'Server header disclosure',
      serverHeader ? 'attention' : 'pass', 'low',
      serverHeader ? `Server header present: ${String(serverHeader).slice(0, 80)}` : 'No Server header was returned.',
      serverHeader ? 'Consider minimizing version details in the Server header.' : ''))
  }
  if (depth === 'deep') {
    const config = await configExposureFindings(url, opts.fetchFn)
    findings.push(...config)
  }
  return {
    ok: true, url: base.url, checkedAt: nowIso(),
    score: scoreOf(findings), findings,
  }
}

export async function runPerformanceCheck(url, opts = {}) {
  const started = Date.now()
  const fetched = await fetchPublic(url, opts.fetchFn)
  if (!fetched.ok) return { ok: false, error: fetched.error }
  const totalMs = Date.now() - started
  // TTFB is approximated by the fetch duration here (single server-side
  // fetch, no browser timing). It is labelled as a server-side
  // measurement, not a browser metric, wherever it is displayed.
  const checks = []
  const cache = fetched.headers.get('cache-control') || ''
  checks.push(finding('perf-cache', 'Cache headers',
    cache ? 'pass' : 'attention', 'low',
    cache ? `Cache-Control present: ${cache.slice(0, 120)}` : 'No Cache-Control header was returned.',
    cache ? '' : 'Set Cache-Control for static assets to improve repeat-visit speed.'))
  const encoding = fetched.headers.get('content-encoding') || ''
  checks.push(finding('perf-encoding', 'Compression',
    encoding ? 'pass' : 'attention', 'medium',
    encoding ? `Response encoding: ${encoding}` : 'No content-encoding was observed.',
    encoding ? '' : 'Enable compression (gzip or Brotli) for text responses.'))
  const size = fetched.body.length
  checks.push(finding('perf-size', 'Page size (HTML)',
    size < 200_000 ? 'pass' : size < 500_000 ? 'attention' : 'attention', size < 200_000 ? 'low' : 'medium',
    `Fetched HTML is about ${Math.round(size / 1024)} KB.`,
    size < 200_000 ? '' : 'Reduce HTML size: remove unused markup and inline assets where possible.'))
  return {
    ok: true, url: fetched.finalUrl, checkedAt: nowIso(),
    ttfbMs: totalMs, totalMs, statusCode: fetched.status, checks,
  }
}

export async function runAccessibilityCheck(url, opts = {}) {
  const fetched = await fetchPublic(url, opts.fetchFn)
  if (!fetched.ok) return { ok: false, error: fetched.error }
  const html = fetched.body
  const findings = []
  const lang = html.match(/<html[^>]+lang=["']([^"']+)["']/i)
  findings.push(finding('a11y-lang', 'Page language declared',
    lang ? 'pass' : 'attention', 'medium',
    lang ? `lang="${lang[1]}" found on <html>.` : 'No lang attribute was found on <html>.',
    lang ? '' : 'Add a lang attribute to <html> so assistive technology uses the right language.'))
  const title = html.match(/<title[^>]*>([^<]+)<\/title>/i)
  findings.push(finding('a11y-title', 'Descriptive page title',
    title && title[1].trim().length >= 3 ? 'pass' : 'attention', 'medium',
    title ? `Title found: "${title[1].trim().slice(0, 80)}".` : 'No <title> was found.',
    title ? '' : 'Add a descriptive <title> to every page.'))
  const h1Count = (html.match(/<h1[\s>]/gi) || []).length
  findings.push(finding('a11y-h1', 'Single main heading',
    h1Count === 1 ? 'pass' : 'attention', 'low',
    h1Count === 1 ? 'Exactly one <h1> found.' : `${h1Count} <h1> elements found.`,
    h1Count === 1 ? '' : 'Use one <h1> per page for the main heading, with lower headings in order.'))
  const imgs = [...html.matchAll(/<img[^>]*>/gi)]
  const missingAlt = imgs.filter((m) => !/alt\s*=/i.test(m[0])).length
  findings.push(finding('a11y-alt', 'Image alt text',
    imgs.length === 0 ? 'not_checked' : missingAlt === 0 ? 'pass' : 'attention', 'medium',
    imgs.length === 0 ? 'No <img> elements were found.' : missingAlt === 0 ? `All ${imgs.length} image(s) carry an alt attribute.` : `${missingAlt} of ${imgs.length} image(s) are missing an alt attribute.`,
    missingAlt === 0 ? '' : 'Add meaningful alt text to informative images, and empty alt="" to decorative ones.'))
  const inputs = [...html.matchAll(/<input[^>]*>/gi)]
  const unlabeled = inputs.filter((m) => !/aria-label\s*=|aria-labelledby\s*=|id\s*=/i.test(m[0])).length
  findings.push(finding('a11y-labels', 'Form control labels',
    inputs.length === 0 ? 'not_checked' : unlabeled === 0 ? 'pass' : 'attention', 'medium',
    inputs.length === 0 ? 'No form controls were found.' : unlabeled === 0 ? `All ${inputs.length} control(s) appear labelled or identifiable.` : `${unlabeled} of ${inputs.length} control(s) have no label reference.`,
    unlabeled === 0 ? '' : 'Associate every form control with a <label> or an aria-label.'))
  const emptyLinks = (html.match(/<a[^>]*>\s*<\/a>/gi) || []).length
  findings.push(finding('a11y-links', 'Empty links',
    emptyLinks === 0 ? 'pass' : 'attention', 'low',
    emptyLinks === 0 ? 'No empty links were found.' : `${emptyLinks} empty link(s) found.`,
    emptyLinks === 0 ? '' : 'Give every link descriptive text; empty links confuse screen-reader users.'))
  findings.push(finding('a11y-note', 'Scope of this check',
    'not_checked', 'low',
    'Automated HTML checks only. Colour contrast, keyboard order, focus states, and screen-reader behaviour need a manual review.',
    'Treat this as a first pass, not a full accessibility audit.'))
  return {
    ok: true, url: fetched.finalUrl, checkedAt: nowIso(),
    score: scoreOf(findings.filter((f) => f.status !== 'not_checked')), findings,
  }
}

export function newSiteRow(userId, url) {
  return { id: randomId(), user_id: userId, url, created_at: nowIso(), updated_at: nowIso() }
}
