// kluzar-manage-api — Cloudflare Worker (plain JS, WebCrypto only).
// LOCAL BUILD ONLY — not deployed by this checkout.
//
// AUTHORIZATION MODEL (approved architecture, enforced here):
//  1. Every protected request must carry Origin: https://manage.kluzar.com
//     exactly, or it is rejected before any other work.
//  2. Every protected request must carry Authorization: Bearer <assertion>
//     where the assertion is a 5-minute Ed25519-signed JWT from the
//     Accounts API (POST /auth/manage-assertion). This Worker holds
//     ONLY public verification keys — it can never mint an assertion.
//  3. The assertion is verified (signature, kid, aud, exp, iat) and then
//     the EXACT session (sid + sub) is looked up live in shared D1:
//     the row must exist, be unexpired, and belong to an active user.
//     Logout / logout-all / expiry therefore revoke instantly.
//  4. The entitlement is read live from shared D1 on every request:
//     premium iff plan is growth/max AND status is active. The
//     assertion NEVER proves a subscription — it carries no plan.
//  5. Each endpoint applies its own tool gate (Uptime is Max-only).
// This Worker NEVER writes to sessions, users, or entitlements. It
// writes only its own tables (manage_sites, security_scans,
// uptime_monitors, uptime_checks, performance_checks,
// accessibility_checks, maintenance_requests, analytics_events).

import { verifyAssertion } from './verify.js'
import { getEntitlement, toolAllowed } from './entitlements.js'
import { normalizeTargetUrl, nowIso, randomId } from './security.js'
import {
  runAccessibilityCheck, runPerformanceCheck,
  runSecurityOverview, runSecurityScan,
} from './tools.js'

const MANAGE_ORIGIN = 'https://manage.kluzar.com'
const SERVICE = 'kluzar-manage-api'
const VERSION = '1.0.0'

// ---- CORS (hardcoded allowlist, exact match only) ----
function corsHeaders(origin) {
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Requested-With',
    Vary: 'Origin',
  }
  if (origin === MANAGE_ORIGIN) headers['Access-Control-Allow-Origin'] = MANAGE_ORIGIN
  return headers
}

// NOTE: no Access-Control-Allow-Credentials — this API uses bearer
// auth, not cookies, so credentials are never needed or accepted.

function jsonResponse(origin, status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
      ...corsHeaders(origin),
    },
  })
}

function errorResponse(origin, status, message) {
  return jsonResponse(origin, status, { ok: false, error: message })
}

// ---- Rate limiting (per-isolate, in-memory) ----
// This is abuse mitigation, not a plan limit, and it is never
// presented to users as one. D1-backed limits remain a hardening
// option; per-isolate limits are the same pattern Accounts uses for
// its in-memory buckets.
const buckets = new Map()
function rateLimit(key, limit, windowMs) {
  const now = Date.now()
  const arr = (buckets.get(key) || []).filter((t) => now - t < windowMs)
  if (arr.length >= limit) {
    buckets.set(key, arr)
    return false
  }
  arr.push(now)
  buckets.set(key, arr)
  return true
}

// ---- Public keys (from env; JWK JSON strings, never in code) ----
function publicKeysByKid(env) {
  const map = {}
  try {
    if (env.MANAGE_ASSERTION_PUBLIC_KEY) {
      map['manage-assertion-v1'] = JSON.parse(env.MANAGE_ASSERTION_PUBLIC_KEY)
    }
  } catch { /* misconfigured key fails closed below (unknown kid) */ }
  try {
    if (env.MANAGE_ASSERTION_PUBLIC_KEY_V2) {
      map['manage-assertion-v2'] = JSON.parse(env.MANAGE_ASSERTION_PUBLIC_KEY_V2)
    }
  } catch { /* ignore */ }
  return map
}

// ---- Authentication (the 5 per-request checks) ----
async function authenticate(request, env, origin) {
  // (1) Strict Origin — every protected request, no exception.
  if (origin !== MANAGE_ORIGIN) return { auth: null, error: errorResponse(origin, 403, 'Request not allowed.') }
  const header = request.headers.get('Authorization') || ''
  const match = header.match(/^Bearer\s+(.+)$/)
  if (!match) return { auth: null, error: errorResponse(origin, 401, 'Missing or invalid authorization.') }
  // (2) Signature + kid + aud + exp + iat (EdDSA only, inside verify).
  const verified = await verifyAssertion(match[1], publicKeysByKid(env))
  if (!verified.ok) return { auth: null, error: errorResponse(origin, 401, verified.error) }
  const { sub, sid } = verified.payload
  // (3) Exact session alive in shared D1: row exists, unexpired,
  // user active. This is what makes logout/logout-all instant.
  const session = await env.DB.prepare(
    'SELECT s.*, u.status AS user_status, u.email AS user_email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.user_id = ?',
  ).bind(sid, sub).first()
  if (!session) return { auth: null, error: errorResponse(origin, 401, 'Session no longer exists.') }
  if (new Date(session.expires_at).getTime() <= Date.now()) {
    return { auth: null, error: errorResponse(origin, 401, 'Session expired.') }
  }
  if (session.user_status !== 'active') return { auth: null, error: errorResponse(origin, 401, 'Account is not active.') }
  // (4) Entitlement live from shared D1 (never from the assertion).
  const entitlement = await getEntitlement(env.DB, sub)
  return { auth: { userId: sub, email: session.user_email || '', entitlement }, error: null }
}

function requirePremium(origin, auth) {
  if (!auth.entitlement.premium) return errorResponse(origin, 403, 'A Growth or Max subscription is required for this tool.')
  return null
}

function requireTool(origin, auth, tool) {
  const denied = requirePremium(origin, auth)
  if (denied) return denied
  if (!toolAllowed(auth.entitlement.plan, tool)) {
    return errorResponse(origin, 403, 'This tool is included in the Max plan. Upgrade to use it.')
  }
  return null
}

async function readJson(request) {
  try {
    const body = await request.json()
    return body && typeof body === 'object' ? body : {}
  } catch {
    return {}
  }
}

async function ensureSite(db, userId, url) {
  const existing = await db.prepare('SELECT id FROM manage_sites WHERE user_id = ? AND url = ?').bind(userId, url).first()
  if (existing) return existing.id
  const id = randomId()
  await db.prepare('INSERT INTO manage_sites (id, user_id, url, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .bind(id, userId, url, nowIso(), nowIso()).run()
  return id
}

// ---- Analytics validation (allowlist only, PII/scan-content free) ----
const ANALYTICS_EVENTS = new Set(['page_view', 'tool_open', 'scan_complete', 'check_complete', 'app_error', 'feature_use'])
function cleanAnalyticsEvent(body) {
  if (!body || typeof body !== 'object') return null
  if (typeof body.event !== 'string' || !ANALYTICS_EVENTS.has(body.event)) return null
  const out = { event: body.event }
  if (typeof body.tool === 'string' && /^[a-z0-9_-]{1,64}$/.test(body.tool)) out.tool = body.tool
  if (typeof body.outcome === 'string' && /^(ok|error|denied)$/.test(body.outcome)) out.outcome = body.outcome
  return out
}

// ---- Router ----
export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    const origin = request.headers.get('Origin') || ''
    const path = url.pathname
    const method = request.method

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) })
    }

    // Public liveness probe only. Returns no user data.
    if (method === 'GET' && path === '/api/health') {
      return jsonResponse(origin, 200, { ok: true, service: SERVICE, version: VERSION })
    }

    // Analytics: Origin-pinned + allowlisted fields + rate-limited.
    // No auth required (guest/upgrade screens have no assertion), but
    // nothing sensitive is ever accepted — unexpected fields are
    // dropped, and the endpoint never returns user data.
    if (method === 'POST' && path === '/api/analytics/event') {
      if (origin !== MANAGE_ORIGIN) return errorResponse(origin, 403, 'Request not allowed.')
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown'
      if (!rateLimit(`analytics:${ip}`, 30, 60_000)) return errorResponse(origin, 429, 'Too many events.')
      const clean = cleanAnalyticsEvent(await readJson(request))
      if (!clean) return errorResponse(origin, 400, 'Invalid analytics event.')
      try {
        await env.DB.prepare('INSERT INTO analytics_events (id, user_id, event, tool, outcome, created_at) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(randomId(), '', clean.event, clean.tool || '', clean.outcome || '', nowIso()).run()
      } catch { /* analytics must never break the product */ }
      return jsonResponse(origin, 200, { ok: true })
    }

    // Everything below requires the full 5-check authentication.
    if (!path.startsWith('/api/')) return errorResponse(origin, 404, 'Not found.')
    const { auth, error } = await authenticate(request, env, origin)
    if (error) return error

    // ---- Identity (live session + entitlement, no plan from token) ----
    if (method === 'GET' && path === '/api/me') {
      return jsonResponse(origin, 200, {
        ok: true,
        user: { id: auth.userId, email: auth.email },
        plan: auth.entitlement.plan,
        status: auth.entitlement.status,
        premium: auth.entitlement.premium,
      })
    }

    // ---- Security scans ----
    if (method === 'GET' && path === '/api/security/scans') {
      const denied = requirePremium(origin, auth)
      if (denied) return denied
      const rows = await env.DB.prepare(
        'SELECT url, score_total, score_max, checked_at FROM security_scans WHERE user_id = ? ORDER BY checked_at DESC LIMIT 20',
      ).bind(auth.userId).all()
      const scans = (rows.results || []).map((r) => ({
        ok: true, url: r.url, checkedAt: r.checked_at,
        score: { total: r.score_total, max: r.score_max }, findings: [],
      }))
      return jsonResponse(origin, 200, { ok: true, scans })
    }

    if (method === 'POST' && path === '/api/security/scan') {
      const denied = requirePremium(origin, auth)
      if (denied) return denied
      if (!rateLimit(`scan:${auth.userId}`, 10, 60_000)) return errorResponse(origin, 429, 'Too many scans. Please wait a minute.')
      const body = await readJson(request)
      const norm = normalizeTargetUrl(body.url)
      if (!norm.ok) return errorResponse(origin, 400, norm.error)
      const res = await runSecurityScan(norm.url)
      if (!res.ok) return errorResponse(origin, 400, res.error)
      const siteId = await ensureSite(env.DB, auth.userId, res.url)
      await env.DB.prepare('INSERT INTO security_scans (id, site_id, user_id, url, kind, score_total, score_max, findings_json, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(randomId(), siteId, auth.userId, res.url, 'scan', res.score.total, res.score.max, JSON.stringify(res.findings), res.checkedAt).run()
      return jsonResponse(origin, 200, res)
    }

    if (method === 'POST' && path === '/api/security/overview') {
      const denied = requirePremium(origin, auth)
      if (denied) return denied
      if (!rateLimit(`scan:${auth.userId}`, 10, 60_000)) return errorResponse(origin, 429, 'Too many checks. Please wait a minute.')
      const body = await readJson(request)
      const norm = normalizeTargetUrl(body.url)
      if (!norm.ok) return errorResponse(origin, 400, norm.error)
      const depth = auth.entitlement.plan === 'max' ? 'deep' : 'standard'
      const res = await runSecurityOverview(norm.url, depth)
      if (!res.ok) return errorResponse(origin, 400, res.error)
      const siteId = await ensureSite(env.DB, auth.userId, res.url)
      await env.DB.prepare('INSERT INTO security_scans (id, site_id, user_id, url, kind, score_total, score_max, findings_json, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(randomId(), siteId, auth.userId, res.url, 'overview', res.score.total, res.score.max, JSON.stringify(res.findings), res.checkedAt).run()
      return jsonResponse(origin, 200, { ...res, depth })
    }

    // ---- Uptime (Max only) ----
    if (path === '/api/uptime/monitors' && (method === 'GET' || method === 'POST')) {
      const denied = requireTool(origin, auth, 'uptime')
      if (denied) return denied
      if (method === 'GET') {
        const rows = await env.DB.prepare('SELECT * FROM uptime_monitors WHERE user_id = ? ORDER BY created_at DESC').bind(auth.userId).all()
        const monitors = await Promise.all((rows.results || []).map(async (m) => {
          const agg = await env.DB.prepare('SELECT COUNT(*) AS total, SUM(CASE WHEN ok = 1 THEN 1 ELSE 0 END) AS up FROM uptime_checks WHERE monitor_id = ?').bind(m.id).first()
          const total = agg?.total || 0
          const up = agg?.up || 0
          return {
            id: m.id, url: m.url, name: m.name, intervalMinutes: m.interval_minutes,
            status: m.status, lastCheckedAt: m.last_checked_at,
            uptimePct: total === 0 ? null : Math.round((up / total) * 1000) / 10,
          }
        }))
        return jsonResponse(origin, 200, { ok: true, monitors })
      }
      const body = await readJson(request)
      const norm = normalizeTargetUrl(body.url)
      if (!norm.ok) return errorResponse(origin, 400, norm.error)
      const name = typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 120) : norm.url
      const id = randomId()
      await env.DB.prepare('INSERT INTO uptime_monitors (id, user_id, url, name, interval_minutes, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(id, auth.userId, norm.url, name, 15, 'unknown', nowIso(), nowIso()).run()
      return jsonResponse(origin, 200, { ok: true, monitor: { id, url: norm.url, name, intervalMinutes: 15, status: 'unknown', lastCheckedAt: null, uptimePct: null } })
    }

    if (method === 'GET' && path === '/api/uptime/checks') {
      const denied = requireTool(origin, auth, 'uptime')
      if (denied) return denied
      const monitorId = url.searchParams.get('monitorId') || ''
      const owner = await env.DB.prepare('SELECT id FROM uptime_monitors WHERE id = ? AND user_id = ?').bind(monitorId, auth.userId).first()
      if (!owner) return errorResponse(origin, 404, 'Monitor not found.')
      const rows = await env.DB.prepare('SELECT * FROM uptime_checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 50').bind(monitorId).all()
      const checks = (rows.results || []).map((c) => ({
        id: c.id, monitorId: c.monitor_id, checkedAt: c.checked_at,
        ok: c.ok === 1, statusCode: c.status_code, responseMs: c.response_ms,
      }))
      return jsonResponse(origin, 200, { ok: true, checks })
    }

    // ---- Performance ----
    if (method === 'POST' && path === '/api/performance/check') {
      const denied = requirePremium(origin, auth)
      if (denied) return denied
      if (!rateLimit(`scan:${auth.userId}`, 10, 60_000)) return errorResponse(origin, 429, 'Too many checks. Please wait a minute.')
      const body = await readJson(request)
      const norm = normalizeTargetUrl(body.url)
      if (!norm.ok) return errorResponse(origin, 400, norm.error)
      const res = await runPerformanceCheck(norm.url)
      if (!res.ok) return errorResponse(origin, 400, res.error)
      const siteId = await ensureSite(env.DB, auth.userId, res.url)
      await env.DB.prepare('INSERT INTO performance_checks (id, site_id, user_id, url, ttfb_ms, total_ms, status_code, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(randomId(), siteId, auth.userId, res.url, res.ttfbMs, res.totalMs, res.statusCode, res.checkedAt).run()
      return jsonResponse(origin, 200, res)
    }

    // ---- Accessibility ----
    if (method === 'POST' && path === '/api/accessibility/check') {
      const denied = requirePremium(origin, auth)
      if (denied) return denied
      if (!rateLimit(`scan:${auth.userId}`, 10, 60_000)) return errorResponse(origin, 429, 'Too many checks. Please wait a minute.')
      const body = await readJson(request)
      const norm = normalizeTargetUrl(body.url)
      if (!norm.ok) return errorResponse(origin, 400, norm.error)
      const res = await runAccessibilityCheck(norm.url)
      if (!res.ok) return errorResponse(origin, 400, res.error)
      const siteId = await ensureSite(env.DB, auth.userId, res.url)
      await env.DB.prepare('INSERT INTO accessibility_checks (id, site_id, user_id, url, score_total, score_max, findings_json, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(randomId(), siteId, auth.userId, res.url, res.score.total, res.score.max, JSON.stringify(res.findings), res.checkedAt).run()
      return jsonResponse(origin, 200, res)
    }

    // ---- Maintenance (Kluzar-built sites only by policy; the request
    // itself is a human-fulfilled task — this portal never edits a
    // website automatically.) ----
    if (path === '/api/maintenance/requests' && (method === 'GET' || method === 'POST')) {
      const denied = requirePremium(origin, auth)
      if (denied) return denied
      if (method === 'GET') {
        const rows = await env.DB.prepare('SELECT * FROM maintenance_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').bind(auth.userId).all()
        const requests = (rows.results || []).map((r) => ({
          id: r.id, siteUrl: r.site_url, title: r.title, details: r.details,
          status: r.status, createdAt: r.created_at,
        }))
        return jsonResponse(origin, 200, { ok: true, requests })
      }
      const body = await readJson(request)
      const norm = normalizeTargetUrl(body.url || body.siteUrl)
      if (!norm.ok) return errorResponse(origin, 400, norm.error)
      const title = typeof body.title === 'string' ? body.title.trim().slice(0, 200) : ''
      if (!title) return errorResponse(origin, 400, 'Add a short title for the change you need.')
      const details = typeof body.details === 'string' ? body.details.slice(0, 4000) : ''
      const id = randomId()
      const createdAt = nowIso()
      await env.DB.prepare('INSERT INTO maintenance_requests (id, user_id, site_url, title, details, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(id, auth.userId, norm.url, title, details, 'open', createdAt, createdAt).run()
      return jsonResponse(origin, 200, {
        ok: true,
        request: { id, siteUrl: norm.url, title, details, status: 'open', createdAt },
      })
    }

    return errorResponse(origin, 404, 'Not found.')
  },

  // Scheduled uptime checks (Cron Trigger). Checks monitors whose
  // interval has elapsed since the last check, stores one history row
  // per check, and updates the monitor status. No user input is
  // involved; targets come from the owner's own monitors table.
  async scheduled(event, env) {
    const monitors = await env.DB.prepare('SELECT * FROM uptime_monitors').all()
    for (const m of monitors.results || []) {
      const last = m.last_checked_at ? new Date(m.last_checked_at).getTime() : 0
      const intervalMs = (m.interval_minutes || 15) * 60_000
      if (Date.now() - last < intervalMs) continue
      const started = Date.now()
      let ok = false
      let statusCode = null
      try {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), 10_000)
        try {
          const res = await fetch(m.url, { method: 'GET', redirect: 'manual', signal: controller.signal })
          statusCode = res.status
          ok = res.status >= 200 && res.status < 400
          await res.arrayBuffer().catch(() => null)
        } finally {
          clearTimeout(timer)
        }
      } catch {
        ok = false
      }
      const checkedAt = nowIso()
      await env.DB.prepare('INSERT INTO uptime_checks (id, monitor_id, checked_at, ok, status_code, response_ms) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(randomId(), m.id, checkedAt, ok ? 1 : 0, statusCode, Date.now() - started).run()
      await env.DB.prepare('UPDATE uptime_monitors SET status = ?, last_checked_at = ?, updated_at = ? WHERE id = ?')
        .bind(ok ? 'up' : 'down', checkedAt, checkedAt, m.id).run()
    }
  },
}
