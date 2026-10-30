// ACCOUNT & ASSERTION — Kluzar Manage.
// The Accounts API session is the ONLY authority on identity. The plan
// shown here comes from GET /auth/session on every page load; the
// Manage API re-verifies identity + entitlement server-side on every
// request (see worker/src/index.js). Nothing in this file is proof of
// a paid plan — a frontend value can at most change local display.
//
// The signed assertion is held IN MEMORY ONLY (a module variable).
// It is never written to any browser storage, a cookie, or a
// URL. It is never stored by the service worker. On expiry the app
// silently requests a fresh one while the Accounts session is alive.
// The assertion carries NO plan and NO personal data — only opaque
// user/session ids — and it is never used as proof of subscription:
// the Manage API reads the live entitlement from shared D1 itself.

function envVal(v: string | undefined): string {
  return v && v.trim() ? v.trim().replace(/\/$/, '') : ''
}

export const LOGIN_URL = envVal(import.meta.env.VITE_LOGIN_URL as string | undefined)
  || 'https://accounts.kluzar.com'
export const PREMIUM_URL = envVal(import.meta.env.VITE_PREMIUM_URL as string | undefined)
  || 'https://payments.kluzar.com'
export const MANAGE_URL = 'https://manage.kluzar.com/'
export const ACCOUNT_LOGIN_URL = `${LOGIN_URL}/login/?next=${encodeURIComponent(MANAGE_URL)}`
export const PREMIUM_RETURN_URL = `${PREMIUM_URL}/?return=${encodeURIComponent(MANAGE_URL)}`
export const SESSION_BASE = envVal(import.meta.env.VITE_AUTH_SESSION_URL as string | undefined)
  || 'https://account-api.kluzar.com/auth'
export const MANAGE_API_URL = envVal(import.meta.env.VITE_MANAGE_API_URL as string | undefined)
  || 'https://manage-api.kluzar.com'

export type Plan = 'free' | 'growth' | 'max'

export interface AccountState {
  authenticated: boolean
  plan: Plan
  planLabel: string
  premium: boolean
  detail: string
  csrfToken: string
}

function planLabelFor(plan: unknown): string {
  if (plan === 'growth') return 'Growth'
  if (plan === 'max') return 'Max'
  return 'Free'
}

function toPlan(plan: unknown): Plan {
  if (plan === 'growth' || plan === 'max') return plan
  return 'free'
}

// In-memory only. Deliberately NOT exported for storage: the only
// accessors are getAssertion (refreshes when needed) and clearAssertion.
let assertion: string | null = null
let assertionExpMs = 0

export function clearAssertion(): void {
  assertion = null
  assertionExpMs = 0
}

export async function checkAccountStatus(): Promise<AccountState> {
  const fallback: AccountState = {
    authenticated: false, plan: 'free', planLabel: 'Free', premium: false,
    detail: 'We could not sign you in.', csrfToken: '',
  }
  try {
    const res = await fetch(`${SESSION_BASE}/session`, { credentials: 'include' })
    const session = (await res.json().catch(() => null)) as {
      authenticated?: unknown
      user?: { email?: unknown } | null
      csrfToken?: unknown
      entitlement?: { plan?: unknown; status?: unknown; premium?: unknown } | null
    } | null
    if (!res.ok || !session || session.authenticated !== true) return fallback
    const e = session.entitlement
    const premium = e?.premium === true
      && (e?.plan === 'growth' || e?.plan === 'max')
      && e?.status === 'active'
    const plan = premium ? toPlan(e?.plan) : 'free'
    return {
      authenticated: true,
      plan,
      planLabel: premium ? planLabelFor(e?.plan) : 'Free',
      premium,
      detail: premium ? `Signed in — ${planLabelFor(e?.plan)} plan.` : 'Signed in — Starter (Free).',
      csrfToken: typeof session.csrfToken === 'string' ? session.csrfToken : '',
    }
  } catch {
    return fallback
  }
}

// Fetch a fresh 5-minute assertion from the Accounts API. Requires a
// live session cookie (sent automatically) plus the CSRF token (the
// token's proper use: protecting this issuance POST, never acting as
// an authentication credential itself). Returns null when the session
// is gone, the CSRF check fails, or the origin is not allowed.
export async function getAssertion(csrfToken: string): Promise<string | null> {
  const now = Date.now()
  if (assertion && assertionExpMs - now > 60_000) return assertion
  try {
    const res = await fetch(`${SESSION_BASE}/manage-assertion`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: '{}',
    })
    const data = (await res.json().catch(() => null)) as {
      ok?: unknown; assertion?: unknown; expiresIn?: unknown
    } | null
    if (!res.ok || !data || data.ok !== true || typeof data.assertion !== 'string') {
      clearAssertion()
      return null
    }
    assertion = data.assertion
    const ttl = typeof data.expiresIn === 'number' && data.expiresIn > 0 ? data.expiresIn : 300
    assertionExpMs = now + ttl * 1000
    return assertion
  } catch {
    clearAssertion()
    return null
  }
}
