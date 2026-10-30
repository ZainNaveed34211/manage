// MANAGE API CLIENT + ANALYTICS + GOOGLE TAG GATE.
// Security rules enforced here (the Worker re-checks everything):
//  - Every protected call carries Authorization: Bearer <assertion>
//    obtained in-memory from account.ts. No assertion is ever stored.
//  - Google tags (gtag + AdSense) are injected ONLY on guest/upgrade
//    screens, ONLY after the plan check has run, and NEVER on premium
//    dashboard screens. The function below is the single gate: callers
//    must pass the resolved screen kind, and it refuses 'premium'.
//  - First-party analytics events are validated and stripped before
//    sending: no passwords, tokens, personal data, or scan contents
//    are ever included. The server drops unexpected fields again.

import { getAssertion, MANAGE_API_URL } from './account'

export const ADSENSE_CLIENT = 'ca-pub-3050978093233454'
export const GTAG_ID = 'G-T30S2TK79K'

export type ScreenKind = 'guest' | 'upgrade' | 'premium'

let googleTagsLoaded = false

// The ONLY place Google tags are ever loaded. Premium is refused
// outright, regardless of caller. Guest/upgrade load gtag + AdSense
// dynamically (never in <head>) after the plan check has completed.
export function loadGoogleTags(kind: ScreenKind): void {
  if (kind === 'premium') return
  if (googleTagsLoaded) return
  if (typeof document === 'undefined') return
  googleTagsLoaded = true
  const gtag = document.createElement('script')
  gtag.async = true
  gtag.src = `https://www.googletagmanager.com/gtag/js?id=${GTAG_ID}`
  document.head.appendChild(gtag)
  const inline = document.createElement('script')
  inline.text = `window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','${GTAG_ID}');`
  document.head.appendChild(inline)
  const ads = document.createElement('script')
  ads.async = true
  ads.src = `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${ADSENSE_CLIENT}`
  ads.crossOrigin = 'anonymous'
  // Once the library loads, request the ad units rendered on this
  // guest/upgrade screen. Premium screens never reach this function.
  ads.addEventListener('load', () => {
    try {
      const w = window as unknown as { adsbygoogle?: unknown[] }
      w.adsbygoogle = w.adsbygoogle || []
      w.adsbygoogle.push({})
    } catch {
      // An ad failing to render must never break the page.
    }
  })
  document.head.appendChild(ads)
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

// Call a protected Manage API endpoint. On 401 the assertion is
// refreshed once (the Accounts session may still be alive) and the
// call is retried a single time. A second 401 means the session is
// gone: the caller must return the user to the guest screen.
export async function callManage<T>(
  csrfToken: string,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const attempt = async (): Promise<Response> => {
    const token = await getAssertion(csrfToken)
    if (!token) throw new ApiError(401, 'Your session has ended. Please sign in again.')
    const headers = new Headers(init.headers || {})
    headers.set('Authorization', `Bearer ${token}`)
    if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    return fetch(`${MANAGE_API_URL}${path}`, { ...init, headers })
  }
  let res = await attempt()
  if (res.status === 401) {
    // Force a refresh by clearing the in-memory assertion, then retry once.
    const { clearAssertion } = await import('./account')
    clearAssertion()
    res = await attempt()
  }
  const data = (await res.json().catch(() => null)) as { ok?: unknown; error?: unknown } | null
  if (!res.ok || !data) {
    const msg = data && typeof data.error === 'string' ? data.error : 'Something went wrong. Please try again.'
    throw new ApiError(res.status, msg)
  }
  return data as T
}

// First-party privacy-conscious analytics. Only the allowlisted,
// non-sensitive fields below are sent; anything else is dropped here
// and again on the server. Never call this with URLs, scan output,
// emails, tokens, or free-form user text.
const ANALYTICS_FIELDS = ['event', 'tool', 'outcome'] as const
export type AnalyticsEvent = { event: string; tool?: string; outcome?: string }

export async function sendAnalytics(csrfToken: string, evt: AnalyticsEvent): Promise<void> {
  try {
    const body: Record<string, string> = { event: String(evt.event).slice(0, 64) }
    if (evt.tool) body.tool = String(evt.tool).slice(0, 64)
    if (evt.outcome) body.outcome = String(evt.outcome).slice(0, 32)
    void ANALYTICS_FIELDS
    await callManage(csrfToken, '/api/analytics/event', { method: 'POST', body: JSON.stringify(body) })
  } catch {
    // Analytics must never break the product or surface errors.
  }
}

// Analytics for guest/upgrade screens (no assertion exists yet): the
// event goes to the same endpoint without auth, and the server only
// accepts the same allowlisted, non-sensitive fields.
export async function sendPublicAnalytics(evt: AnalyticsEvent): Promise<void> {
  try {
    const body: Record<string, string> = { event: String(evt.event).slice(0, 64) }
    if (evt.tool) body.tool = String(evt.tool).slice(0, 64)
    if (evt.outcome) body.outcome = String(evt.outcome).slice(0, 32)
    await fetch(`${MANAGE_API_URL}/api/analytics/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  } catch {
    // Never break the page for analytics.
  }
}
