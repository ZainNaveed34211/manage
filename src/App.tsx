import { useCallback, useEffect, useState, type ReactNode } from 'react'
import {
  ACCOUNT_LOGIN_URL, PREMIUM_RETURN_URL, checkAccountStatus,
  type AccountState,
} from './lib/account'
import { loadGoogleTags, sendAnalytics, sendPublicAnalytics } from './lib/api'
import { LOGO_URL } from './logoData'
import { Sidebar, type ToolId } from './components/components'
import { OverviewView, SecurityOverviewView, SecurityScanView } from './tools/OverviewAndSecurity'
import { AccessibilityView, MaintenanceView, PerformanceView, UptimeView } from './tools/MonitoringTools'
import './styles.css'

type Screen = 'loading' | 'guest' | 'upgrade' | 'dashboard'
type Theme = 'light' | 'dark'

function GuestScreen(): ReactNode {
  return (
    <main className="hero">
      <img className="logo" src={LOGO_URL} alt="Kluzar" />
      <h1>Website Management &amp; Monitoring — for premium subscribers</h1>
      <p>
        Kluzar Manage keeps your website secure, online, fast, and accessible —
        with security scans, uptime monitoring, performance checks, accessibility
        checks, and maintenance for Kluzar-built websites. This is a premium-only
        service for Growth and Max subscribers.
      </p>
      <div style={{ marginTop: 24 }}>
        <a href={ACCOUNT_LOGIN_URL}><button type="button" className="primary-btn">Log in</button></a>
      </div>
      <p className="small muted" style={{ marginTop: 16 }}>
        After you log in, you return right here. If your subscription is not
        premium yet, you will see how to upgrade.
      </p>
      <div className="ad-slot" aria-label="Advertisement">
        <ins className="adsbygoogle" style={{ display: 'block' }} data-ad-client="ca-pub-3050978093233454" data-ad-slot="auto" data-ad-format="auto" data-full-width-responsive="true" />
      </div>
    </main>
  )
}

function UpgradeScreen(props: { detail: string }): ReactNode {
  return (
    <main className="hero">
      <img className="logo" src={LOGO_URL} alt="Kluzar" />
      <h1>Upgrade to unlock Website Management</h1>
      <p>
        {props.detail} Website Management &amp; Monitoring is included with
        Growth and Max subscriptions — security scans, performance and
        accessibility checks, maintenance for Kluzar-built websites, and (on Max)
        uptime monitoring.
      </p>
      <div style={{ marginTop: 24 }}>
        <a href={PREMIUM_RETURN_URL}><button type="button" className="primary-btn">Get Premium</button></a>
      </div>
      <p className="small muted" style={{ marginTop: 16 }}>
        After checkout, you return to manage.kluzar.com.
      </p>
      <div className="ad-slot" aria-label="Advertisement">
        <ins className="adsbygoogle" style={{ display: 'block' }} data-ad-client="ca-pub-3050978093233454" data-ad-slot="auto" data-ad-format="auto" data-full-width-responsive="true" />
      </div>
    </main>
  )
}

export default function App(): ReactNode {
  const [screen, setScreen] = useState<Screen>('loading')
  const [account, setAccount] = useState<AccountState | null>(null)
  const [active, setActive] = useState<ToolId>('overview')
  const [theme, setTheme] = useState<Theme>(() =>
    typeof document !== 'undefined' && document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light',
  )
  const [updateAvailable, setUpdateAvailable] = useState(false)

  const applyTheme = useCallback((t: Theme) => {
    setTheme(t)
    document.documentElement.setAttribute('data-theme', t)
    // Theme is a display preference held in memory only. No browser
    // storage is used by this app for anything credential-related —
    // and the assertion is never stored anywhere at all.
  }, [])

  useEffect(() => {
    // Default to the OS preference on first load; the toggle above
    // changes it for this session.
    if (typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      applyTheme('dark')
    }
  }, [applyTheme])

  // Service worker registration + update banner (never silent updates).
  useEffect(() => {
    if (!('serviceWorker' in navigator)) return
    navigator.serviceWorker.register('/sw.js').then((reg) => {
      if (reg.waiting) setUpdateAvailable(true)
      reg.addEventListener('updatefound', () => {
        const worker = reg.installing
        if (!worker) return
        worker.addEventListener('statechange', () => {
          if (worker.state === 'installed' && navigator.serviceWorker.controller) setUpdateAvailable(true)
        })
      })
    }).catch(() => { /* offline/PWA is an enhancement, never a blocker */ })
    const onController = () => window.location.reload()
    navigator.serviceWorker.addEventListener('controllerchange', onController)
    return () => navigator.serviceWorker.removeEventListener('controllerchange', onController)
  }, [])

  // Session + plan check on every page load. Google tags are loaded
  // ONLY after this resolves, and ONLY for guest/upgrade screens —
  // loadGoogleTags itself refuses 'premium'.
  useEffect(() => {
    let live = true
    ;(async () => {
      const state = await checkAccountStatus()
      if (!live) return
      setAccount(state)
      if (!state.authenticated) {
        setScreen('guest')
        loadGoogleTags('guest')
        void sendPublicAnalytics({ event: 'page_view', tool: 'guest' })
      } else if (!state.premium) {
        setScreen('upgrade')
        loadGoogleTags('upgrade')
        void sendPublicAnalytics({ event: 'page_view', tool: 'upgrade' })
      } else {
        setScreen('dashboard')
        void sendAnalytics(state.csrfToken, { event: 'page_view', tool: 'dashboard', outcome: 'ok' })
      }
    })()
    return () => { live = false }
  }, [])

  const openTool = (id: ToolId) => {
    setActive(id)
    if (account) void sendAnalytics(account.csrfToken, { event: 'tool_open', tool: id, outcome: 'ok' })
  }

  if (screen === 'loading') {
    return <main className="hero"><p role="status">Checking your subscription…</p></main>
  }
  if (screen === 'guest') return <><GuestScreen /></>
  if (screen === 'upgrade') return <><UpgradeScreen detail={account?.detail || ''} /></>

  // Dashboard (premium only — the Worker enforces this again per request).
  const plan = account?.plan || 'growth'
  const isMax = plan === 'max'
  const navItems = [
    { id: 'overview' as ToolId, label: 'Overview' },
    { id: 'security' as ToolId, label: 'Security Scan' },
    { id: 'security-overview' as ToolId, label: 'Security Overview' },
    { id: 'uptime' as ToolId, label: 'Uptime Monitoring', locked: !isMax, lockedNote: 'Max only' },
    { id: 'performance' as ToolId, label: 'Performance Monitor' },
    { id: 'accessibility' as ToolId, label: 'Accessibility Checker' },
    { id: 'maintenance' as ToolId, label: 'Maintenance' },
  ]
  const csrf = account?.csrfToken || ''

  const renderTool = (): ReactNode => {
    switch (active) {
      case 'overview': return <OverviewView csrfToken={csrf} plan={plan} />
      case 'security': return <SecurityScanView csrfToken={csrf} />
      case 'security-overview': return <SecurityOverviewView csrfToken={csrf} depth={isMax ? 'deep' : 'standard'} />
      case 'uptime':
        if (!isMax) {
          return (
            <div className="locked-box">
              <h2>Uptime Monitoring is a Max feature 🔒</h2>
              <p>Your Growth plan includes security, performance, accessibility, and maintenance tools. Uptime Monitoring — scheduled checks with history — is included with Max.</p>
              <a href={PREMIUM_RETURN_URL}><button type="button" className="primary-btn">Upgrade to Max</button></a>
            </div>
          )
        }
        return <UptimeView csrfToken={csrf} />
      case 'performance': return <PerformanceView csrfToken={csrf} tier={isMax ? 'unlimited' : 'advanced'} />
      case 'accessibility': return <AccessibilityView csrfToken={csrf} tier={isMax ? 'unlimited' : 'advanced'} />
      case 'maintenance': return <MaintenanceView csrfToken={csrf} />
      default: return <OverviewView csrfToken={csrf} plan={plan} />
    }
  }

  return (
    <div className="shell">
      <Sidebar
        theme={theme}
        planLabel={account?.planLabel || 'Growth'}
        active={active}
        items={navItems}
        onSelect={openTool}
      />
      <div className="main">
        <div className="topbar">
          <h1>Kluzar Manage</h1>
          <span className="spacer" />
          <span className="pill premium">{account?.planLabel} plan</span>
          <button type="button" className="theme-btn" onClick={() => applyTheme(theme === 'dark' ? 'light' : 'dark')}>
            {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
          </button>
        </div>
        {renderTool()}
      </div>
      {updateAvailable ? (
        <div className="update-banner" role="alert">
          A new version of Kluzar Manage is available.
          <button type="button" onClick={() => {
            navigator.serviceWorker.getRegistration().then((reg) => reg?.waiting?.postMessage({ type: 'SKIP_WAITING' }))
          }}>Refresh</button>
        </div>
      ) : null}
    </div>
  )
}
