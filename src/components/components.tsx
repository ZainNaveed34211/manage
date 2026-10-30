import { useState, type ReactNode } from 'react'
import { LOGO_DARK_URL } from '../logoData'

export type ToolId =
  | 'overview' | 'security' | 'security-overview' | 'uptime'
  | 'performance' | 'accessibility' | 'maintenance'

export interface NavItem {
  id: ToolId
  label: string
  locked?: boolean
  lockedNote?: string
}

export function Sidebar(props: {
  planLabel: string
  theme: 'light' | 'dark'
  active: ToolId
  items: NavItem[]
  onSelect: (id: ToolId) => void
}): ReactNode {
  const { planLabel, active, items, onSelect } = props
  return (
    <aside className="sidebar">
      <span className="logo">
        {/* Sidebar background is always dark navy, so always the dark-background logo variant (existing asset, logo itself untouched). */}
        <img src={LOGO_DARK_URL} alt="Kluzar" />
      </span>
      <span className="plan-pill">{planLabel} plan</span>
      <nav>
        {items.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`nav-btn${item.id === active ? ' active' : ''}${item.locked ? ' locked' : ''}`}
            onClick={() => onSelect(item.id)}
          >
            {item.label}{item.locked ? ' 🔒' : ''}
          </button>
        ))}
      </nav>
      <div className="foot">Website Management &amp; Monitoring. Premium service for Kluzar subscribers.</div>
    </aside>
  )
}

export function Pill(props: { kind: 'ok' | 'warn' | 'bad' | 'plain' | 'premium' | 'live'; children: ReactNode }): ReactNode {
  const cls = props.kind === 'plain' ? 'pill' : `pill ${props.kind}`
  return <span className={cls}>{props.children}</span>
}

export function Loading(): ReactNode {
  return <div className="empty" role="status">Loading…</div>
}

export function ErrorBox(props: { message: string; onRetry?: () => void }): ReactNode {
  return (
    <div className="error" role="alert">
      {props.message}
      {props.onRetry ? (
        <div style={{ marginTop: 10 }}>
          <button type="button" className="ghost-btn" onClick={props.onRetry}>Try again</button>
        </div>
      ) : null}
    </div>
  )
}

export function EmptyState(props: { title: string; body: string }): ReactNode {
  return (
    <div className="empty">
      <strong>{props.title}</strong>
      <div>{props.body}</div>
    </div>
  )
}

// Shared URL input + run button for the URL-based tools. Validation
// here is UX feedback only; the Worker re-validates server-side.
export function UrlForm(props: {
  label: string
  busy: boolean
  onRun: (url: string) => void
}): ReactNode {
  const [value, setValue] = useState('')
  return (
    <form
      className="field-row"
      onSubmit={(e) => {
        e.preventDefault()
        props.onRun(value)
      }}
    >
      <label className="small muted" htmlFor="tool-url" style={{ width: '100%' }}>{props.label}</label>
      <input
        id="tool-url"
        className="url-input"
        type="text"
        inputMode="url"
        autoComplete="off"
        placeholder="example.com or https://example.com"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button type="submit" className="primary-btn" disabled={props.busy || !value.trim()}>
        {props.busy ? 'Checking…' : 'Check'}
      </button>
    </form>
  )
}

export function FindingRows(props: { findings: { id: string; title: string; status: string; severity: string; detail: string; recommendation: string }[] }): ReactNode {
  if (props.findings.length === 0) return <EmptyState title="No checks yet" body="Run a check to see results here." />
  return (
    <div>
      {props.findings.map((f) => (
        <div className="check-row" key={f.id}>
          <div style={{ flex: 1 }}>
            <div className="title">{f.title}</div>
            <div className="rec">{f.detail}</div>
            {f.status !== 'pass' && f.recommendation ? <div className="rec"><strong>Do this:</strong> {f.recommendation}</div> : null}
          </div>
          <Pill kind={f.status === 'pass' ? 'ok' : f.status === 'attention' ? (f.severity === 'high' ? 'bad' : 'warn') : 'plain'}>
            {f.status === 'pass' ? 'Good' : f.status === 'attention' ? 'Needs work' : 'Not checked'}
          </Pill>
        </div>
      ))}
    </div>
  )
}
