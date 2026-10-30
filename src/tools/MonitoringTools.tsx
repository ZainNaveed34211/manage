import { useEffect, useState, type ReactNode } from 'react'
import { callManage, ApiError } from '../lib/api'
import { normalizeTargetUrl } from '../lib/url'
import type { MaintenanceRequest, PerfResult, UptimeCheck, UptimeMonitor } from '../lib/types'
import { EmptyState, ErrorBox, FindingRows, Loading, Pill, UrlForm } from '../components/components'

export function UptimeView(props: { csrfToken: string }): ReactNode {
  const [monitors, setMonitors] = useState<UptimeMonitor[]>([])
  const [selected, setSelected] = useState<UptimeMonitor | null>(null)
  const [checks, setChecks] = useState<UptimeCheck[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [url, setUrl] = useState('')
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirmId, setConfirmId] = useState<string | null>(null)
  const [removingId, setRemovingId] = useState<string | null>(null)

  const load = async () => {
    try {
      const res = await callManage<{ monitors: UptimeMonitor[] }>(props.csrfToken, '/api/uptime/monitors')
      setMonitors(res.monitors || [])
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Could not load monitors.')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { void load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const openChecks = async (m: UptimeMonitor) => {
    setSelected(m)
    try {
      const res = await callManage<{ checks: UptimeCheck[] }>(props.csrfToken, `/api/uptime/checks?monitorId=${encodeURIComponent(m.id)}`)
      setChecks(res.checks || [])
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Could not load check history.')
    }
  }

  const addMonitor = async (e: React.FormEvent) => {
    e.preventDefault()
    const norm = normalizeTargetUrl(url)
    if (!norm.ok) { setError(norm.error); return }
    setBusy(true)
    setError('')
    try {
      await callManage(props.csrfToken, '/api/uptime/monitors', {
        method: 'POST',
        body: JSON.stringify({ url: norm.url, name: name.trim() || norm.url }),
      })
      setUrl('')
      setName('')
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The monitor could not be added.')
    } finally {
      setBusy(false)
    }
  }

  const removeMonitor = async (m: UptimeMonitor) => {
    if (confirmId !== m.id) { setConfirmId(m.id); return }
    setConfirmId(null)
    setRemovingId(m.id)
    setError('')
    try {
      await callManage(props.csrfToken, '/api/uptime/monitors/delete', {
        method: 'POST',
        body: JSON.stringify({ monitorId: m.id }),
      })
      setMonitors((prev) => prev.filter((x) => x.id !== m.id))
      if (selected?.id === m.id) { setSelected(null); setChecks([]) }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'The monitor could not be removed.')
    } finally {
      setRemovingId(null)
    }
  }

  if (loading) return <Loading />
  return (
    <div>
      <div className="card">
        <h2>Uptime Monitoring <Pill kind="premium">Max only</Pill></h2>
        <p>Scheduled checks of your websites. A monitor is checked on its interval by the Manage Worker, and every result is stored as history. This tool is included in the Max plan only.</p>
        <form className="field-row" onSubmit={addMonitor}>
          <input className="url-input" placeholder="Website URL" value={url} onChange={(e) => setUrl(e.target.value)} />
          <input className="url-input" placeholder="Name (optional)" value={name} onChange={(e) => setName(e.target.value)} />
          <button type="submit" className="primary-btn" disabled={busy || !url.trim()}>{busy ? 'Adding…' : 'Add monitor'}</button>
        </form>
        {error ? <ErrorBox message={error} /> : null}
        {monitors.length === 0
          ? <EmptyState title="No monitors yet" body="Add your first website above to start uptime monitoring." />
          : (
            <table>
              <thead><tr><th>Website</th><th>Status</th><th>Uptime</th><th>Last check</th><th></th></tr></thead>
              <tbody>
                {monitors.map((m) => (
                  <tr key={m.id}>
                    <td><strong>{m.name}</strong><div className="small muted">{m.url}</div></td>
                    <td><Pill kind={m.status === 'up' ? 'ok' : m.status === 'down' ? 'bad' : 'plain'}>{m.status}</Pill></td>
                    <td>{m.uptimePct === null ? '—' : `${m.uptimePct}%`}</td>
                    <td className="small muted">{m.lastCheckedAt || 'Not checked yet'}</td>
                    <td>
                      <button type="button" className="ghost-btn" onClick={() => void openChecks(m)}>History</button>{' '}
                      <button type="button" className="ghost-btn" disabled={removingId === m.id} onClick={() => void removeMonitor(m)}>
                        {removingId === m.id ? 'Removing…' : confirmId === m.id ? 'Confirm remove?' : 'Remove'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </div>
      {selected ? (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>History — {selected.name}</h3>
          {checks.length === 0
            ? <EmptyState title="No checks yet" body="Checks appear here once the scheduled monitor runs." />
            : (
              <table>
                <thead><tr><th>When</th><th>Result</th><th>Status</th><th>Response time</th></tr></thead>
                <tbody>
                  {checks.map((c) => (
                    <tr key={c.id}>
                      <td className="small muted">{c.checkedAt}</td>
                      <td><Pill kind={c.ok ? 'ok' : 'bad'}>{c.ok ? 'Up' : 'Down'}</Pill></td>
                      <td>{c.statusCode ?? '—'}</td>
                      <td>{c.responseMs === null ? '—' : `${c.responseMs} ms`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </div>
      ) : null}
    </div>
  )
}

export function PerformanceView(props: { csrfToken: string; tier: 'advanced' | 'unlimited' }): ReactNode {
  const [result, setResult] = useState<PerfResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (raw: string) => {
    const norm = normalizeTargetUrl(raw)
    if (!norm.ok) { setError(norm.error); return }
    setBusy(true)
    setError('')
    try {
      const res = await callManage<PerfResult>(props.csrfToken, '/api/performance/check', { method: 'POST', body: JSON.stringify({ url: norm.url }) })
      setResult(res)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'The performance check could not be completed.')
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="card">
      <h2>Website Performance Monitor <Pill kind="premium">{props.tier === 'unlimited' ? 'Unlimited' : 'Advanced'}</Pill></h2>
      <p>Server-side timing and response indicators for a page: time to first byte, total fetch time, and response headers that affect loading. This is a server-side measurement, not a browser Lighthouse audit.</p>
      <UrlForm label="Website URL" busy={busy} onRun={run} />
      {error ? <ErrorBox message={error} /> : null}
      {result ? (
        <div style={{ marginTop: 16 }}>
          <div className="grid">
            <div><div className="big-num">{result.ttfbMs === null ? '—' : `${result.ttfbMs} ms`}</div><div className="small muted">Time to first byte</div></div>
            <div><div className="big-num">{result.totalMs === null ? '—' : `${result.totalMs} ms`}</div><div className="small muted">Total fetch time</div></div>
            <div><div className="big-num">{result.statusCode ?? '—'}</div><div className="small muted">HTTP status</div></div>
          </div>
          <div style={{ marginTop: 16 }}><FindingRows findings={result.checks} /></div>
        </div>
      ) : null}
    </div>
  )
}

export function AccessibilityView(props: { csrfToken: string; tier: 'advanced' | 'unlimited' }): ReactNode {
  const [result, setResult] = useState<import('../lib/types').ScanResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (raw: string) => {
    const norm = normalizeTargetUrl(raw)
    if (!norm.ok) { setError(norm.error); return }
    setBusy(true)
    setError('')
    try {
      const res = await callManage<import('../lib/types').ScanResult>(props.csrfToken, '/api/accessibility/check', { method: 'POST', body: JSON.stringify({ url: norm.url }) })
      setResult(res)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'The accessibility check could not be completed.')
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="card">
      <h2>Accessibility Checker <Pill kind="premium">{props.tier === 'unlimited' ? 'Unlimited' : 'Advanced'}</Pill></h2>
      <p>Automated HTML-based checks: page language, title, heading order, image alt text, form labels, link text, and colour-contrast hints. These are automated checks — they do not replace a full manual accessibility audit.</p>
      <UrlForm label="Website URL" busy={busy} onRun={run} />
      {error ? <ErrorBox message={error} /> : null}
      {result ? (
        <div style={{ marginTop: 16 }}>
          <p><strong>Results for {result.url}</strong> · Score {result.score.total}/{result.score.max}</p>
          <FindingRows findings={result.findings} />
        </div>
      ) : null}
    </div>
  )
}

export function MaintenanceView(props: { csrfToken: string }): ReactNode {
  const [items, setItems] = useState<MaintenanceRequest[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [siteUrl, setSiteUrl] = useState('')
  const [title, setTitle] = useState('')
  const [details, setDetails] = useState('')
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState('')

  const load = async () => {
    try {
      const res = await callManage<{ requests: MaintenanceRequest[] }>(props.csrfToken, '/api/maintenance/requests')
      setItems(res.requests || [])
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Could not load maintenance requests.')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { void load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const norm = normalizeTargetUrl(siteUrl)
    if (!norm.ok) { setError(norm.error); return }
    if (!title.trim()) { setError('Add a short title for the change you need.'); return }
    setBusy(true)
    setError('')
    setNote('')
    try {
      const res = await callManage<{ request: MaintenanceRequest }>(props.csrfToken, '/api/maintenance/requests', {
        method: 'POST',
        body: JSON.stringify({ siteUrl: norm.url, title: title.trim(), details: details.trim() }),
      })
      setItems((prev) => [res.request, ...prev])
      setSiteUrl('')
      setTitle('')
      setDetails('')
      setNote('Request received. Changes are made by the Kluzar team — nothing is edited automatically.')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The request could not be sent.')
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <Loading />
  return (
    <div>
      <div className="card">
        <h2>Website Maintenance</h2>
        <p>Request changes for your Kluzar-built website — text changes, photo replacement, and other included updates. This tool is for Kluzar-built websites only. Requests are handled by the Kluzar team; this portal never edits your website automatically.</p>
        <form onSubmit={submit}>
          <div className="field-row">
            <input className="url-input" placeholder="Your Kluzar-built website URL" value={siteUrl} onChange={(e) => setSiteUrl(e.target.value)} />
            <input className="url-input" placeholder="Change title, e.g. Update homepage text" value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <textarea className="notes" placeholder="Describe the change you need…" value={details} onChange={(e) => setDetails(e.target.value)} />
          <div className="field-row">
            <button type="submit" className="primary-btn" disabled={busy}>{busy ? 'Sending…' : 'Send request'}</button>
          </div>
        </form>
        {note ? <div className="notice" style={{ marginTop: 12 }}>{note}</div> : null}
        {error ? <div style={{ marginTop: 12 }}><ErrorBox message={error} /></div> : null}
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        <h3>Your requests</h3>
        {items.length === 0
          ? <EmptyState title="No requests yet" body="Your maintenance requests and their status will appear here." />
          : items.map((r) => (
            <div className="check-row" key={r.id}>
              <div style={{ flex: 1 }}>
                <div className="title">{r.title}</div>
                <div className="small muted">{r.siteUrl} · {r.createdAt}</div>
                {r.details ? <div className="small muted">{r.details}</div> : null}
              </div>
              <Pill kind={r.status === 'done' ? 'ok' : r.status === 'in_progress' ? 'warn' : 'plain'}>{r.status}</Pill>
            </div>
          ))}
      </div>
    </div>
  )
}
