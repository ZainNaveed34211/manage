import { useEffect, useState, type ReactNode } from 'react'
import { callManage, ApiError } from '../lib/api'
import { normalizeTargetUrl } from '../lib/url'
import type { ScanResult } from '../lib/types'
import { EmptyState, ErrorBox, FindingRows, Loading, Pill, UrlForm } from '../components/components'

export function OverviewView(props: { csrfToken: string; plan: string }): ReactNode {
  const [me, setMe] = useState<{ plan: string; status: string } | null>(null)
  const [scans, setScans] = useState<ScanResult[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let live = true
    ;(async () => {
      try {
        const meRes = await callManage<{ plan: string; status: string }>(props.csrfToken, '/api/me')
        const scanRes = await callManage<{ scans: ScanResult[] }>(props.csrfToken, '/api/security/scans')
        if (!live) return
        setMe(meRes)
        setScans(scanRes.scans || [])
      } catch (e) {
        if (live) setError(e instanceof ApiError ? e.message : 'Could not load your dashboard.')
      } finally {
        if (live) setLoading(false)
      }
    })()
    return () => { live = false }
  }, [props.csrfToken])
  if (loading) return <Loading />
  if (error) return <ErrorBox message={error} />
  return (
    <div>
      <div className="grid" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3>Your plan</h3>
          <div className="big-num">{me ? me.plan : props.plan}</div>
          <p className="small muted">Status: {me ? me.status : 'active'}. Your subscription is checked live on every request.</p>
        </div>
        <div className="card">
          <h3>Security scans</h3>
          <div className="big-num">{scans.length}</div>
          <p className="small muted">Saved scans for your websites.</p>
        </div>
        <div className="card">
          <h3>Monitoring</h3>
          {props.plan === 'max'
            ? <p>Uptime Monitoring is included in your Max plan. Open it from the sidebar.</p>
            : <p>Uptime Monitoring is a Max feature. <span className="small muted">Your Growth plan includes the other tools here.</span></p>}
        </div>
      </div>
      <div className="card">
        <h2>Recent security scans</h2>
        {scans.length === 0
          ? <EmptyState title="No scans yet" body="Run your first security scan from the Security Scan tool." />
          : scans.slice(0, 5).map((s) => (
            <div className="check-row" key={`${s.url}-${s.checkedAt}`}>
              <div style={{ flex: 1 }}>
                <div className="title">{s.url}</div>
                <div className="small muted">{s.checkedAt} · Score {s.score.total}/{s.score.max}</div>
              </div>
              <Pill kind={s.score.total >= s.score.max * 0.8 ? 'ok' : 'warn'}>{s.score.total}/{s.score.max}</Pill>
            </div>
          ))}
      </div>
    </div>
  )
}

function useScan(csrfToken: string, path: string) {
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async (raw: string) => {
    const norm = normalizeTargetUrl(raw)
    if (!norm.ok) { setError(norm.error); return }
    setBusy(true)
    setError('')
    try {
      const res = await callManage<ScanResult>(csrfToken, path, { method: 'POST', body: JSON.stringify({ url: norm.url }) })
      setResult(res)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'The check could not be completed.')
    } finally {
      setBusy(false)
    }
  }
  return { result, error, busy, run }
}

export function SecurityScanView(props: { csrfToken: string }): ReactNode {
  const { result, error, busy, run } = useScan(props.csrfToken, '/api/security/scan')
  return (
    <div className="card">
      <h2>Website Security Scan</h2>
      <p>Safe, non-destructive checks: security headers, HTTPS indicators, cookie attributes, public JavaScript and source-map exposure, public configuration exposure, and DNS indicators — with clear remediation guidance. Nothing is executed from the scanned site and no exploit attempts are made.</p>
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

export function SecurityOverviewView(props: { csrfToken: string; depth: 'standard' | 'deep' }): ReactNode {
  const { result, error, busy, run } = useScan(props.csrfToken, '/api/security/overview')
  return (
    <div className="card">
      <h2>Security Overview</h2>
      <p>{props.depth === 'deep'
        ? 'Deeper security assessment for Max: everything in the standard overview, plus extended header analysis, TLS indicators, and exposure checks.'
        : 'A deeper look at your website security posture: headers, transport, cookies, and public exposure, summarized with priorities.'}</p>
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
