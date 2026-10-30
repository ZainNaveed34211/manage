// Shared response shapes for Manage API tool endpoints. The Worker is
// authoritative; these types only describe what it returns. No demo or
// sample data is constructed anywhere in the frontend — empty states
// are shown until a real server response arrives.

export interface Finding {
  id: string
  title: string
  status: 'pass' | 'attention' | 'not_checked'
  severity: 'low' | 'medium' | 'high'
  detail: string
  recommendation: string
}

export interface ScanResult {
  ok: boolean
  url: string
  checkedAt: string
  score: { total: number; max: number }
  findings: Finding[]
}

export interface UptimeMonitor {
  id: string
  url: string
  name: string
  intervalMinutes: number
  status: string
  lastCheckedAt: string | null
  uptimePct: number | null
}

export interface UptimeCheck {
  id: string
  monitorId: string
  checkedAt: string
  ok: boolean
  statusCode: number | null
  responseMs: number | null
}

export interface PerfResult {
  ok: boolean
  url: string
  checkedAt: string
  ttfbMs: number | null
  totalMs: number | null
  statusCode: number | null
  checks: Finding[]
}

export interface MaintenanceRequest {
  id: string
  siteUrl: string
  title: string
  details: string
  status: string
  createdAt: string
}
