-- 0001_manage: Kluzar Manage portal tables. ADDITIVE ONLY.
-- This migration creates ONLY new tables. It never alters, renames,
-- or drops any existing table (users, sessions, entitlements,
-- mfa_secrets, audit_events, rate_limits, or anything else), and it
-- never writes to those tables. Manage reads sessions/users/
-- entitlements; it writes only the tables below.
-- No column in these tables stores passwords, tokens, session
-- credentials, or scan contents — findings are stored as structured
-- indicator rows (title/status/severity/detail/recommendation), and
-- configuration-probe bodies are never stored at all.

CREATE TABLE IF NOT EXISTS manage_sites (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  url TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_manage_sites_user ON manage_sites(user_id);

CREATE TABLE IF NOT EXISTS security_scans (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  url TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'scan',
  score_total INTEGER NOT NULL DEFAULT 0,
  score_max INTEGER NOT NULL DEFAULT 0,
  findings_json TEXT NOT NULL DEFAULT '[]',
  checked_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (site_id) REFERENCES manage_sites(id)
);
CREATE INDEX IF NOT EXISTS idx_security_scans_user ON security_scans(user_id);

CREATE TABLE IF NOT EXISTS uptime_monitors (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  url TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  interval_minutes INTEGER NOT NULL DEFAULT 15,
  status TEXT NOT NULL DEFAULT 'unknown',
  last_checked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_uptime_monitors_user ON uptime_monitors(user_id);

CREATE TABLE IF NOT EXISTS uptime_checks (
  id TEXT PRIMARY KEY,
  monitor_id TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  ok INTEGER NOT NULL DEFAULT 0,
  status_code INTEGER,
  response_ms INTEGER,
  FOREIGN KEY (monitor_id) REFERENCES uptime_monitors(id)
);
CREATE INDEX IF NOT EXISTS idx_uptime_checks_monitor ON uptime_checks(monitor_id);

CREATE TABLE IF NOT EXISTS performance_checks (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  url TEXT NOT NULL,
  ttfb_ms INTEGER,
  total_ms INTEGER,
  status_code INTEGER,
  checked_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (site_id) REFERENCES manage_sites(id)
);
CREATE INDEX IF NOT EXISTS idx_performance_checks_user ON performance_checks(user_id);

CREATE TABLE IF NOT EXISTS accessibility_checks (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  url TEXT NOT NULL,
  score_total INTEGER NOT NULL DEFAULT 0,
  score_max INTEGER NOT NULL DEFAULT 0,
  findings_json TEXT NOT NULL DEFAULT '[]',
  checked_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (site_id) REFERENCES manage_sites(id)
);
CREATE INDEX IF NOT EXISTS idx_accessibility_checks_user ON accessibility_checks(user_id);

CREATE TABLE IF NOT EXISTS maintenance_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  site_url TEXT NOT NULL,
  title TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_maintenance_requests_user ON maintenance_requests(user_id);

-- First-party privacy analytics. Deliberately minimal: event name,
-- tool, and outcome only. No URL, IP, email, token, or scan content
-- is ever stored here (the endpoint allowlists fields and drops the
-- rest before insert; user_id is stored as '' for guest/upgrade
-- events, which carry no identity).
CREATE TABLE IF NOT EXISTS analytics_events (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL,
  tool TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analytics_events_created ON analytics_events(created_at);
