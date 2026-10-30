// Entitlement logic — mirrors the Accounts API getEntitlement rule
// exactly, not redefined: premium iff plan is growth/max AND status is
// active. No row means free. This module only READS the entitlements
// table; it never writes to it, and it never defines new plans.

export async function getEntitlement(db, userId) {
  const row = await db.prepare('SELECT * FROM entitlements WHERE user_id = ?').bind(userId).first()
  if (!row) return { plan: 'free', status: 'active', premium: false }
  const premium = (row.plan === 'growth' || row.plan === 'max') && row.status === 'active'
  return { plan: row.plan, status: row.status, premium }
}

// Per-tool gate on top of the live entitlement. Uptime is Max-only.
// Everything else in this portal requires premium (growth or max).
export function toolAllowed(plan, tool) {
  if (tool === 'uptime') return plan === 'max'
  return plan === 'growth' || plan === 'max'
}
