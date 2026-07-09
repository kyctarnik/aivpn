import type { Context } from 'hono'
import { getConnInfo as getNodeConnInfo } from '@hono/node-server/conninfo'
import { getConnInfo as getBunConnInfo } from 'hono/bun'
import { TRUST_PROXY } from '../config'

/**
 * Single source of truth for client IP resolution (rate limits, audit log,
 * session records).
 *
 * X-Forwarded-For / X-Real-IP are attacker-controlled request headers: they
 * are only honoured when AIVPN_WEB_TRUST_PROXY=true, i.e. when the operator
 * has confirmed a trusted reverse proxy overwrites them. Otherwise the real
 * socket peer address is used, so a client cannot spoof its IP to bypass
 * per-IP rate limits or forge audit-log entries.
 */

function socketAddress(c: Context): string | null {
  // The app is served via @hono/node-server (which also works on Bun through
  // node:http), so try its conninfo helper first; fall back to the native
  // Bun adapter in case the app is ever served with Bun.serve directly.
  for (const getInfo of [getNodeConnInfo, getBunConnInfo]) {
    try {
      const addr = getInfo(c).remote?.address
      if (addr) return addr
    } catch {
      /* adapter mismatch — try the next one */
    }
  }
  return null
}

export function getClientIp(c: Context): string {
  if (TRUST_PROXY) {
    const forwarded = c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
      ?? c.req.header('x-real-ip')
    if (forwarded) return forwarded
  }
  return socketAddress(c) ?? 'unknown'
}
