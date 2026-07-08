import { Hono } from 'hono'
import type { Context, Next } from 'hono'
import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
import { secureHeaders } from 'hono/secure-headers'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { eq } from 'drizzle-orm'
import { randomBytes } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { config, IS_SQLITE } from './config'
import { getDb } from './db'
import { sqliteUsers, pgUsers } from './db/schema'
import { runMigrations } from './db/migrate'
import { hashPassword } from './auth/argon'
import { authRoute } from './routes/auth'
import { oidcRoute } from './routes/oidc'
import { proxyRoute } from './routes/proxy'
import { metricsRoute } from './routes/metrics'
import { eventsRoute } from './routes/events'
import { checkRateLimit, scheduleRateLimitCleaner } from './ratelimit'
import { getClientIp } from './lib/client-ip'

// ─── Rate limiting ────────────────────────────────────────────────────────────
// Simple in-process sliding window rate limiter (no Redis required).
// For multi-instance deployments, swap this for a Redis-backed limiter.

scheduleRateLimitCleaner(Math.max(config.AUTH_RATE_WINDOW_MS, config.API_RATE_WINDOW_MS))

// ─── App setup ────────────────────────────────────────────────────────────────

const app = new Hono()

// Security headers
app.use('*', secureHeaders({
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    // 'unsafe-inline' is deliberate: SvelteKit (adapter-static) emits a
    // per-build inline bootstrap script in every prerendered HTML page, served
    // raw via serveStatic — there is no templating layer to inject a nonce,
    // and dev mode proxies Vite's inline HMR scripts. Hash-based CSP would
    // have to re-hash every dist/*.html at startup and would break dev/HMR;
    // a wrong hash bricks hydration. Revisit if serving moves to SSR.
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    frameAncestors: ["'none'"],
  },
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
  },
}))

// CORS — same-origin only in production; allow the SvelteKit dev server in dev
app.use('*', cors({
  origin: config.DEV_MODE
    ? [`http://localhost:${config.SVELTEKIT_DEV_PORT}`, config.ORIGIN]
    : config.ORIGIN,
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
  maxAge: 86400,
}))

// Request logger. Redact SSE credentials in the query string: the dashboard
// opens EventSource('/web/events?ticket=...') and the default logger prints
// the full path incl. query string. Tickets are single-use and expire in
// seconds, but keep them (and any legacy `?token=` from old clients) out of
// stdout and fronting nginx access logs anyway.
const redactToken = (s: string) => s.replace(/([?&](?:token|ticket)=)[^&\s]+/gi, '$1[REDACTED]')
app.use(
  '*',
  logger((str: string, ...rest: unknown[]) => console.log(redactToken(str), ...rest)),
)

// ─── Auth routes — rate limited ───────────────────────────────────────────────

app.use('/web/auth/*', async (c, next) => {
  // getClientIp only honours X-Forwarded-For when AIVPN_WEB_TRUST_PROXY=true;
  // otherwise the socket peer address is used (spoofed XFF would bypass this limit).
  const key = `auth:${getClientIp(c)}`

  if (!checkRateLimit(key, config.AUTH_RATE_MAX, config.AUTH_RATE_WINDOW_MS)) {
    return c.json({ error: 'Too many requests. Please wait before retrying.' }, 429)
  }

  await next()
})

// ─── API proxy routes — rate limited per user ─────────────────────────────────

app.use('/api/v1/*', async (c, next) => {
  // Hash the full Authorization token so each user gets an independent bucket.
  // Slicing the raw JWT would put every user in the same bucket (identical alg/typ prefix).
  const { createHash } = await import('node:crypto')
  const rawAuth = c.req.header('authorization') ?? getClientIp(c)
  const key = `api:${createHash('sha256').update(rawAuth).digest('hex').slice(0, 16)}`

  if (!checkRateLimit(key, config.API_RATE_MAX, config.API_RATE_WINDOW_MS)) {
    return c.json({ error: 'Too many requests.' }, 429)
  }

  await next()
})

// ─── Metrics + realtime events — rate limited per user ────────────────────────
// These routes matched no limiter before: GET /web/metrics samples uncached CPU
// load per hit and POST /web/events/ticket mints tickets — both are DoS
// amplification vectors for any authenticated user (incl. read-only viewers).
const eventsRateLimit = async (c: Context, next: Next) => {
  const { createHash } = await import('node:crypto')
  const rawAuth = c.req.header('authorization') ?? getClientIp(c)
  const key = `evt:${createHash('sha256').update(rawAuth).digest('hex').slice(0, 16)}`
  if (!checkRateLimit(key, config.API_RATE_MAX, config.API_RATE_WINDOW_MS)) {
    return c.json({ error: 'Too many requests.' }, 429)
  }
  await next()
}
app.use('/web/metrics/*', eventsRateLimit)
app.use('/web/events/*', eventsRateLimit)

// ─── Mount routes ─────────────────────────────────────────────────────────────

app.route('/web/auth', authRoute)
app.route('/web/auth/oidc', oidcRoute)
app.route('/web/metrics', metricsRoute)
app.route('/web/events', eventsRoute)
app.route('/api/v1', proxyRoute)

// ─── Frontend serving ─────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url))

if (config.DEV_MODE) {
  // In dev: proxy everything else to SvelteKit dev server
  app.all('*', async (c) => {
    const url = new URL(c.req.url)
    const target = `http://localhost:${config.SVELTEKIT_DEV_PORT}${url.pathname}${url.search}`

    const headers = new Headers(c.req.raw.headers)
    headers.delete('host')

    try {
      const response = await fetch(target, {
        method: c.req.method,
        headers,
        body: ['GET', 'HEAD'].includes(c.req.method) ? undefined : c.req.raw.body,
      })

      return new Response(response.body, {
        status: response.status,
        headers: response.headers,
      })
    } catch {
      return c.text('SvelteKit dev server not running on port ' + config.SVELTEKIT_DEV_PORT, 502)
    }
  })
} else {
  // In production: serve built SvelteKit static files
  const clientBuildDir = path.resolve(__dirname, '..', config.CLIENT_BUILD_DIR)

  app.use('*', serveStatic({ root: clientBuildDir }))
  // SPA fallback: serve index.html for all unmatched routes
  app.get('*', async (c) => {
    return c.html(await Bun.file(path.join(clientBuildDir, 'index.html')).text())
  })
}

// ─── Bootstrap: ensure at least one admin user exists ────────────────────────

async function ensureFirstUser(): Promise<void> {
  const db = await getDb()
  const d = db as any
  const usersTable = IS_SQLITE ? sqliteUsers : pgUsers

  const [existing] = await d.select({ id: usersTable.id }).from(usersTable).limit(1)
  if (existing) return

  // Honor an operator-supplied initial password (documented in .env.example);
  // otherwise generate a strong random one and print it once.
  const provided = config.AIVPN_WEB_ADMIN_PASSWORD
  const password = provided ?? randomBytes(16).toString('base64url')
  const hash = await hashPassword(password)

  await d.insert(usersTable).values({
    username: 'admin',
    password_hash: hash,
    role: 'admin',
  })

  if (provided) {
    console.log('[setup] Seeded admin user from AIVPN_WEB_ADMIN_PASSWORD (username: admin)')
  } else {
    console.log('╔══════════════════════════════════════════════════╗')
    console.log('║         FIRST-TIME SETUP — SAVE THESE NOW        ║')
    console.log('╠══════════════════════════════════════════════════╣')
    console.log(`║  Username : admin                                 ║`)
    console.log(`║  Password : ${password.padEnd(36)} ║`)
    console.log('╚══════════════════════════════════════════════════╝')
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────

async function main() {
  await runMigrations()
  await ensureFirstUser()

  serve(
    {
      fetch: app.fetch,
      port: config.PORT,
    },
    (info) => {
      console.log(`[server] aivpn-web listening on http://localhost:${info.port}`)
      console.log(`[server] Origin: ${config.ORIGIN}`)
      console.log(`[server] DB: ${IS_SQLITE ? config.DATABASE_URL : 'PostgreSQL'}`)
      console.log(`[server] Unix socket: ${config.UNIX_SOCK}`)
    },
  )
}

main().catch((err) => {
  console.error('[FATAL]', err)
  process.exit(1)
})
