import { SignJWT, jwtVerify, type JWTPayload } from 'jose'
import { createHash, randomBytes } from 'node:crypto'
import { config } from '../config'

const SECRET = new TextEncoder().encode(config.JWT_SECRET)

const ACCESS_TOKEN_TTL = 15 * 60 // 15 minutes in seconds
const REFRESH_TOKEN_TTL_DAYS = 7

export interface TokenPayload extends JWTPayload {
  sub: string // userId as string
  role: 'admin' | 'viewer'
  session_version: number
  session_id: string // refresh token session row ID
}

export async function signAccessToken(payload: Omit<TokenPayload, 'iat' | 'exp'>): Promise<string> {
  return new SignJWT(payload as Record<string, unknown>)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL}s`)
    .sign(SECRET)
}

export async function verifyAccessToken(token: string): Promise<TokenPayload> {
  const { payload } = await jwtVerify<TokenPayload>(token, SECRET, {
    algorithms: ['HS256'],
  })
  return payload
}

export interface RefreshTokenPair {
  raw: string // sent to client
  hash: string // stored in DB (SHA-256 hex)
  expiresAt: Date
}

export function generateRefreshToken(): RefreshTokenPair {
  const raw = randomBytes(32).toString('base64url')
  const hash = createHash('sha256').update(raw).digest('hex')
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000)
  return { raw, hash, expiresAt }
}

export function hashRefreshToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex')
}

// __Host- prefix on HTTPS deployments: the browser then enforces Secure,
// Path=/ and no Domain attribute, so the cookie cannot be planted by a
// subdomain or over plain http. Kept unprefixed on http ORIGINs (dev), where
// browsers would reject a __Host- cookie outright. After an https upgrade the
// old unprefixed cookie is simply ignored (one re-login).
export const REFRESH_COOKIE_NAME = config.ORIGIN.startsWith('https')
  ? '__Host-aivpn_rt'
  : 'aivpn_rt'

// Build a Set-Cookie header value for the refresh token
export function buildRefreshCookieHeader(raw: string, expiresAt: Date): string {
  const maxAge = Math.floor((expiresAt.getTime() - Date.now()) / 1000)
  const secure = config.ORIGIN.startsWith('https') ? '; Secure' : ''
  return `${REFRESH_COOKIE_NAME}=${raw}; HttpOnly; SameSite=Strict${secure}; Path=/; Max-Age=${maxAge}`
}

export function buildClearRefreshCookieHeader(): string {
  const secure = config.ORIGIN.startsWith('https') ? '; Secure' : ''
  return `${REFRESH_COOKIE_NAME}=; HttpOnly; SameSite=Strict${secure}; Path=/; Max-Age=0`
}
