import { IS_SQLITE } from './config'
import type { DbClient } from './db'
import { sqliteWebAudit, pgWebAudit } from './db/schema'

export type AuditResult = 'ok' | 'fail' | 'denied'

export async function writeAudit(
  db: DbClient,
  userId: number | null,
  action: string,
  target: string | null,
  result: AuditResult,
  ip: string | null,
): Promise<void> {
  try {
    if (IS_SQLITE) {
      const d = db as import('drizzle-orm/bun-sqlite').BunSQLiteDatabase<any>
      await d.insert(sqliteWebAudit).values({
        user_id: userId ?? undefined,
        action,
        target: target ?? undefined,
        result,
        ip: ip ?? undefined,
      })
    } else {
      const d = db as import('drizzle-orm/postgres-js').PostgresJsDatabase<any>
      await d.insert(pgWebAudit).values({
        user_id: userId ?? undefined,
        action,
        target: target ?? undefined,
        result,
        ip: ip ?? undefined,
      })
    }
  } catch (err) {
    // Audit must never crash the request
    console.error('[audit] write failed:', err)
  }
}
