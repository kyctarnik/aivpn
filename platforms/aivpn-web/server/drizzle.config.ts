import { defineConfig } from 'drizzle-kit'
import { config } from './src/config'

const isSqlite = !config.DATABASE_URL.startsWith('postgres')

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './src/db/migrations',
  dialect: isSqlite ? 'sqlite' : 'postgresql',
  dbCredentials: isSqlite
    ? { url: config.DATABASE_URL.replace('file:', '') }
    : { url: config.DATABASE_URL },
})
