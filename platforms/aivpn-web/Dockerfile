# Stage 1: builder
FROM oven/bun:1 AS builder

WORKDIR /app

# Copy workspace manifests first for layer caching
COPY package.json ./
COPY server/package.json ./server/
COPY client/package.json ./client/

RUN bun install --frozen-lockfile

# Copy source
COPY server/ ./server/
COPY client/ ./client/

# Build SvelteKit static output (the server serves this as the SPA)
RUN bun run --cwd client build

# NOTE: the server runs from source, not a bundle. `bun build` inlines the
# @node-rs/argon2 native addon into dist/index.js, which then fails to load at
# runtime ("Failed to load native binding"). Running src/index.ts directly lets
# Bun resolve the native addon from node_modules normally, so the image boots.

# Stage 2: runtime
FROM oven/bun:1-alpine AS runtime

WORKDIR /app

# Copy production deps
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/server/node_modules ./server/node_modules

# Copy server source (run directly) + package manifest + built SPA
COPY --from=builder /app/server/src ./server/src
COPY --from=builder /app/server/package.json ./server/package.json
COPY --from=builder /app/client/build ./client/build

# Persistent data directory (SQLite DB)
VOLUME ["/app/data"]

ENV DATABASE_URL=file:./data/aivpn-web.db
ENV PORT=8080
ENV UNIX_SOCK=/run/aivpn/api.sock

EXPOSE 8080

CMD ["bun", "server/src/index.ts"]
