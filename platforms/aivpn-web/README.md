# aivpn-web

Web management panel for aivpn. Backend: Hono 4.x on Bun. Frontend: SvelteKit 2.x (static build served by the backend).

## Prerequisites

- [Bun](https://bun.sh) 1.x

## Local Development

```bash
# Install all workspace dependencies
bun install

# Start backend + frontend in watch mode (hot-reload)
bun run dev
```

The backend listens on `http://localhost:8080` by default; the SvelteKit dev server runs on `http://localhost:5173` and proxies API calls to the backend.

## Production Build

```bash
bun install
bun run build   # builds client → dist/public/, server → dist/server.js
bun start       # runs dist/server.js (serves API + static UI)
```

## Docker

```bash
# Build image
docker build -t aivpn-web .

# Run (minimal)
docker run -p 8080:8080 \
  -v ./data:/app/data \
  -v /run/aivpn:/run/aivpn \
  -e JWT_SECRET=replace-with-a-long-random-secret \
  aivpn-web
```

To deploy alongside `aivpn-server` use the provided `docker-compose.yml` as an override:

```bash
docker compose -f docker-compose.yml -f platforms/aivpn-web/docker-compose.yml up -d
```

## Environment Variables

| Variable                    | Default                        | Required | Description                                              |
|-----------------------------|--------------------------------|----------|----------------------------------------------------------|
| `DATABASE_URL`              | `file:./data/aivpn-web.db`    | No       | SQLite file path or Postgres URL                         |
| `JWT_SECRET`                | —                              | **Yes**  | Secret used to sign JWT session tokens                   |
| `ORIGIN`                    | —                              | Prod     | Public URL of the panel (e.g. `https://vpn.example.com`) |
| `PORT`                      | `8080`                         | No       | HTTP listen port                                         |
| `UNIX_SOCK`                 | `/run/aivpn/api.sock`          | No       | Path to the aivpn-server management Unix socket          |
| `AIVPN_WEB_ADMIN_PASSWORD`  | —                              | No       | Preset admin password for first-run bootstrap            |
| `AIVPN_WEB_TRUST_PROXY`     | `false`                        | No       | Trust `X-Forwarded-For`/`X-Real-IP` for client IP (rate limits, audit log) |

Copy `.env.example` to `.env` and fill in the required values before running locally.

> **`AIVPN_WEB_TRUST_PROXY` security note:** set it to `true` only when the panel
> sits behind a trusted reverse proxy (e.g. nginx) that **overwrites** the
> `X-Forwarded-For` header with the real client address. When the panel is
> directly reachable, keep the default `false`: forwarded headers are
> attacker-controlled, and trusting them lets clients spoof their IP to bypass
> per-IP rate limiting and forge audit-log entries.

## First-Run Bootstrap

If no admin account exists in the database, the server creates one automatically on startup. The generated password is printed to stdout once:

```
[aivpn-web] First run — admin account created. Password: <random>
```

Set `AIVPN_WEB_ADMIN_PASSWORD` to choose your own password instead of a generated one.
