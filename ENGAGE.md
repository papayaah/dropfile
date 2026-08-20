# Engage (feedback / bug reports / suggestions / FAQ / newsletter / admin)

dropfile embeds [`@reactkits.dev/react-engage`](https://www.npmjs.com/package/@reactkits.dev/react-engage).
We **use the package**, we don't fork it — new features you build in react-engage
flow into dropfile by rebuilding (widget) or `npm update` + redeploy (sidecar).

## Architecture

Three processes:

```
Browser ──▶ Go server (:8080, systemd, native)
              ├─ serves index.html + embedded widget  (assets/engage.js|css)
              ├─ serves /admin (Basic Auth → cookie)  (assets/engage-admin.js|css)
              └─ reverse-proxies /api/engage ─▶ Next.js sidecar (:3001, container)
                                                   └─▶ Postgres (container + volume)
```

- **Widget** (`widget/`) — esbuild bundles react-engage's `EngageWidget` +
  `EngageAdminPanel` into static JS/CSS under `assets/`, which `main.go` embeds
  via `//go:embed`. Built **on the dev machine** (even for deploy), so it uses a
  local `file:` link to react-engage → your unpublished edits show up instantly.
- **Sidecar** (`engage/`) — a minimal Next.js app hosting react-engage's
  `/api/engage` route against dropfile's own Postgres. Built **on the server**
  (Docker), so it depends on react-engage from **npm**.
- **Go** (`main.go`) — reverse-proxies `/api/engage*` to the sidecar and serves
  the widget/admin assets. Never runs any JS.

## Local development

```bash
# 1. Backend (Postgres + sidecar) — needs Docker Desktop running:
docker compose up -d --build          # creates engage_* tables automatically

# 2. Widget bundle (rebuild after ANY react-engage edit):
cd widget && npm install && npm run build      # or: npm run watch

# 3. Go server:
go run main.go                        # http://localhost:8080
```

The widget launcher appears bottom-right (a bottom action-sheet on mobile).
FAQ works with no backend; submitting needs the sidecar (step 1).

To iterate on react-engage: edit `../tradingdiary/packages/react-engage`, then
`cd widget && npm run build` (frontend changes) — no publish needed. For
**server-side** react-engage changes, `npm publish` it, then in `engage/`
`npm update @reactkits.dev/react-engage`.

## Admin

Visit `/admin` (HTTP Basic Auth). On success the Go server sets an httpOnly
`engage_admin` cookie; the sidecar validates it to authorize admin actions.
Set these env vars (must match on both sides):

- Go server (`.env`): `ADMIN_USER`, `ADMIN_PASS`, `ENGAGE_ADMIN_SECRET`
- Sidecar (compose reads from shell/.env): `ENGAGE_ADMIN_SECRET`

If `ENGAGE_ADMIN_SECRET` is unset, admin endpoints stay locked (403) and `/admin`
returns 503 — so the endpoints are never accidentally public.

## Email (optional)

Set `ENGAGE_API_KEY` (Brevo) + `ENGAGE_ADMIN_EMAIL` / `ENGAGE_FROM_EMAIL` on the
sidecar to email the admin on each submission and send newsletter/welcome mail.
Without them, submissions still persist to Postgres — just no email.

## Deploy

`./deploy.sh` builds the widget, compiles the Go binary (with the widget
embedded), rsyncs the binary + `engage/` + `docker-compose.yml`, runs
`docker compose up -d --build` (Postgres + sidecar), and restarts the `dropfile`
service. Requires **Docker + Docker Compose on the server**.
