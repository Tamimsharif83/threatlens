# 0003. Security baseline for the web application and container

- **Status:** Accepted
- **Date:** 2026-11-08

## Context

ThreatLens displays attacker-controlled data: every log line may contain HTML,
JavaScript, terminal escape sequences or spreadsheet formulas written by an
attacker. A SIEM that runs a stored XSS payload from a log is a known real-world
vulnerability class. ThreatLens also holds sensitive data (logs, investigation
notes) and must be safe to run on a laptop with defaults.

## Decision

### Browser side
- **Autoescaping is always on** (`jinja2.Environment(autoescape=True)`); no `|safe`,
  `Markup()` or `innerHTML` anywhere. A test fails the build if any of these appear.
- **Strict CSP**: `default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
  No inline scripts or styles. The only exception is `style-src 'unsafe-inline'` on
  `/docs` (Swagger UI). That page never displays log data.
- HTMX is hardened through its config meta tag: `allowEval=false`, `allowScriptTags=false`,
  `selfRequestsOnly=true`, `historyCacheSize=0` (pages with log data are never
  copied into localStorage).
- Other headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, a restrictive `Permissions-Policy`,
  and `Cache-Control: no-store` on every non-static response. No `Server` header.
- All front-end assets are vendored, with SHA-256 hashes recorded and tested.

### Authentication & sessions
- Passwords are hashed with **argon2id** (RFC 9106 low-memory profile), 12–1024 characters.
  Unknown usernames are verified against a dummy hash, so response timing does
  not reveal which accounts exist.
- **Server-side sessions**: the cookie carries a random 256-bit token; the database
  stores only its SHA-256. Cookies are `HttpOnly; SameSite=Strict; Path=/`, and
  `Secure` with the `__Host-` prefix when served over HTTPS (`TL_COOKIE_SECURE=auto|always|never`).
  Logout, password change and account disable end sessions immediately.
- **CSRF**: a per-session synchronizer token (form field or `X-CSRF-Token` header)
  on every state-changing request; a double-submit token on the login form; plus
  `Origin` / `Sec-Fetch-Site` checks as defence in depth. Because our
  `Referrer-Policy` makes browsers send `Origin: null` on form posts, `null` is
  accepted only when `Sec-Fetch-Site: same-origin`.
- **Login rate limiting**: failures are counted per IP and per username in a
  sliding window (default 5 per 15 minutes). A successful login clears only the
  username's counter, so logging into your own account cannot reset an IP's budget.
- First run: admin from `TL_ADMIN_PASSWORD` (≥ 12 chars) or a random password
  printed once to the container log. Analysts are created from the UI only.
  Lost password: `threatlens user reset-password <name>` inside the container.
- Roles: `admin`, `analyst`. Every login, logout and failure is audit-logged.

### Container
- Non-root UID 10001. Works with `--read-only`, `--cap-drop ALL`,
  `no-new-privileges`. Only `/data` is writable (mode 0700; database 0600).
- Multi-stage build on a digest-pinned `python:3.13-slim` base; no compilers,
  pip or caches in the final image. `HEALTHCHECK` built in.
- Documentation binds the port to `127.0.0.1` only. Exposing ThreatLens requires
  a deliberate change, ideally behind a TLS reverse proxy (`TL_FORWARDED_ALLOW_IPS`).
- CI pins every GitHub Action to a full commit SHA (tags can be moved, as the
  2026 compromise of `aquasecurity/trivy-action` tags showed), and scans the
  image with Trivy (fails on HIGH/CRITICAL).

### Later phases (planned here, implemented with the feature)
- Uploads: size cap, extension + magic-byte checks, zip-bomb and zip-slip limits,
  random server-side names outside any served path.
- Hunt console: separate `mode=ro` connection plus an authorizer that denies
  writes, `ATTACH` and `PRAGMA` changes, with a row limit and timeout.
- CSV export neutralizes `= + - @` prefixes; CLI output strips terminal escapes
  (the helper already exists and is tested).
- XSS regression tests are extended to every page that renders log fields.

## Consequences

- No inline `<script>` or `onclick=` attributes: every behaviour lives in static JS
  files. This is slightly more work, but it makes XSS-by-log far harder.
- In-memory login throttling resets on restart. Acceptable for a single-process app.
- Sessions in SQLite cost one indexed lookup per request (negligible).
