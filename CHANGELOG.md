# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-08

Phase 1: ingestion and storage.

### Added
- Parsers: Apache/Nginx access logs (combined, common, vhost_combined, or a custom
  Apache `LogFormat` / Nginx `log_format` string), ECS JSON Lines, Linux
  `auth.log`/`secure` (RFC 3164 with year inference, ISO, RFC 5424; sshd, sudo, su,
  PAM, account changes, cron, logind), and generic JSON Lines with YAML field
  mappings. Format auto-detection.
- Event storage per Sigma log source (`ev_*` tables) with on-demand columns, a field
  catalog, overflow JSON for unsafe or excess fields, and pivot indexes.
- Deduplication by content hash that still keeps genuinely repeated lines.
- Safe archive handling: streamed `.gz`/`.zip` (no extraction), size and ratio
  limits, zip-slip names refused, binary files refused.
- Web upload (drag & drop, several files, progress, background jobs), ingest
  history and per-batch reports with malformed-line samples.
- Watch folder `/data/inbox`: follows appends, waits for complete lines, handles
  rotation and truncation, resumes after restarts, works when mounted read-only.
- Retention by ingestion time with a scheduled purge and incremental vacuum;
  `threatlens db stats|purge|compact`.
- Optional raw line storage (`TL_STORE_RAW`), zstd with per-batch dictionaries.
- Overview: events over time chart (vendored uPlot), top source IPs and users,
  ingest health.
- Settings (admin): retention and default timezone, storage per source and per
  table, user management (one-time passwords, forced change, enable/disable,
  reset), maintenance buttons. Account page to change your own password.
- CLI: `threatlens ingest`, `threatlens synth` (seeded synthetic logs).
- Upload size limit enforced while streaming (413), 1 MB limit on other requests.
- Docs: ADR-0004 (ingestion pipeline), `log-formats.md`, `schema.md`, example
  field mappings.
- `TL_HOST_PORT` (Compose) to choose the host port when 8080 is taken, plus a
  `.env.example`; README section "Changing the port".
- Regression guards that ThreatLens is only published on `127.0.0.1`: a pytest
  check of the Compose files and every documented `docker run` command, and a CI
  step that verifies the rendered Compose config and the running container.

### Changed
- A generated first-run admin password must be changed at first sign-in.

## [0.1.0] - 2026-11-08

Phase 0: plan and scaffold.

### Added
- Project skeleton (`src/threatlens/...`), Apache-2.0 license, contributor docs.
- ADR-0001 (application stack), ADR-0002 (SQLite storage, per-logsource tables,
  with benchmark), ADR-0003 (security baseline).
- Configuration through `TL_*` environment variables, validated at startup.
- Structured JSON logging.
- SQLite storage (WAL, incremental auto-vacuum) with numbered migrations.
- Authentication: argon2id passwords, server-side sessions, CSRF protection,
  login rate limiting, `admin` / `analyst` roles, audit log.
- First-run admin from `TL_ADMIN_PASSWORD`, or a random password printed once.
- `threatlens` CLI: `serve`, `healthcheck`, `user reset-password`, `--version`.
- Dark-theme web UI with an empty overview dashboard; vendored HTMX; Swagger UI
  API docs behind login.
- Security headers on every response (strict CSP, nosniff, frame denial,
  no-referrer, no-store).
- Hardened multi-stage Docker image (non-root, read-only rootfs compatible,
  healthcheck) and `docker-compose.yml`.
- CI (lint, types, tests, Docker build, smoke test, Trivy), release workflow
  (multi-arch to GHCR), Dependabot, issue/PR templates, pre-commit hooks.

[Unreleased]: https://github.com/Tamimsharif83/threatlens/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Tamimsharif83/threatlens/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Tamimsharif83/threatlens/releases/tag/v0.1.0
