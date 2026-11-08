# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Tamimsharif83/threatlens/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Tamimsharif83/threatlens/releases/tag/v0.1.0
