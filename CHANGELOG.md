# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-11-09

Phase 6: ATT&CK coverage and rule metrics.

### Added
- Bundled MITRE ATT&CK Enterprise v20.0 technique and tactic list, generated from
  MITRE's STIX by `scripts/gen_attack_techniques.py` (source hash recorded); no
  runtime download.
- ATT&CK coverage matrix: enabled, compiling rules per technique, with levels
  (rules / tested / tested and fired), sub-technique rules counted toward the
  parent, "covered only" filter, and warnings for tags not in the bundled release.
- ATT&CK Navigator layer export (layer format 4.5).
- Rule metrics: events, alerts, suppressed hits, open alerts, TP / FP / benign
  verdicts, precision = TP / (TP + FP), noisiest rules, sortable.
- `rules lint` warns on technique tags that are revoked, deprecated or mistyped.
- Docs: ADR-0009, `docs/attack-coverage.md`, MITRE attribution.

### Changed
- Case findings and reports show technique names from the bundled catalogue.

## [0.6.0] - 2026-11-09

Phase 5: cases and reports.

### Added
- Cases: create from the alert queue (bulk) or an alert page, or empty; add to an
  existing case; title, description, severity, status (open, investigating,
  contained, closed), owner, notes; everything audited.
- Case timeline in event time merging alerts, their events and analyst annotations.
- ATT&CK findings: case alerts grouped by technique with tactics.
- IOCs: extracted from the case's events (IPs, domains, URLs, user agents, users,
  file names and hashes) with counts and first/last seen, plus manual IOCs with
  notes; CSV (formula-safe) and JSON export.
- Incident report: executive summary, scope, timeline, findings mapped to ATT&CK,
  IOCs, impact, root cause, recommendations, appendix; analyst-written sections are
  edited on the case page; exported as Markdown (log values as escaped code spans)
  and self-contained, print-ready HTML (no scripts, own restrictive CSP).
- Docs: ADR-0008.

## [0.5.0] - 2026-11-09

Phase 4: correlation.

### Added
- Sigma v2 correlation rules (`event_count`, `value_count`, `value_sum`, `value_avg`,
  `temporal`, `temporal_ordered`) compiled with the rules they reference, routed per
  rule to its own event table; aliases and Sigma webserver names supported; works
  across log sources (e.g. web + auth).
- Incremental correlation after every batch over the new events' time range widened
  by the timespan (bursts split across uploads are caught); retro-hunts for
  correlations.
- Correlation alerts: one per group, every window's events referenced once, metric
  (type, value, window) shown, child alerts linked; parents shown on child alerts.
- `generate` semantics: base rules used only by `generate: false` correlations are
  marked "correlation only" and do not alert alone; recomputed on enable/disable.
- Correlation rule tests (tp must fire, tn must not, each in its own scratch database).
- Example: "[Example] SSH Brute Force From One Address" (in the failed-SSH example
  file) with near-miss negative fixtures; synthetic auth logs now contain bursts.
- Docs: ADR-0007, complete `correlation-rules.md`.

## [0.4.0] - 2026-11-09

Phase 3: triage.

### Added
- Alert queue: open/status/level/rule/assignee/entity filters, sort by severity,
  last/first seen or events; bulk status and assignment; keyboard shortcuts
  (j/k/x/o, /, ?).
- Alert detail: why it fired (rule description and YAML, tested fields highlighted
  in each matched event), matched events (purged ones marked), entity pivots (±1 h
  search, related alerts, suppress), notes, and a change history from the audit log.
- Statuses new / in progress / closed; closing requires a verdict (true positive,
  false positive, benign true positive); assignees.
- Search: field-filter search with operators and UTC time range; event pages with
  ±1 h pivots per field and the alerts on that event.
- Hunt console: read-only SQL (read-only connection + authorizer: no writes, ATTACH,
  PRAGMA, or users/sessions), time and row limits, saved hunts with description and
  ATT&CK tag, formula-safe CSV export; every run audited.
- Tuning: Sigma v2 filters loaded with the rules and applied at compile time (also in
  rule tests); suppressions with required reason, author, optional expiry, hit
  counters and per-rule suppressed counts.
- Audit log page (admin) with filters.
- `TL_HUNT_ROW_LIMIT`, `TL_HUNT_TIMEOUT_SECONDS`.
- Docs: ADR-0006, `triage-workflow.md`.

### Fixed
- Example rule fixtures (`tests/rules/**/*.log`) were excluded by the `*.log` ignore
  rule and missing from git; a test now guards against ignored fixtures.

## [0.3.0] - 2026-11-08

Phase 2: detection.

### Added
- Sigma rules compiled with pySigma + pySigma-backend-sqlite, routed to event tables
  by log source (webserver, Linux auth, ECS with category condition, mapped JSON
  sources); Sigma webserver field names mapped to ECS.
- Detection on every ingested batch (uploads, watch folder, CLI) by row-id range,
  and retro-hunts over all stored data (UI button and `threatlens rules hunt`).
- Alerts grouped per rule and primary entity within the throttle window, with
  references to every matched event; an event is never counted twice per rule.
- Rules page: enable/disable, reload, validation errors with file and reason,
  validator warnings, test status, hits/alerts/last fired; rule page with YAML,
  compiled SQL per table and recent alerts.
- Alerts page (first version) and overview widgets: open alerts by severity, top rules.
- Detection-as-code: `threatlens rules lint` (Sigma validity, unique UUID ids,
  required metadata, ATT&CK tags) and `threatlens rules test` (tp/tn fixtures as raw
  log lines or JSON events); both run in CI; tests also run on every reload.
- `threatlens rules import-sigmahq` for a local SigmaHQ clone (DRL notice kept).
- Five `[Example]` rules with fixtures: SQL injection in query, scanner user agent,
  user added to a privileged group, failed SSH login, script upload via the app.
- Docs: ADR-0005, `writing-rules.md`, `correlation-rules.md`.

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

[Unreleased]: https://github.com/Tamimsharif83/threatlens/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Tamimsharif83/threatlens/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Tamimsharif83/threatlens/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Tamimsharif83/threatlens/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Tamimsharif83/threatlens/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Tamimsharif83/threatlens/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Tamimsharif83/threatlens/releases/tag/v0.1.0
