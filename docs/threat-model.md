# Threat model

This document lists what ThreatLens protects, who might attack it, and how it
defends against each threat (STRIDE). It also covers the risks that are left
and what operators should do about them. The design decisions behind each
control are in [ADR-0003](adr/0003-security-baseline.md); the tests that
enforce them are named in each row.

Version: 1.0.0. Review it again whenever an ADR adds a route, an input format
or a new place that data leaves the system.

## What ThreatLens is, for this model

A single container: a FastAPI web app, a background ingest worker, a watch
folder poller and a SQLite database under `/data`. Analysts reach it through a
browser on `127.0.0.1` (or through an operator's TLS reverse proxy). Log files
come in by browser upload, by the watch folder, or by `threatlens ingest` inside
the container. Nothing is fetched from the internet at runtime.

```
             trust boundary 1                 trust boundary 2
  browser ──────────────► web app ◄──────── log files (upload, /data/inbox, CLI)
  (analyst, admin)        │  │                 ↑ attacker-controlled content
                          │  └─► ingest worker ─► parsers ─► SQLite (/data)
                          │                                      ▲
  rules dir (/data/rules) ─► Sigma compiler ─► SQL ──────────────┘
             trust boundary 3: rule authors are trusted, but rules run on hostile data
```

## Assets

| Asset | Why it matters |
|---|---|
| Event data and alerts | Confidential: logs contain IPs, user names, URLs, command lines. Integrity: triage decisions rest on them. |
| Credentials and sessions | Password hashes (argon2id) and session token hashes in `users` / `sessions`. |
| Audit log | Who logged in, ran which hunt, changed which alert. Must not be readable or editable by analysts. |
| Cases and reports | Investigation notes; exported as Markdown/HTML/CSV/STIX and opened in other tools. |
| The analyst's browser | It renders attacker-written text all day. |
| The host | ThreatLens must not be a way into the machine it runs on. |

## Actors

| Actor | Capability | Trust |
|---|---|---|
| **Log author** (external attacker) | Writes arbitrary bytes into the logs that get ingested: request paths, user agents, user names, EVTX fields, whole crafted files. | None. **The main adversary.** |
| Network neighbour | Can reach the port if the operator exposes it. | None |
| Malicious web page | Runs in the analyst's browser while they are logged in (CSRF, clickjacking). | None |
| Analyst | Logged in, role `analyst`: triage, hunt, rules reload, cases, suppressions. | Partial: cannot manage users or settings, cannot read the audit log. |
| Admin | Everything an analyst can, plus users, settings, maintenance, audit log. | Full (inside the app) |
| Rule author | Whoever writes files in the rules directory. | Trusted (rules are code) |
| Host operator | Runs the container, has `docker exec`. | Full; out of scope |

## STRIDE

### Spoofing

| Threat | Controls | Tests |
|---|---|---|
| Password guessing on `/login` | argon2id; per-IP and per-user sliding-window throttle (5 / 15 min); same message and timing for unknown users | `test_auth_flow`, `test_passwords_and_throttle` |
| Guessing the current password with a stolen session (`/account`) | The same throttle as the login form; every failure is audit-logged | `test_hardening::test_password_change_is_throttled` |
| Session theft | 256-bit random token, only its SHA-256 is stored; `HttpOnly; SameSite=Strict`; `__Host-` + `Secure` over HTTPS; 12 h lifetime; password change ends other sessions | `test_auth_flow`, `test_hardening::test_logout_everywhere_on_password_change` |
| Default credentials | None exist: the first admin password comes from `TL_ADMIN_PASSWORD` or is generated and printed once; must be changed at first login | `test_cli_and_bootstrap` |
| Login CSRF / session fixation | Double-submit token on the login form; a fresh session token at every login | `test_auth_flow` |

### Tampering

| Threat | Controls | Tests |
|---|---|---|
| CSRF on any state-changing route | Per-session synchronizer token on **every** non-GET route, `Origin`/`Sec-Fetch-Site` checks | `test_hardening::test_every_write_requires_csrf` (walks every route) |
| SQL injection through search, filters, pivots | All values are bound parameters; identifiers are checked against the catalogue and quoted | `test_triage::test_search_builder`, `test_hardening::test_hostile_query_strings_never_crash` |
| Writes through the hunt console | Separate `mode=ro` connection, an authorizer allowing only SELECT/READ/FUNCTION/RECURSIVE, one statement, no ATTACH/PRAGMA | `test_triage::test_hunt_console_denies_writes_and_secrets` |
| Path traversal in uploads and archives | Server-side random file names; zip-slip and absolute member paths refused; only basenames kept | `test_ingest::test_zip_slip_and_absolute_paths_refused`, `test_hardening::test_upload_filename_cannot_escape` |
| Event forgery inside logs (fake "admin logged in" lines) | Not preventable by a SIEM: the source decides. Every event keeps its batch, source and file name so analysts can judge provenance | — |
| Deleting evidence | Analysts cannot delete events; purge/compact are admin-only and audit-logged | `test_hardening::test_analyst_refused_on_every_admin_route` |
| Hiding events from detection: a batch that fails half-way (e.g. a rotated log flooded with identical lines until it compresses past the 200:1 bomb ratio), or a crash mid-ingest | Detection runs on the stored part of failed batches; each batch records whether detection ran; at startup interrupted batches are closed and a catch-up job runs the rules on anything not yet checked | `test_hardening::test_failed_upload_still_detects_its_stored_events`, `test_interrupted_batch_is_closed_and_its_events_detected` |
| Hiding a whole log with one crafted request (NUL bytes make the file look binary) | A file is binary only when NUL bytes are dense (> 1 % of the sample); a few logged TLS bytes are fine | `test_ingest::test_a_few_nul_bytes_do_not_hide_a_log` |

### Repudiation

| Threat | Controls |
|---|---|
| "I didn't close that alert" | Every login, failure, status change, note, assignment, suppression, hunt run, rule toggle, case action and settings change is written to `audit_log` with user and IP. |
| An analyst editing the audit trail | Nothing in the app deletes or edits `audit_log`; analysts can neither see the audit page nor query the table from the hunt console. |

### Information disclosure

| Threat | Controls | Tests |
|---|---|---|
| Unauthenticated access | Every route except `/login` and `/healthz` requires a session, checked by walking all routes | `test_hardening::test_route_inventory`, `test_every_route_requires_login` |
| Reading password or session hashes via the hunt console | `users` and `sessions` are denied to everyone; `audit_log` to analysts | `test_hardening::test_hunt_audit_log_is_admin_only` |
| Pages cached on shared machines | `Cache-Control: no-store` on every non-static response | `test_security_headers` |
| Leaking through referrers | `Referrer-Policy: no-referrer` | `test_security_headers` |
| Raw lines kept longer than needed | Raw storage is opt-in (`TL_STORE_RAW`); retention purge (30 days default); uploads deleted after ingest | `test_watch_and_maintenance` |
| Tracking pixels in exported reports | Markdown reports put log values in code spans; the HTML report is autoescaped with its own CSP | `test_cases` |

### Denial of service

| Threat | Controls | Tests |
|---|---|---|
| Huge uploads | Request body cap (`TL_MAX_UPLOAD_MB`), per-file cap, 1 MiB per line (longer lines are cut and counted) | `test_web_phase1`, `test_ingest` |
| Zip/gzip bombs | Decompressed-size cap and a 200:1 ratio check while streaming; zip member count ≤ 10,000; nested zips refused | `test_ingest::test_gzip_bomb_ratio_and_size_limits` |
| Damaged or crafted EVTX | The Rust parser is memory-safe; bad chunks become counted malformed lines; 10,000 consecutive errors stop the file | `test_windows` |
| Deeply nested or very wide JSON | Recursion errors become malformed lines, never a crash; nesting is flattened to 12 levels and at most 1,000 fields per event are kept | `test_hardening::test_deep_or_wide_json_is_malformed_not_fatal` |
| Hunt queries that never end | Progress-handler time limit (10 s), row limit, query runs in a worker thread so other users are not blocked | `test_triage::test_hunt_console_reads_limits_and_timeout` |
| Hunt queries that allocate gigabytes (`printf('%.*c', 1e9, 'x')`) | `SQLITE_LIMIT_LENGTH` of 16 MiB on the hunt connection | `test_hardening::test_hunt_cannot_allocate_huge_values` |
| Catastrophic regex (`(a+)+$`) | The hunt console refuses nested quantifiers; `rules lint` warns about them in rules | `test_hardening::test_hunt_refuses_catastrophic_regex`, `test_lint_warns_on_catastrophic_regex` |
| Oversized numbers in URLs (`/alerts/99999999999999999999`) | Answered with 400, not a server error | `test_hardening::test_path_tricks_are_refused` |
| Memory exhaustion of the host | Container `mem_limit: 1g`, `pids_limit: 256`; ingestion streams files in chunks | `docs/performance.md` |
| A full data volume | The batch fails with "database or disk is full", committed chunks are kept, the app keeps serving; uploads that cannot be saved are refused with a message | `test_hardening::test_full_disk_fails_the_batch_with_a_clear_message`; scenario sweep with a 40 MB volume |

### Elevation of privilege

| Threat | Controls | Tests |
|---|---|---|
| **XSS from log content** (the main risk) | Jinja2 autoescaping everywhere; no `|safe` on data; strict CSP `script-src 'self'` with no inline scripts; `object-src 'none'`; `base-uri 'none'` | `test_xss`, XSS cases in every phase's tests, `test_hardening::test_xss_in_event_cards` |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | `test_security_headers` |
| Analyst → admin | Role checked server-side on every admin route; extra form fields (`role=admin`) are ignored | `test_hardening::test_analyst_refused_on_every_admin_route` |
| Terminal escape injection (CLI output) | Control characters stripped before printing | `test_cli_and_bootstrap::test_sanitize_terminal_output` |
| CSV formula injection (spreadsheet) | Cells starting with `= + - @ \t \r` are prefixed with `'` | `test_triage::test_csv_neutralizes_formulas` |
| YAML code execution in rules/mappings | Only `yaml.safe_load` is used | code review (`grep yaml.load`) |
| Container escape aids | Non-root UID 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges`; no shell tools needed at runtime | `test_deployment` |
| Supply chain | Locked dependencies (`uv.lock`), digest-pinned base images, SHA-pinned GitHub Actions, SBOM + provenance on release, Trivy scan, Dependabot, gitleaks pre-commit | CI |

## Residual risks (accepted)

| Risk | Why accepted | What the operator should do |
|---|---|---|
| No TLS in the app | A reverse proxy does it better; the default bind is `127.0.0.1` | Put Caddy/nginx with TLS in front before exposing it; set `TL_COOKIE_SECURE=always`. |
| No MFA, no SSO | Out of scope for a single-team tool | Keep it on a private network or behind an authenticating proxy. |
| Login throttle is in memory | It resets on restart | Restarts are rare; logs show `auth.login.failure` for alerting. |
| Rules are code | A rule author can write a slow rule; `rules lint` warns about catastrophic regex but a rule can still be slow | Review rules like code (pull requests); run `threatlens rules lint` in CI. |
| Analysts see all event data | It is a shared investigation tool; there is no per-source access control | Give accounts only to people allowed to see all ingested logs. |
| Data at rest is not encrypted | SQLite file in a Docker volume | Use disk encryption on the host. |
| Forged log lines | A SIEM trusts its sources | Protect the log sources; check an event's batch and source before acting on it. |
| SigmaHQ import runs third-party rules | Imported rules land as files the operator chose to import | Review `threatlens rules import-sigmahq` output; it never runs on its own. |

## Reporting

See [SECURITY.md](../SECURITY.md) for how to report a vulnerability privately.
