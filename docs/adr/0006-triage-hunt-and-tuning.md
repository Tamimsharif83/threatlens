# 0006. Triage, the read-only hunt console, and tuning

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

Phase 3 gives analysts the workflow after an alert fires: triage, pivoting,
free-form hunting and tuning. Two parts carry real risk. The hunt console runs
analyst-written SQL against the database that also holds password hashes, and
tuning can silently hide true attacks if it isn't visible and accountable.

## Decisions

### Triage state on the alert, history in the audit log
Alerts carry `status` (new → in_progress → closed), `resolution` (required to
close: true positive, false positive, benign true positive), and `assignee`.
Reopening clears the resolution. Every change and note is written to the audit
log with `target = alert:<id>`, which doubles as the alert's history. There is
no separate history table to keep consistent.

### Hunt console sandbox
Analyst SQL runs on a **separate connection** opened with `mode=ro`, plus an
SQLite **authorizer** that allows only `SELECT`, reads, functions and recursive
CTEs. That denies:

- every write and every schema change (also refused by the read-only file mode);
- `ATTACH` (no reading or creating other files) and every `PRAGMA`;
- reading the `users` and `sessions` tables, however they are reached (join,
  subquery, CTE), because the authorizer sees each column read.

A progress handler aborts queries after `TL_HUNT_TIMEOUT_SECONDS` (default 10),
results are capped at `TL_HUNT_ROW_LIMIT` rows (default 1000), and Python's
driver refuses multiple statements. Every run is audit-logged with its SQL.

### Field search builds SQL from the catalog only
The form-based search accepts field names only if the table has that column
(checked case-insensitively, then quoted); operators come from a fixed list
and all values are bound parameters. Pivot links are plain search URLs, so a
pivot ("events from this IP ±1 h") is just a bookmarkable search.

### Two tuning mechanisms, both visible
1. **Sigma filters** (Sigma v2 meta-rules with a `filter:` section) live with the
   rules as code. pySigma's `SigmaFilter.apply_on_rule` adds them to the matching
   rules' conditions at compile time. A broken filter is reported and skipped;
   it never breaks a rule. Rule tests run with filters applied.
2. **Suppressions** (UI allowlist) are `field = value` matches, per rule or
   global, with a **required reason**, the author, an optional expiry, and a hit
   counter. Suppressed matches never become alerts; the rule's `suppressed`
   counter and each entry's `hits` / `last_hit_at` show what tuning is hiding.
   Creating, disabling and deleting entries is audited.

### CSV export neutralizes formulas
Cells starting with `= + - @`, tab or CR get a leading `'`, so attacker-controlled
log values cannot execute as spreadsheet formulas.

## Consequences

- Analysts can explore everything except credentials, without being able to
  damage data, even with a typo like `DELETE`.
- A pathological query stops after the time limit instead of hanging the app.
- Tuning is reviewable: stale suppressions show `last_hit_at`, over-broad ones
  show large hit counts, and expiry makes temporary exceptions temporary.
