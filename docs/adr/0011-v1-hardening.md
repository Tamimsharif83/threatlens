# 0011. v1.0 hardening: whole-app checks, hunt console limits, log evasion, scale

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

Before v1.0 the security controls of ADR-0003 were tested route by route, as
each phase added them. A route added later without `SessionDep`, without the
CSRF check or without `AdminDep` would not have been noticed. A review of the
whole application against a STRIDE threat model ([threat-model.md](../threat-model.md)),
hostile-input sweeps of every page, a 1M-line run and the
EVTX-ATTACK-SAMPLES / OTRF corpora found these problems:

1. **Hunt console memory**: SQLite allows 1 GB strings, so
   `SELECT printf('%.*c', 1000000000, 'x')` could take the 1 GB container down.
2. **Hunt console regex**: `REGEXP '(a+)+$'` against a near-miss value backtracks
   for hours; SQLite's progress handler cannot interrupt a Python function.
3. **Hunt console blocking**: the route was `async` and ran the query inline, so
   a 10-second query froze the server for every user.
4. **Audit log via the console**: analysts could `SELECT * FROM audit_log`
   although the audit page is admin-only.
5. **Password change**: `/account` checked the current password with no
   throttle (a stolen session could guess it), hashed on the event loop, and
   answered 500 for a password over 1,024 characters.
6. **Log evasion**: any NUL byte in a file's first 8 KiB rejected the whole file
   as binary. Apache logs a TLS handshake sent to a plain-HTTP port as raw
   bytes, NULs included — one such request hid an entire access log.
7. **Server errors on hostile URLs**: `/alerts/99999999999999999999` (beyond
   SQLite's 64-bit integers) and `/search?start=99999999999999999999` answered 500.
8. **Overview at scale**: "top source IPs" grouped every event of the last
   7 days through the table: 2.4 s at 1M events, linear beyond.
9. **Alert pages**: every event with every field, up to 200 — thousands of lines
   for Windows alerts.
10. **Events never checked by the rules**: detection ran only after a batch
    finished successfully. A batch that failed half-way (a bomb ratio reached
    after millions of good lines, a full disk) kept its stored events without
    detection — an attacker who can make a rotated log compress past 200:1 could
    hide in it. A crash or `docker kill` mid-ingest left the batch `running`
    forever: never detected, and never purged by retention (which skips running
    batches).
11. **Full disk**: SQLite rolls back by itself on `SQLITE_FULL`; our
    `transaction()` then issued a second `ROLLBACK`, whose "no transaction is
    active" error replaced the real one, and the batch stayed `running`.

## Decisions

### Test the whole route table, not individual routes
`tests/test_hardening.py` walks FastAPI's route table (including included
routers) and resolves each route's dependency tree. It asserts the exact set of
public routes (`/login`, `/healthz`) and admin routes, then calls **every** route
anonymously (must redirect to login or 401), every write route without and with
a forged CSRF token (must be 403), and every admin route as an analyst (must be
403). Every GET page is requested with hostile values in every known query
parameter and must neither fail with 5xx nor render markup. A new route is
covered the day it is added.

### Hunt console: cap values, refuse catastrophic regex, run in a thread, role-aware
- `SQLITE_LIMIT_LENGTH` = 16 MiB on the hunt connection (stored values are at
  most 1 MiB per line).
- `REGEXP` in the console refuses patterns where a variable repeat contains
  another variable repeat (`(a+)+`, `(\w+\s?)*`, `(a|b+)*`), found by walking
  Python's own regex parse tree. Atomic groups and possessive quantifiers
  (`(?>a+)+`, `(a++)+`, Python 3.11+) pass: they do not backtrack. This is a
  heuristic for the common exponential shapes, not a proof; the time limit still
  bounds everything else. `rules lint` gives the same check as a **warning** for
  `|re` values in rules, which are trusted code (ADR-0005).
- The query runs in the thread pool (`run_in_threadpool`).
- `audit_log` is denied to analysts (admins keep it); the page says which
  tables each role can read.

### Password changes use the login throttle
Same per-IP / per-user window as the login form, failures audit-logged, argon2
work in the thread pool, 1,024-character maximum checked before hashing.

### NUL bytes: density, not presence
A sample is binary when it holds more than `max(16, 1 %)` NUL bytes; UTF-16
text gets a hint to convert it. Magic-number checks for executables, documents
and EVTX are unchanged.

### Out-of-range numbers are a 400
One exception handler maps `OverflowError` (an id beyond SQLite's integers) to
400 "number out of range"; the search form ignores timestamps past year 9999.

### Pivot indexes are `(field, tl_ts)`
Pivot fields (`source.ip`, `destination.ip`, `user.name`, `host.name`) are
indexed together with the event time, so "top values in a time window" and
pivots with a time range are answered from the index alone (2.4 s → 0.1 s at
1M events). With several event tables, top values are grouped per table first
and the per-table counts summed, so each table still reads only its index. Existing databases are upgraded once at startup by
`upgrade_pivot_indexes` (idempotent; ~2.5 s per million events).

### Every stored event is checked by the rules, even after a failure or a crash
Migration 0007 adds `ingest_batches.detection` (`NULL` = not yet, `done`,
`skipped` for `ingest --no-detect`). Detection runs on the stored chunks of
failed batches too, and marks the batch `done` afterwards. At startup, batches
still `running` are marked `failed` ("interrupted: … the events stored before
the stop are kept"), and a "detection catch-up" job runs the rules on every
batch whose detection is still `NULL`. Alert keys make re-running idempotent.
Existing batches are marked `done` by the migration.

### Storage errors fail the batch, with the reason
`transaction()` rolls back only while a transaction is open. A `sqlite3.Error`
during an ingest ends the batch `failed` with "storage error: database or disk
is full (free space on the data volume, or purge old data, then retry)"; if even
that status cannot be written, the worker retries it on its next job (and the
next start would mark it interrupted). Uploads that cannot be saved (`ENOSPC`)
are refused with a message. Failed batches show their reason in the batch list.

### Alert events are paged and folded
25 events per page; each card shows the rule's fields (highlighted) and a short
list of key fields; the other fields and the raw line are in a `<details>`
element (no JavaScript, so the CSP stays strict).

### Flat Windows JSON
Recorded-attack datasets (OTRF Security-Datasets) and many forwarders write one
flat JSON object per Windows event (`Channel`, `EventID` at the top level). The
Windows parser accepts that shape too, so these files land in the same
`ev_windows_*` tables and Windows rules run on them unchanged.
`scripts/fetch-datasets.sh` downloads pinned commits of EVTX-ATTACK-SAMPLES
(GPL-3.0) and a Windows subset of OTRF Security-Datasets (MIT) into the
git-ignored `datasets/` folder; nothing third-party is redistributed.

## Consequences

- A forgotten `SessionDep`/`AdminDep`/CSRF check on a future route fails CI.
- Analysts lose console access to `audit_log`; admins keep it.
- A hunt pattern like `(\w+\s)+` must be rewritten (`(?>\w+\s)+` or without
  the nesting). Some rare safe-but-nested patterns are refused; the error says
  how to rewrite them.
- The first start of v1.0 on a large existing database rebuilds four indexes
  per event table.
- Performance numbers are in [performance.md](../performance.md) and can be
  reproduced with `scripts/bench/perf_1m.py`.
