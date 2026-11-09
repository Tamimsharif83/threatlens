# Release verification: v1.0.0

Before tagging v1.0.0, every feature was exercised against the release image
running exactly as documented (hardened container: `--read-only`, `--cap-drop ALL`,
`no-new-privileges`, `--memory 1g`, `--pids-limit 256`, port on `127.0.0.1`),
through its HTTP interface, its CLI and a real Chromium browser: the expected
use (**best case**) and hostile or broken input, failures and limits
(**worst case**). The automated test suite (469 tests, including
`tests/test_hardening.py`) covers the same ground in CI; this page records the
end-to-end run.

**Result: 140 of 140 checks pass** (72 best case, 68 worst case).

## Problems this run found (fixed before the release)

| Problem | Fix |
|---|---|
| A `docker kill` during an ingest left the batch "running" forever: its events were never checked by the rules and never purged | Interrupted batches are closed at the next start and a catch-up job runs the rules on them (migration 0007) |
| Events stored by a batch that failed half-way were never checked by the rules | Detection runs on the stored part of failed batches |
| A full disk left the batch "running", and a second `ROLLBACK` replaced "database or disk is full" with a misleading error | The batch fails with the real reason, shown in the batch list; unsaved uploads are refused with a message |
| An access log with one TLS handshake logged as raw bytes (NULs) was refused as binary — one request could hide a whole log | NUL bytes count as binary only when dense |
| The overview took 0.6 s with seven event tables (1.2M events) | Top values grouped per table on the `(field, tl_ts)` index: 0.17 s |
| The alert filter's rule list made the page wider than a phone | Form controls no longer exceed their column |

Hunt-console limits, the audit-log rule for analysts, the password-change throttle
and the 500 errors on huge numbers were found earlier in the same phase by the
route-walking tests; see [ADR-0011](adr/0011-v1-hardening.md).

## Environment

- Image built from this commit (`docker build`), 185 MB; Docker on Linux (Kali, x86-64), Intel Core i5-1235U, 8 GB RAM.
- Data: synthetic web/Linux/ECS logs (`threatlens synth`), the EVTX samples in `tests/fixtures/evtx/`, EVTX-ATTACK-SAMPLES and OTRF Security-Datasets (via `scripts/fetch-datasets.sh`), and crafted hostile files (bombs, zip-slip, UTF-16, NUL bytes, XSS payloads, 3 MB lines, 70 MB uploads).
- A volume created by v0.8.0 was opened by v1.0.0 for the upgrade check.

## Login and sessions

| Case | Kind | Result | Detail |
|---|---|---|---|
| generated admin password printed once at first run | best | ✅ | banner lines with 'password:': 1 |
| login with generated password | best | ✅ | 303 |
| generated password forces a change before anything else | best | ✅ | /account |
| too-short new password refused | worst | ✅ | 400 |
| mismatched confirmation refused | worst | ✅ | 400 |
| password changed | best | ✅ | 303 |
| overview reachable after change | best | ✅ |  |
| anonymous page -> login redirect | worst | ✅ | /login?next=/alerts |
| anonymous API -> 401 JSON | worst | ✅ | {"detail":"not authenticated"} |
| anonymous upload refused | worst | ✅ | 303 |
| logged-in POST without CSRF token -> 403 | worst | ✅ | 403 |
| cross-site POST with valid token -> 403 | worst | ✅ | 403 |
| 6 wrong passwords then the right one (same IP) | worst | ✅ | codes=[401, 401, 401, 401, 401, 429], right password -> 429, Retry-After=900 |
| brute force is audit-logged | best | ✅ | 14 entries |
| throttle is in memory: a restart clears it (documented) | best | ✅ | 303 |

## User management

| Case | Kind | Result | Detail |
|---|---|---|---|
| admin creates analyst, one-time password shown | best | ✅ | 200 |
| duplicate username refused | worst | ✅ | 409 |
| invalid username refused | worst | ✅ | 400 |
| unknown role refused | worst | ✅ | 400 |
| analyst forced password change works | best | ✅ | 303 |
| disabling analyst ends their session at once | worst | ✅ | disable=200 analyst-next=303 |
| re-enabled analyst can log in | best | ✅ | 303 |
| admin cannot disable the last admin (self) | worst | ✅ | 400 |

## Analyst vs admin

| Case | Kind | Result | Detail |
|---|---|---|---|
| analyst GET /settings -> 403 | worst | ✅ | 403 |
| analyst GET /audit -> 403 | worst | ✅ | 403 |
| analyst cannot create users | worst | ✅ | 403 |
| analyst cannot purge data | worst | ✅ | 403 |
| analyst hunt on audit_log refused | worst | ✅ | 400 |
| admin hunt on audit_log allowed | best | ✅ | 200 |
| nobody reads password hashes via hunt | worst | ✅ | 400 |

## Ingestion

| Case | Kind | Result | Detail |
|---|---|---|---|
| web + auth + ECS + .gz + .zip (with nested .gz) in one upload | best | ✅ | access.log:done 0 ev [apache]; auth.log:done 0 ev [linux-auth]; app.jsonl:done 0 ev [ecs-json]; web2.log:done 0 ev [apache]; bundle.zip!m1.log:done 0 ev [apache]; bundle.zip!m2.log:done 0 ev [linux-auth]; bundle.zip!m3.l… |
| events routed to per-source tables | best | ✅ | ['ev_ecs', 'ev_linux_auth', 'ev_webserver'] |
| EVTX (Sysmon/System/Security) + OTRF flat-JSON zip | best | ✅ | sysmon.evtx:done 41 ev [evtx]; system.evtx:done 108 ev [evtx]; security-short.evtx:done 7 ev [evtx]; security-new-user.evtx:done 4 ev [evtx]; otrf_mimikatz.zip!empire_mimikatz_logonpasswords_2020-08-07103224.json:done 60… |
| re-uploading the same file adds nothing (dedup) | best | ✅ | inserted=0 duplicates=20000 |
| 6 concurrent uploads from 6 sessions | worst | ✅ | codes=[200, 200, 200, 200, 200, 200] batches=['done', 'done', 'done', 'done', 'done', 'done', 'done', 'done'] in 2.6s |
| CLI ingest inside the container (50k lines) | best | ✅ | g OK   batch #29 cli.log [apache] source=cli.log: 50000 events, 0 duplicates, 0 malformed of 50000 lines      detection: 1245 matching event(s), 4 new alert(s) |
| empty file | worst | ✅ | HTTP 400:  empty.log: empty file Upload jobs File State Lines Events Duplicates Malformed Batches web2.log.gz 64.8 KB done 5,000 0 5,000 0 #28 xss_access.log 1.2 KB done 5 5 0 0 #27 auth.log 308.3 KB done 3,000 |
| ELF binary named .log | worst | ✅ | HTTP 400:  elf.log: binary file (executable or document), not a log Upload jobs File State Lines Events Duplicates Malformed Batches web2.log.gz 64.8 KB done 5,000 0 5,000 0 #28 xss_access.log 1.2 KB done 5 5 0 |
| .exe upload | worst | ✅ | HTTP 400: tool.exe: file type not accepted (.log, .txt, .json, .evtx, .gz, .zip ...) |
| gzip bomb 300 MB of zeros in 300 KB | worst | ✅ | failed: compression ratio above 200:1 (possible zip bomb) |
| zip-slip member ../../../../etc/evil.log | worst | ✅ | failed: unsafe path in archive: '../../../../etc/evil.log' |
| zip inside a zip | worst | ✅ | failed: nested.zip!inner.zip: nested zip archives are not supported |
| password-protected zip | worst | ✅ | failed: encrypted.zip!access.log: encrypted members not supported |
| zip with 10,050 members | worst | ✅ | failed: many.zip: too many archive members (10050) |
| UTF-16 text | worst | ✅ | HTTP 400:  utf16.log: binary data (NUL bytes), not a text log (UTF-16 text? convert it to UTF-8) Upload jobs File State Lines Events Duplicates Malformed Batches many.zip 920.5 KB failed many.zip: too many arch |
| EVTX data named .log | worst | ✅ | HTTP 400:  evtx_named.log: EVTX data but the name does not end in .evtx Upload jobs File State Lines Events Duplicates Malformed Batches many.zip 920.5 KB failed many.zip: too many archive members (10050) 0 0 0 |
| text named .evtx | worst | ✅ | HTTP 400:  text_named.evtx: not an EVTX file (no ElfFile header) Upload jobs File State Lines Events Duplicates Malformed Batches many.zip 920.5 KB failed many.zip: too many archive members (10050) 0 0 0 0 #36 |
| unrecognisable text | worst | ✅ | failed: could not recognise the log format; choose a type explicitly (best match: none, 0% of sample lines) |
| 3 MB single line among good lines | worst | ✅ | status=done inserted=2 malformed=1 err=None |
| TLS bytes with NULs in an access log (evasion attempt) | worst | ✅ | status=done inserted=3 malformed=0 err=None |
| EVTX cut off mid-chunk | worst | ✅ | status=done inserted=312 malformed=0 err=None |
| 70 MB upload over the 64 MB limit | worst | ✅ | HTTP 413 |
| 60 files in one request | worst | ✅ | HTTP 400  400 · ThreatLens Skip to content 400 Too many files. Maximum number of files is 20. Back to ThreatLens |
| upload file name with ../ path traversal | worst | ✅ | HTTP 200 |
| bad timezone / source name in the form | worst | ✅ | HTTP 400 |

## Watch folder

| Case | Kind | Result | Detail |
|---|---|---|---|
| docker cp into the read-only container | worst | ✅ | works |
| file written into /data/inbox/<source>/ is ingested | best | ✅ | batch #32 web-prod/web2.log done (5,000 duplicates of an earlier upload), source 'web-prod' created |

## Rules

| Case | Kind | Result | Detail |
|---|---|---|---|
| reload with one broken rule file: error shown, others load | worst | ✅ | reload HTTP 200 |
| lint flags the broken file and the nested regex | worst | ✅ | 8 rule(s), 1 error(s), 1 warning(s) |
| rule tests: examples pass, the broken file is reported | best | ✅ | 8 rule(s), 1 failing |
| Windows rule compiled for Sysmon (EventID 1) and Security (4688) | best | ✅ | per-table SQL shown |

## Detection

| Case | Kind | Result | Detail |
|---|---|---|---|
| retro-hunt of a new Windows rule over stored EVTX + OTRF | best | ✅ | 2 alerts; tables: [['ev_windows_security'], ['ev_windows_sysmon']] |
| SSH brute-force correlation fired from auth.log | best | ✅ | 8 correlation alerts, largest 54 events |
| disabled rule does not alert on new data | worst | ✅ | events in SQLi alerts 547 -> 547 |

## Triage

| Case | Kind | Result | Detail |
|---|---|---|---|
| alert queue /alerts | best | ✅ | HTTP 200 |
| alert queue /alerts?status=all&sort=severity | best | ✅ | HTTP 200 |
| alert queue /alerts?status=open&level=high | best | ✅ | HTTP 200 |
| alert queue /alerts?q=203.0.113.66 | best | ✅ | HTTP 200 |
| alert queue /alerts?status=all&sort=events | best | ✅ | HTTP 200 |
| largest alert (430 events) pages 25 at a time, details folded | best | ✅ | Page 1 of 18 |
| Windows alert card: rule field highlighted, rest folded | best | ✅ | Sysmon alert highlights Channel, EventID, Image (54 more fields folded); Security alert highlights NewProcessName (4688 mapping), 42 folded |
| bulk close 2 alerts as false positive | best | ✅ | [['closed', 'false_positive'], ['closed', 'false_positive']] |
| note with HTML/JS is stored and shown inert | worst | ✅ |  |
| assign alert to analyst | best | ✅ |  |
| unknown status value refused | worst | ✅ | 303 |

## Tuning (suppressions)

| Case | Kind | Result | Detail |
|---|---|---|---|
| create suppression (rule + source.ip) | best | ✅ | 303 |
| suppressed IP gets no new alerts; hits counted | best | ✅ | new SQLi alerts for ['192.0.2.13', '203.0.113.77']; hits=[[52]] |
| empty suppression refused | worst | ✅ | 400 |

## Field search

| Case | Kind | Result | Detail |
|---|---|---|---|
| pivot search source.ip = attacker | best | ✅ | HTTP 200 |
| hostile search ['users', 'password_hash', 'eq'] | worst | ✅ | HTTP 200; no password hashes in page: True |
| hostile search ['ev_webserver', 'x" OR 1=1 --', 'eq'] | worst | ✅ | HTTP 200 |
| hostile search ['ev_webserver', 'regex', 'url.original'] | worst | ✅ | HTTP 200 |
| hostile search ['ev_webserver', '99999999999999999999', '-5'] | worst | ✅ | HTTP 200 |

## Hunt console

| Case | Kind | Result | Detail |
|---|---|---|---|
| CSV export neutralises formulas | worst | ✅ | x,y "'=HYPERLINK(""http://evil"")",'+1  |
| write refused | worst | ✅ | HTTP 400 in 0.02s |
| ATTACH refused | worst | ✅ | HTTP 400 in 0.02s |
| 900 MB string not allocated | worst | ✅ | HTTP 200 in 0.02s |
| catastrophic regex refused | worst | ✅ | HTTP 400 in 0.03s |
| 10 s hunt query does not block other users | worst | ✅ | hunt stopped after 10.0s; meanwhile 5 health checks + alert page took 0.05s |
| save a hunt, load it, run it | best | ✅ | HTTP 200 |
| bad ATT&CK tag on a saved hunt refused | worst | ✅ |  |

## Cases and reports

| Case | Kind | Result | Detail |
|---|---|---|---|
| create case from 3 alerts | best | ✅ | [[1, 'Investigation: [Example] Known Vulnerability Scanner User Agent']] |
| case action note | best | ✅ | HTTP 303 |
| case action annotate | best | ✅ | HTTP 303 |
| case action add-ioc | best | ✅ | HTTP 303 |
| case action extract-iocs | best | ✅ | HTTP 303 |
| case action update | best | ✅ | HTTP 303 |
| case action report | best | ✅ | HTTP 303 |
| invalid IOC value refused | worst | ✅ | HTTP 303 |
| IOCs extracted from the alerts' events | best | ✅ | [['ip', 3], ['url', 20], ['user', 5], ['user_agent', 3]] |
| export report.md | best | ✅ | 29755 bytes, text/markdown; charset=utf-8 |
| export report.html | best | ✅ | 68044 bytes, text/html; charset=utf-8 |
| export iocs.csv | best | ✅ | 3330 bytes text/csv, attachment; header type,value,origin,occurrences,... |
| export iocs.json | best | ✅ | 6582 bytes, application/json |
| HTML report: log data inert, own strict CSP | worst | ✅ |  |
| missing case -> 404 | worst | ✅ | 404 |

## Coverage and metrics

| Case | Kind | Result | Detail |
|---|---|---|---|
| page /coverage | best | ✅ | HTTP 200 |
| page /coverage?covered=1 | best | ✅ | HTTP 200 |
| page /metrics | best | ✅ | HTTP 200 |
| page /metrics?sort=precision | best | ✅ | HTTP 200 |
| ATT&CK Navigator layer export | best | ✅ | 9 techniques in layer |

## Settings and maintenance

| Case | Kind | Result | Detail |
|---|---|---|---|
| retention 0 days refused | worst | ✅ | 400 |
| non-numeric retention / bad timezone refused | worst | ✅ |  |
| retention 90 days + Asia/Dhaka saved | best | ✅ |  |
| maintenance purge | best | ✅ | HTTP 200 |
| maintenance compact | best | ✅ | HTTP 200 |

## Audit log

| Case | Kind | Result | Detail |
|---|---|---|---|
| audit log holds every kind of action | best | ✅ | missing: []; 26 kinds |

## Upgrade

| Case | Kind | Result | Detail |
|---|---|---|---|
| v0.8.0 database opened by v1.0.0: same data, same login | best | ✅ | login 303; pages {'/account': 200, '/': 200, '/alerts': 200, '/coverage': 200, '/ingest': 200} |
| restart on the new image with the same volume | best | ✅ | same counts before/after; this volume already had v1 indexes (the v0.8.0 -> v1.0.0 upgrade is the separate 'upgrade' check) |
| database integrity after upgrade | best | ✅ | ok |

## Restart

| Case | Kind | Result | Detail |
|---|---|---|---|
| session survives a restart (server-side sessions) | best | ✅ | {"username":"admin","role":"admin"} |
| Docker HEALTHCHECK reports healthy | best | ✅ | healthy |

## Memory

| Case | Kind | Result | Detail |
|---|---|---|---|
| idle with data loaded (~130k events) | best | ✅ | 55 MiB |
| idle after 1M more events (server process) | best | ✅ | 55 MiB |

## Scale

| Case | Kind | Result | Detail |
|---|---|---|---|
| 1,000,000 web lines via the CLI inside the container | best | ✅ | first run: 75 s including generating the file, container peak 126 MiB, 1,000,000 events stored, detection: 22,878 matching events, 4 new alerts; second run with the same seed: all 1,000,000 recognised as duplicates in 38… |
| / with 1,176,309 events | best | ✅ | 589 ms |
| /alerts with 1,176,309 events | best | ✅ | 7 ms |
| /coverage with 1,176,309 events | best | ✅ | 10 ms |
| /metrics with 1,176,309 events | best | ✅ | 7 ms |
| /api/v1/stats/events-over-time with 1,176,309 events | best | ✅ | 225 ms |
| /search?run=1&table=ev_webserver&f1=sour with 1,176,309 events | best | ✅ | 9 ms |
| hunt: ORDER BY a text column over all web events | worst | ✅ | HTTP 200 in 1.8s, container peak 62 MiB |

## Crash

| Case | Kind | Result | Detail |
|---|---|---|---|
| docker kill -9 in the middle of a 600k-line ingest | worst | ✅ | killed at 55000 events; after restart: integrity=ok, batch=['failed', 'interrupted: ThreatLens stopped during this ingest; the events stored before the stop are kept (and checked by the rules)', 'done'], rule matches fou… |
| UI after the crash: batch shown as interrupted, app works | worst | ✅ |  |

## Full disk

| Case | Kind | Result | Detail |
|---|---|---|---|
| data volume fills up during uploads (40 MB tmpfs) | worst | ✅ | uploads=[200, 200, 200, 200, 200, 200, 200, 200]; batches=[('done', 20000, ''), ('done', 20000, ''), ('done', 20000, ''), ('done', 20000, ''), ('done', 20000, ''), ('failed', 10000, 'storage error: database or disk is fu… |

## Real browser (Chromium)

| Case | Kind | Result | Detail |
|---|---|---|---|
| 20 pages in Chromium: no JS errors | best | ✅ | clean |
| no CSP violations on any page | worst | ✅ | none |
| log data with <script>/onerror never runs (no dialogs) | worst | ✅ | XSS alert page visited: True |
| event card folds open without JavaScript | best | ✅ |  |
| alert queue at phone width (390 px) | best | ✅ | horizontal overflow 0px |
