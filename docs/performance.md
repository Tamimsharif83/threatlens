# Performance

ThreatLens targets an 8 GB laptop: one container, under 300 MB of memory when
idle, and an interactive UI over a few million events. This page shows what it
achieves and how to measure it yourself.

## The 1M-line run

`scripts/bench/perf_1m.py` generates 1,000,000 Apache access-log lines (seeded
synthetic traffic, ~0.5 % attacks), ingests them **with detection on** (the
shipped example rules run on every chunk, as in production), then times the
real web pages through the FastAPI app: login, CSRF, templates and all.

```bash
uv run python scripts/bench/perf_1m.py                # 1,000,000 lines, ~1 minute
uv run python scripts/bench/perf_1m.py --lines 200000 # quicker
uv run python scripts/bench/perf_1m.py --gzip         # ingest a .log.gz instead
```

Results for v1.0.0 on a laptop (Intel Core i5-1235U, 8 GB RAM, Python 3.13,
SQLite 3.53; data directory on tmpfs):

| Measure (1,000,000 web log lines) | Result |
|---|---|
| Events stored | 1,000,000 (0 rejected, 0 duplicates) |
| Ingest + detection, wall time | 40.0 s |
| Throughput | **25,000 lines/s** |
| Alerts raised | 6 (3 scanning IPs × 2 rules, grouped per source IP) |
| Peak memory (RSS) of the process | **125 MiB** |
| Database size | 280 MiB (294 bytes/event; input 163 MiB) |
| Retro-hunt: 5 detection rules over all events | 1.5 s |
| Overview `/` | 87 ms |
| Alert queue `/alerts` | 4 ms |
| Alert detail (largest alert, 6,061 events, paged) | 8 ms |
| Field search, `source.ip = …` (indexed pivot field) | 11 ms |
| Field search, `url.original contains …` (full scan, stops at 200 hits) | 17 ms |
| Hunt console, `GROUP BY` over all events | 1,229 ms |
| ATT&CK coverage `/coverage` | 11 ms |
| Rule metrics `/metrics` | 3 ms |
| Events-over-time API (overview chart) | 181 ms |
| Peak memory (RSS), whole run | 144 MiB |

Ingest memory does not grow with file size: files are streamed and written in
chunks of a few thousand events, and detection runs per chunk.

### In the container

The hardened container (`--read-only --cap-drop ALL`, `--memory 1g`, named volume
on an SSD), measured with `docker stats`:

| Measure | Result |
|---|---|
| Idle, empty database | 55 MiB |
| 1,000,000 web lines via `threatlens ingest` inside the container | 75 s including generating the file; container peak **126 MiB** |
| The same 1,000,000 lines again | all recognised as duplicates, 38 s |
| Idle with 1.23 million events (web, Linux, ECS, 7 Windows channels) | **61 MiB** |
| Overview `/` at 1.23 million events in 7 tables | 170 ms |
| Alert queue, coverage, metrics, pivot search | 4–11 ms |
| Events-over-time chart | 248 ms |
| Hunt `ORDER BY` a text column over 1.2 million rows | 1.8 s, container peak 62 MiB (SQLite sorts in temp files) |
| 278 real attack `.evtx` files (EVTX-ATTACK-SAMPLES, 50 MB) via the CLI | 7 s, 78 MiB peak (in-process) |

## Windows event logs

A 31 MB Security log (62,031 records) ingests in about 4 s with an 84 MB peak.
EVTX is decoded by the Rust `evtx` library, one record at a time.

## What scales with what

| Operation | Cost grows with | Notes |
|---|---|---|
| Ingest | lines × enabled rules | Each rule is one SQL query per chunk, on new rows only (`tl_id` range). |
| Correlation | events matching the base rules in the window | Runs on new chunks, with look-back. |
| Overview, pivots | distinct values in the window | Pivot fields are indexed as `(field, tl_ts)`, so "top source IPs in the last 7 days" reads only the index ([ADR-0011](adr/0011-v1-hardening.md)). |
| Field search with `eq` on a pivot field | matches | Index lookup. |
| Field search with `contains`, regex | rows scanned until the limit is reached | No full-text index; narrow it with a time range. |
| Hunt console | whatever the SQL asks for | 10 s limit, 1,000 rows, values capped at 16 MiB. |
| Retention purge | rows deleted | Runs shortly after start-up and every few hours; `threatlens db compact` returns the space. |

## Tips for large deployments

- Keep `/data` on an SSD. SQLite in WAL mode is fast, but each chunk is a
  transaction that must reach the disk.
- Keep the retention short (`TL_RETENTION_DAYS`, default 30) and run
  `threatlens db compact` after large purges.
- `TL_STORE_RAW=false` is the default; turning it on stores every original line
  (zstd-compressed) as well, so only do it if you need them.
- Disable rules you do not need: ingest time grows with the number of enabled
  rules.
- Prefer `eq` searches on pivot fields (`source.ip`, `destination.ip`,
  `user.name`, `host.name`), and add a time range to `contains` searches.
