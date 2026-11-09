# 0002. Storage engine and event table layout

- **Status:** Accepted
- **Date:** 2026-11-08

## Context

Events must be stored compactly, survive restarts, and be queryable by Sigma
detection **and correlation** rules without a hand-written Sigma compiler. The
whole platform must fit in one container on a laptop, offline.

pySigma-backend-sqlite (2.1.1, pySigma 2.0.2) compiles Sigma rules — including
v2 correlation rules (`event_count`, `value_count`, `temporal`,
`temporal_ordered`, and value aggregations) — to SQLite SQL. We verified this
before deciding: correlation queries run and return the group-by values, the
window, and the **row ids of the matching events**, which lets alerts reference
events instead of copying them. The backend also supports:

- a per-rule target table, set from a processing pipeline (`SetStateTransformation("table", ...)`),
- numeric timestamps (`timestamp_format="unix_ms"`),
- a configurable event-id column, and
- correlations whose base rules live in different tables.

## Options considered

### Engine

1. **SQLite (WAL mode)** — embedded, zero-ops, single file, mature; a compiler
   to its SQL dialect already exists. Single writer is fine for one ingest pipeline.
2. **DuckDB** — faster analytics on columns, but no Sigma backend with
   correlation support; we would have to write one.
3. **OpenSearch / Elasticsearch** — powerful, but multi-GB RAM and a second
   service. Breaks the laptop budget.

### Event layout inside SQLite

Measured with [`scripts/bench/storage_layout_spike.py`](../../scripts/bench/storage_layout_spike.py)
(200 000 synthetic web events, SQLite 3.46, same rules, same pySigma field-mapping
pipeline for both layouts; both returned identical matches for every rule):

| | **A**: one `events` table (typed columns for known fields + JSON `extra`) and a VIEW per log source | **B**: one wide table per log source, one column per field (Zircolite-style) |
|---|---|---|
| Database size | 47.4 MB | **34.3 MB** |
| Ingest time | 10.1 s | **6.8 s** |
| Rule: `contains` on query string | 181 ms | **106 ms** |
| Rule: `contains` on user agent | 217 ms | **130 ms** |
| Rule on fields that are not "known" | 582 ms (`json_extract`) | **302 ms** |
| `event_count` correlation | 1614 ms | 1683 ms |

## Decision

**SQLite in WAL mode, with layout B**: one flattened table per Sigma log source
(e.g. `ev_webserver`, `ev_linux_auth`, later `ev_windows_*`), one column per field.

- Field values are stored once; Sigma (`cs-uri-stem`), ECS (`url.path`) and other
  aliases are resolved at **compile time** by pySigma processing pipelines, so no
  storage is spent on duplicate names.
- Text columns are declared `COLLATE NOCASE`, matching Sigma's case-insensitive
  semantics without `lower()` calls that defeat indexes.
- Every table shares the same provenance columns: `id`, `ts` (UTC unix ms),
  `ingest_batch_id`, `source_id`, `file_name`, `record_no`, `content_hash` (UNIQUE
  for dedup), optional `raw` (zstd-compressed, only with `TL_STORE_RAW=true`).
- New fields become new columns (`ALTER TABLE ... ADD COLUMN` is a metadata-only
  change in SQLite). A **field catalog** table records each column per log source,
  so the UI and hunt console know what exists.
- To stop arbitrary JSON keys from creating thousands of columns, each table is
  capped (default 1,000 promoted columns; raised from 400 in Phase 7 for Windows logs). Fields beyond the cap go into a JSON
  `overflow` column; they stay searchable, and a rule that needs one gets a
  generated column or view expression.
- Indexes: `ts`, plus only the columns that pivots and correlations actually use
  (source IP, user, host). Each index is added deliberately, with a measurement.
- `PRAGMA auto_vacuum = INCREMENTAL` from creation, so the retention purge can
  give space back with `PRAGMA incremental_vacuum` instead of a full `VACUUM`.
- Application state (users, sessions, audit, alerts, cases) lives in the same
  database file. One file is one backup.

## Consequences

- Rules run against a narrow, typed table: smallest size and fastest scans we measured.
- Cross-source correlation (e.g. web + auth) relies on the backend's multi-table
  correlation support; Phase 4 will test it explicitly.
- "Search everything" across log sources needs a `UNION ALL` over the tables of
  interest, generated from the field catalog.
- Schema changes at ingest time (new columns) must be serialized with writes.
  The single-writer ingest pipeline does this naturally.
- The correlation output is one row **per sliding window**; the alert layer must
  merge overlapping windows into one alert with a counter (Phase 2/4).
- SQLite's single writer limits ingest to one pipeline at a time. That is
  acceptable for the target scale (one analyst or small team, GBs not TBs).
- If a future need outgrows SQLite (e.g. 100+ GB), this ADR is superseded, not patched.
