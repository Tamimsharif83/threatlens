# 0004. Ingestion pipeline: dedup, retention, watch folder, archives

- **Status:** Accepted
- **Date:** 2026-11-08

## Context

Phase 1 turns files into events. The spec requires streaming ingestion,
deduplication by content hash, a watch folder that survives restarts and log
rotation, safe archive handling, optional compressed raw lines, and a
retention policy. Several of these have non-obvious trade-offs.

## Decisions

### 1. Streaming in chunks, one transaction per chunk
Lines are read one at a time (capped at 1 MiB per line), parsed, and written
in chunks of 5,000 events. Each chunk is one transaction that also updates the
batch counters, so bookkeeping and events never disagree. Memory use does not
depend on file size.

### 2. Dedup key = hash(table, line, occurrence)
A plain hash of the line would merge genuinely repeated events — two identical
requests in the same second are two events. The key is a 64-bit BLAKE2b of the
event table, the raw line, and **how many times that exact line was already seen
with the same timestamp**. Re-ingesting a file reproduces the same keys (all
duplicates); repeated lines within a file stay distinct. Counts are kept only for
the current timestamp, so memory stays bounded. The watch folder keeps one counter
per file across polls, so identical lines split over two polls are not lost.

*Cost:* 64-bit keys could in theory collide (~3×10⁻⁶ at 10 million events per
table), silently dropping one event. Acceptable at ThreatLens' scale; a stronger
key would roughly double the index size.

### 3. Retention counts from ingestion time, not event time
Analysts often import old logs (last quarter's incident, public datasets from
2019). Event-time retention would delete those at the next purge, within hours of
the upload. Batches expire as a whole once `finished_at` is older than the
retention period. Rows are found through the per-batch id ranges recorded in
`ingest_batch_tables` (a rowid range scan, so no extra index), deleted in
chunks of 20,000, then `incremental_vacuum` returns the space. Watch-folder
batches roll over daily, so a tailed file ages out day by day.

### 4. Watch folder
- Polls `/data/inbox` every `TL_WATCH_INTERVAL_SECONDS` (default 5 s); the folder
  may be mounted read-only and is never modified.
- Offsets are stored per file and only ever at a line boundary; a half-written
  last line waits for its newline.
- Rotation is detected by a new inode/device, a size smaller than the offset
  (truncation), or a changed hash of the first 256 bytes (inode reuse). The file
  is then read from the start; already-ingested lines dedup away.
- The offset is committed after the events of each read. A crash in between
  re-reads that region, which the dedup key absorbs, so nothing is lost or doubled.
- `.gz`/`.zip` files are ingested once, after their size and mtime are stable
  for one poll (so a file still being copied in is not read half-way).
- Symlinks, hidden files and temp names (`.part`, `.tmp`, `~`) are ignored.

### 5. Archives are streamed, never extracted
Members are streamed straight into the parser, so zip-slip cannot write
anywhere. Names with `..`, absolute paths or drive letters are still refused and
reported. Limits:
- total decompressed size `TL_MAX_DECOMPRESSED_MB` (default 10 GB), checked on
  declared sizes up front and on actual bytes while reading;
- compression ratio 200:1 once past 10 MB (bomb detection);
- at most 10,000 zip members, one level of nesting (`.gz` inside `.zip`),
  no nested zips, no encrypted members;
- binary files (executables, PDFs, text with many NUL bytes) are refused; Windows
  EVTX is the one binary format read (Phase 7, see ADR-0010). A few NUL bytes are
  tolerated, because web servers log garbage requests verbatim (ADR-0011).

### 6. Raw lines: zstd with a per-batch dictionary (optional)
With `TL_STORE_RAW=true`, each line is stored zstd-compressed. Short log lines
compress poorly one at a time, so a 16 KB dictionary is trained on up to 2,000
lines of each batch (when at least 500 are available) and stored once in
`raw_dicts`. In tests this cuts raw storage to well under half of the plain text.

### 7. Background work
Uploads go to `/data/uploads` under random names and are processed by a
single worker thread. The watch folder and a maintenance thread (retention
purge every 6 hours, expired sessions) run alongside. CLI ingestion is another
process; SQLite's locking and the busy timeout serialize writers, and the
schema is re-read inside each write transaction, so concurrent column
additions are safe.

## Consequences

- Re-uploading the same file is harmless and visibly reported as duplicates.
- Old logs stay available for the full retention period after import.
- A file appended between two polls appears within about 5 seconds.
- Python parsing speed (~10k lines/s per core on a laptop) is the throughput
  limit; Phase 8 measures it on 1 million lines and optimises if needed.
