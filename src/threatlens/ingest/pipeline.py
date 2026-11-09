"""The ingest pipeline: lines -> parser -> events -> event tables, in batches.

Streaming: lines are read, parsed and written in chunks of `CHUNK_SIZE`; memory
use does not depend on file size. Every chunk is one transaction, which also
updates the batch counters (and, for the watch folder, the file offset), so a
crash never leaves events without bookkeeping or vice versa.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import islice
from typing import Any
from zoneinfo import ZoneInfo

from threatlens.ingest.readers import MALFORMED, READ_ERRORS
from threatlens.normalize.schema import Event
from threatlens.parsers import (
    FieldMapping,
    ParseContext,
    ParseError,
    Parser,
    UnknownFormatError,
    detect_parser,
    make_parser,
)
from threatlens.storage.db import transaction
from threatlens.storage.events import (
    EventStore,
    PreparedEvent,
    RawCodec,
    content_hash,
    load_raw_codec,
    store_raw_dict,
)
from threatlens.timeutil import now_ms

log = logging.getLogger(__name__)

CHUNK_SIZE = 5000
SNIFF_LINES = 50
MAX_SAMPLES = 20
SAMPLE_CHARS = 500
TOO_LONG = "\x00TOO_LONG\x00"


@dataclass(slots=True)
class IngestOptions:
    parser_type: str = "auto"  # see parsers.PARSER_TYPES
    source_name: str | None = None
    timezone: str | None = None  # overrides the source/default timezone
    web_format: str | None = None
    mapping: FieldMapping | None = None
    store_raw: bool = False
    origin: str = "cli"
    created_by: str | None = None
    reference_time: datetime | None = None  # for logs without a year (file mtime)


@dataclass(slots=True)
class BatchReport:
    batch_id: int
    source: str
    file_name: str
    parser: str
    status: str = "running"
    lines: int = 0
    inserted: int = 0
    duplicates: int = 0
    malformed: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)
    tables: dict[str, int] = field(default_factory=dict)
    min_ts: int | None = None
    max_ts: int | None = None
    error: str | None = None
    chunks: list[tuple[str, int, int]] = field(default_factory=list)  # (table, min_id, max_id)

    def as_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "source": self.source,
            "file": self.file_name,
            "parser": self.parser,
            "status": self.status,
            "lines": self.lines,
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "malformed": self.malformed,
            "tables": self.tables,
            "error": self.error,
        }


class OccurrenceCounter:
    """Distinguishes genuinely repeated identical lines from re-ingested ones.

    Two identical lines (same second, same request) are two real events, so the
    dedup hash includes how many times the line was already seen. Identical
    lines share a timestamp, so counts are kept only for the current timestamp:
    memory stays bounded no matter how big the file is.
    """

    def __init__(self) -> None:
        self._ts: int | None = None
        self._seen: dict[str, int] = {}

    def next(self, ts: int, raw: str) -> int:
        if ts != self._ts:
            self._ts = ts
            self._seen.clear()
        n = self._seen.get(raw, 0)
        self._seen[raw] = n + 1
        return n


def get_or_create_source(
    conn: sqlite3.Connection,
    name: str,
    parser: str,
    timezone: str | None = None,
    options: dict[str, Any] | None = None,
) -> tuple[int, str | None]:
    """Return (source id, source timezone)."""
    row = conn.execute("SELECT id, timezone FROM sources WHERE name = ?", (name,)).fetchone()
    if row:
        if timezone and timezone != row["timezone"]:
            conn.execute("UPDATE sources SET timezone = ? WHERE id = ?", (timezone, row["id"]))
            return row["id"], timezone
        return row["id"], row["timezone"]
    cur = conn.execute(
        "INSERT INTO sources (name, parser, timezone, options, created_at) VALUES (?, ?, ?, ?, ?)",
        (name, parser, timezone, json.dumps(options or {}), now_ms()),
    )
    assert cur.lastrowid is not None  # noqa: S101
    return cur.lastrowid, timezone


def set_source_parser(conn: sqlite3.Connection, source_id: int, parser: str) -> None:
    """Record the detected format on the source (it starts as "auto")."""
    with transaction(conn):
        conn.execute("UPDATE sources SET parser = ? WHERE id = ?", (parser, source_id))


def _resolve_tz(name: str | None, default: str) -> ZoneInfo:
    return ZoneInfo(name or default)


def _sample(record: int, line: str, reason: str) -> dict[str, Any]:
    return {"record": record, "reason": reason[:200], "line": line[:SAMPLE_CHARS]}


class BatchWriter:
    """Owns one ingest batch row and writes event chunks into it."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        source_id: int,
        source_name: str,
        file_name: str,
        parser_name: str,
        opts: IngestOptions,
        batch_id: int | None = None,
    ) -> None:
        self.conn = conn
        self.store = EventStore(conn)
        self.opts = opts
        self.codec: RawCodec | None = None
        self._dict_checked = False
        if batch_id is None:
            with transaction(conn):
                cur = conn.execute(
                    "INSERT INTO ingest_batches (source_id, origin, file_name, parser, status, "
                    "started_at, created_by) VALUES (?, ?, ?, ?, 'running', ?, ?)",
                    (source_id, opts.origin, file_name, parser_name, now_ms(), opts.created_by),
                )
            assert cur.lastrowid is not None  # noqa: S101
            batch_id = cur.lastrowid
        else:
            row = conn.execute(
                "SELECT raw_dict_id FROM ingest_batches WHERE id = ?", (batch_id,)
            ).fetchone()
            if opts.store_raw:
                self.codec = load_raw_codec(conn, row["raw_dict_id"] if row else None)
                self._dict_checked = True
        self.report = BatchReport(batch_id, source_name, file_name, parser_name)

    @property
    def batch_id(self) -> int:
        return self.report.batch_id

    def _ensure_codec(self, events: list[Event]) -> None:
        if not self.opts.store_raw or self._dict_checked:
            return
        self._dict_checked = True
        dict_data = RawCodec.train([e.raw for e in events[:2000] if e.raw])
        if dict_data:
            dict_id = store_raw_dict(self.conn, dict_data)
            self.conn.execute(
                "UPDATE ingest_batches SET raw_dict_id = ? WHERE id = ?", (dict_id, self.batch_id)
            )
        self.codec = RawCodec(dict_data)

    def write_chunk(
        self,
        events: list[PreparedEvent],
        lines: int,
        malformed: list[dict[str, Any]],
        malformed_count: int,
        bytes_read: int = 0,
        on_commit: Callable[[sqlite3.Connection], None] | None = None,
    ) -> None:
        rep = self.report
        with transaction(self.conn):
            self._ensure_codec([pe.event for pe in events])
            result = self.store.insert(events, self.batch_id, self.codec)
            for table, tr in result.tables.items():
                rep.tables[table] = rep.tables.get(table, 0) + tr.inserted
                if tr.min_id is not None and tr.max_id is not None:
                    rep.chunks.append((table, tr.min_id, tr.max_id))
                    self.conn.execute(
                        "INSERT INTO ingest_batch_tables (batch_id, table_name, min_id, max_id, "
                        "events) VALUES (?, ?, ?, ?, ?) ON CONFLICT (batch_id, table_name) DO "
                        "UPDATE SET min_id = min(min_id, excluded.min_id), "
                        "max_id = max(max_id, excluded.max_id), events = events + excluded.events",
                        (self.batch_id, table, tr.min_id, tr.max_id, tr.inserted),
                    )
            rep.lines += lines
            rep.inserted += result.inserted
            rep.duplicates += result.duplicates
            rep.malformed += malformed_count
            room = MAX_SAMPLES - len(rep.samples)
            if room > 0:
                rep.samples.extend(malformed[:room])
            for pe in events:
                ts = pe.event.ts
                rep.min_ts = ts if rep.min_ts is None else min(rep.min_ts, ts)
                rep.max_ts = ts if rep.max_ts is None else max(rep.max_ts, ts)
            self.conn.execute(
                "UPDATE ingest_batches SET lines_total = lines_total + ?, "
                "events_inserted = events_inserted + ?, duplicates = duplicates + ?, "
                "malformed = malformed + ?, bytes_read = bytes_read + ?, "
                "malformed_samples = ?, min_ts = ?, max_ts = ? WHERE id = ?",
                (
                    lines,
                    result.inserted,
                    result.duplicates,
                    malformed_count,
                    bytes_read,
                    json.dumps(rep.samples, ensure_ascii=False),
                    rep.min_ts,
                    rep.max_ts,
                    self.batch_id,
                ),
            )
            if on_commit:
                on_commit(self.conn)

    def fail_on_storage_error(self, exc: sqlite3.Error) -> BatchReport:
        """The database refused a write. The chunks already committed are kept."""
        message = f"storage error: {exc}"
        if "full" in str(exc):
            message += " (free space on the data volume, or purge old data, then retry)"
        log.error("ingest stopped by a storage error", extra={"batch": self.batch_id})
        for attempt in range(2):
            try:
                return self.finish("failed", message)
            except sqlite3.Error:
                if attempt == 0:  # moving the WAL into the database file often frees room
                    with contextlib.suppress(sqlite3.Error):
                        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        # Still no room: the status stays 'running' until the next start marks it
        # interrupted; the job and the log carry the reason meanwhile.
        self.report.status, self.report.error = "failed", message
        return self.report

    def finish(self, status: str = "done", error: str | None = None) -> BatchReport:
        rep = self.report
        rep.status, rep.error = status, error
        with transaction(self.conn):
            self.conn.execute(
                "UPDATE ingest_batches SET status = ?, finished_at = ?, error = ? WHERE id = ?",
                (status, now_ms(), error, self.batch_id),
            )
            if rep.max_ts is not None:
                self.conn.execute(
                    "UPDATE sources SET last_event_at = max(coalesce(last_event_at, 0), ?) "
                    "WHERE id = (SELECT source_id FROM ingest_batches WHERE id = ?)",
                    (rep.max_ts, self.batch_id),
                )
        return rep


def parse_lines(
    lines: Iterable[tuple[int, str]],
    parser: Parser,
    ctx: ParseContext,
    counter: OccurrenceCounter,
) -> Iterator[tuple[int, PreparedEvent | None, dict[str, Any] | None]]:
    """Yield (record, event or None, malformed sample or None) per line. Never raises
    for bad input: any parser failure becomes a malformed-line sample."""
    for record, line in lines:
        if line.startswith(TOO_LONG):
            yield record, None, _sample(record, line[len(TOO_LONG) :], "line too long (> 1 MiB)")
            continue
        if line.startswith(MALFORMED):  # a record the reader could not decode (EVTX)
            yield record, None, _sample(record, "", line[len(MALFORMED) :])
            continue
        try:
            event = parser.parse(line, ctx)
        except ParseError as exc:
            yield record, None, _sample(record, line, str(exc))
            continue
        except Exception as exc:  # a parser bug must not stop the ingest
            log.warning("parser error", extra={"parser": parser.name, "error": repr(exc)})
            yield record, None, _sample(record, line, f"parser error: {type(exc).__name__}")
            continue
        event.record_no = record
        table = event.logsource.table_name
        h = content_hash(table, event.raw or line, counter.next(event.ts, event.raw or line))
        yield record, PreparedEvent(event, h), None


def ingest_stream(
    conn: sqlite3.Connection,
    lines: Iterator[tuple[int, str]],
    file_name: str,
    opts: IngestOptions,
    default_timezone: str,
    *,
    progress: Callable[[BatchReport], None] | None = None,
) -> BatchReport:
    """Ingest one stream of lines as one batch and return its report."""
    sample = list(islice(lines, SNIFF_LINES))
    sample_lines = [ln for _, ln in sample if not ln.startswith((TOO_LONG, MALFORMED))]
    source_name = opts.source_name or file_name
    reference = opts.reference_time or datetime.now(UTC)
    # Source timezone (from an earlier ingest) unless overridden for this run.
    with transaction(conn):
        _, source_tz = get_or_create_source(
            conn,
            source_name,
            opts.parser_type,
            opts.timezone,
            {"web_format": opts.web_format, "mapping": opts.mapping.name if opts.mapping else None},
        )
    ctx = ParseContext(tz=_resolve_tz(source_tz, default_timezone), reference_time=reference)

    if opts.parser_type == "auto":
        try:
            parser = detect_parser(
                sample_lines,
                ctx,
                web_format=opts.web_format,
                mapping=opts.mapping,
            )
        except UnknownFormatError as exc:
            return _failed_batch(conn, source_name, file_name, opts, str(exc), sample)
    else:
        parser = make_parser(opts.parser_type, web_format=opts.web_format, mapping=opts.mapping)

    source_id, _ = get_or_create_source(conn, source_name, parser.name)
    set_source_parser(conn, source_id, parser.name)
    writer = BatchWriter(conn, source_id, source_name, file_name, parser.name, opts)
    try:
        run_chunks(writer, _chain(sample, lines), parser, ctx, progress=progress)
    except READ_ERRORS as exc:  # e.g. a zip bomb detected halfway through
        return writer.finish("failed", str(exc))
    except sqlite3.Error as exc:  # e.g. the data volume is full
        return writer.fail_on_storage_error(exc)
    return writer.finish()


def _chain(
    first: list[tuple[int, str]], rest: Iterator[tuple[int, str]]
) -> Iterator[tuple[int, str]]:
    yield from first
    yield from rest


def run_chunks(
    writer: BatchWriter,
    lines: Iterable[tuple[int, str]],
    parser: Parser,
    ctx: ParseContext,
    *,
    counter: OccurrenceCounter | None = None,
    progress: Callable[[BatchReport], None] | None = None,
) -> None:
    counter = counter or OccurrenceCounter()
    events: list[PreparedEvent] = []
    samples: list[dict[str, Any]] = []
    bad = 0
    n_lines = 0
    for _, prepared, sample in parse_lines(lines, parser, ctx, counter):
        n_lines += 1
        if prepared is not None:
            events.append(prepared)
        else:
            bad += 1
            if sample is not None and len(samples) < MAX_SAMPLES:
                samples.append(sample)
        if n_lines >= CHUNK_SIZE:
            writer.write_chunk(events, n_lines, samples, bad)
            if progress:
                progress(writer.report)
            events, samples, bad, n_lines = [], [], 0, 0
    if n_lines:
        writer.write_chunk(events, n_lines, samples, bad)
        if progress:
            progress(writer.report)


def _failed_batch(
    conn: sqlite3.Connection,
    source_name: str,
    file_name: str,
    opts: IngestOptions,
    error: str,
    sample: list[tuple[int, str]],
) -> BatchReport:
    source_id, _ = get_or_create_source(conn, source_name, opts.parser_type)
    writer = BatchWriter(conn, source_id, source_name, file_name, opts.parser_type, opts)
    samples = [_sample(r, line, "format not recognised") for r, line in sample[:5]]
    writer.write_chunk([], len(sample), samples, 0)
    return writer.finish("failed", error)


# ---------------------------------------------------------------- crash recovery

INTERRUPTED = (
    "interrupted: ThreatLens stopped during this ingest; the events stored before the "
    "stop are kept (and checked by the rules)"
)


def mark_interrupted(conn: sqlite3.Connection) -> int:
    """At startup: batches still 'running' were cut off by a crash or a restart."""
    cur = conn.execute(
        "UPDATE ingest_batches SET status = 'failed', finished_at = ?, "
        "error = coalesce(error, ?) WHERE status = 'running'",
        (now_ms(), INTERRUPTED),
    )
    return cur.rowcount


def mark_detection(conn: sqlite3.Connection, batch_id: int, state: str) -> None:
    conn.execute("UPDATE ingest_batches SET detection = ? WHERE id = ?", (state, batch_id))


def pending_detection(
    conn: sqlite3.Connection, limit: int = -1
) -> list[tuple[int, list[tuple[str, int, int]]]]:
    """Finished or failed batches whose stored events the rules have not seen yet."""
    out: list[tuple[int, list[tuple[str, int, int]]]] = []
    for (batch_id,) in conn.execute(
        "SELECT id FROM ingest_batches WHERE detection IS NULL AND status != 'running' "
        "ORDER BY id LIMIT ?",
        (limit,),
    ).fetchall():
        chunks = [
            (r[0], r[1], r[2])
            for r in conn.execute(
                "SELECT table_name, min_id, max_id FROM ingest_batch_tables WHERE batch_id = ?",
                (batch_id,),
            )
        ]
        out.append((batch_id, chunks))
    return out
