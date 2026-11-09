"""Read-only aggregates for the Overview page and the stats API."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from threatlens.storage.events import TS, EventStore, quote_ident

HOUR_MS = 3_600_000
DAY_MS = 24 * HOUR_MS
DEFAULT_WINDOW_DAYS = 7


@dataclass(frozen=True, slots=True)
class Totals:
    events: int
    sources: int
    last_ingest_at: int | None
    failed_batches_24h: int
    malformed_24h: int


def totals(conn: sqlite3.Connection, now: int) -> Totals:
    store = EventStore(conn)
    events = sum(
        int(conn.execute(f"SELECT count(*) FROM {quote_ident(t)}").fetchone()[0])
        for t in store.event_tables()
    )
    row = conn.execute(
        "SELECT (SELECT count(*) FROM sources), (SELECT max(finished_at) FROM ingest_batches), "
        "(SELECT count(*) FROM ingest_batches WHERE status = 'failed' AND started_at >= ?), "
        "(SELECT coalesce(sum(malformed), 0) FROM ingest_batches WHERE started_at >= ?)",
        (now - DAY_MS, now - DAY_MS),
    ).fetchone()
    return Totals(events, row[0], row[1], row[2], row[3])


def data_window(
    conn: sqlite3.Connection, days: int = DEFAULT_WINDOW_DAYS
) -> tuple[int, int] | None:
    """The last ``days`` of *event time* (logs are often old: anchor on the newest event)."""
    newest = None
    for t in EventStore(conn).event_tables():
        value = conn.execute(f"SELECT max({TS}) FROM {quote_ident(t)}").fetchone()[0]
        if value is not None and (newest is None or value > newest):
            newest = value
    if newest is None:
        return None
    return newest - days * DAY_MS, newest


# Bucket sizes for the chart, smallest first: pick the first that gives <= MAX_BUCKETS.
BUCKET_SIZES_MS = (60_000, 5 * 60_000, 15 * 60_000, HOUR_MS, 6 * HOUR_MS, DAY_MS)
MAX_BUCKETS = 200


def events_over_time(conn: sqlite3.Connection, days: int = DEFAULT_WINDOW_DAYS) -> dict[str, Any]:
    """Event counts per bucket and per log-source table, for the overview chart.

    The range fits the data: from the oldest event inside the last ``days`` of
    event time to the newest one, so a 3-hour log file fills the chart instead of
    being a spike at the edge of a 7-day axis.
    """
    window = data_window(conn, days)
    if window is None:
        return {"buckets": [], "series": {}, "bucket_ms": HOUR_MS}
    start, end = window
    tables = EventStore(conn).event_tables()
    oldest = min(
        (
            v
            for t in tables
            if (
                v := conn.execute(
                    f"SELECT min({TS}) FROM {quote_ident(t)} WHERE {TS} >= ?", (start,)
                ).fetchone()[0]
            )
            is not None
        ),
        default=start,
    )
    start = max(start, oldest)
    span = max(end - start, 1)
    bucket = next((b for b in BUCKET_SIZES_MS if span / b <= MAX_BUCKETS), DAY_MS)
    first = start - start % bucket
    n = (end - first) // bucket + 1
    buckets = [first + i * bucket for i in range(n)]
    series: dict[str, list[int]] = {}
    for table in tables:
        counts = [0] * n
        for b, c in conn.execute(
            f"SELECT ({TS} - ?) / ? AS b, count(*) FROM {quote_ident(table)} "
            f"WHERE {TS} >= ? AND {TS} <= ? GROUP BY b",
            (first, bucket, first, end),
        ):
            if 0 <= b < n:
                counts[b] = c
        if any(counts):
            series[table.removeprefix("ev_")] = counts
    return {"buckets": buckets, "series": series, "bucket_ms": bucket}


def top_values(
    conn: sqlite3.Connection, field: str, limit: int = 10, days: int = DEFAULT_WINDOW_DAYS
) -> list[tuple[str, int]]:
    """Most frequent values of ``field`` across every event table that has it."""
    window = data_window(conn, days)
    tables = EventStore(conn).tables_with_field(field)
    if window is None or not tables:
        return []
    col = quote_ident(field)
    # Group inside each table first: that reads only the (field, tl_ts) index. Grouping
    # a UNION of raw values instead would sort every row in a temporary b-tree.
    union = " UNION ALL ".join(
        f"SELECT {col} AS v, count(*) AS n FROM {quote_ident(t)} "
        f"WHERE {TS} >= ? AND {col} IS NOT NULL GROUP BY {col}"
        for t in tables
    )
    rows = conn.execute(
        f"SELECT v, sum(n) AS n FROM ({union}) GROUP BY v ORDER BY n DESC LIMIT ?",
        (*([window[0]] * len(tables)), limit),
    ).fetchall()
    return [(str(r[0]), int(r[1])) for r in rows]


@dataclass(frozen=True, slots=True)
class BatchRow:
    id: int
    source: str
    origin: str
    file_name: str
    parser: str
    status: str
    started_at: int
    finished_at: int | None
    lines: int
    inserted: int
    duplicates: int
    malformed: int
    error: str | None


def recent_batches(conn: sqlite3.Connection, limit: int = 50) -> list[BatchRow]:
    rows = conn.execute(
        "SELECT b.id, s.name, b.origin, b.file_name, b.parser, b.status, b.started_at, "
        "b.finished_at, b.lines_total, b.events_inserted, b.duplicates, b.malformed, b.error "
        "FROM ingest_batches b JOIN sources s ON s.id = b.source_id ORDER BY b.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [BatchRow(*r) for r in rows]
