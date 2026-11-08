"""Retention purge, space reclamation and storage statistics."""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from threatlens.storage.events import BATCH, ID, EventStore, quote_ident
from threatlens.timeutil import now_ms

log = logging.getLogger(__name__)
PURGE_CHUNK = 20_000
DAY_MS = 86_400_000


@dataclass(slots=True)
class PurgeResult:
    cutoff_ms: int
    events_deleted: dict[str, int] = field(default_factory=dict)
    batches_deleted: int = 0
    pages_freed: int = 0

    @property
    def total(self) -> int:
        return sum(self.events_deleted.values())


def _in_tx(conn: sqlite3.Connection, sql: str, params: tuple[object, ...]) -> int:
    conn.execute("BEGIN IMMEDIATE")
    try:
        n = conn.execute(sql, params).rowcount
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return n


def purge(conn: sqlite3.Connection, retention_days: int, now: int | None = None) -> PurgeResult:
    """Delete everything ingested more than ``retention_days`` ago.

    Retention counts from *ingestion* time, not event time: analysts routinely
    import old logs (last quarter's incident, a public dataset), and those must
    stay for the full retention period instead of vanishing at the next purge.

    Whole batches expire together. Their rows are found through the id ranges
    recorded per batch (a rowid range scan, no extra index), deleted in small
    chunks so ingestion and the UI are never blocked for long, and the freed
    pages are returned to the OS with ``incremental_vacuum``.
    """
    cutoff = (now if now is not None else now_ms()) - retention_days * DAY_MS
    result = PurgeResult(cutoff_ms=cutoff)
    existing = set(EventStore(conn).event_tables())
    expired = conn.execute(
        "SELECT id FROM ingest_batches WHERE status != 'running' AND "
        "coalesce(finished_at, started_at) < ? ORDER BY id",
        (cutoff,),
    ).fetchall()
    for (batch_id,) in expired:
        ranges = conn.execute(
            "SELECT table_name, min_id, max_id FROM ingest_batch_tables WHERE batch_id = ?",
            (batch_id,),
        ).fetchall()
        for table, lo, hi in ranges:
            if table not in existing:
                continue
            q = quote_ident(table)
            start = lo
            while start <= hi:
                end = min(hi, start + PURGE_CHUNK - 1)
                n = _in_tx(
                    conn,
                    f"DELETE FROM {q} WHERE {ID} BETWEEN ? AND ? AND {BATCH} = ?",
                    (start, end, batch_id),
                )
                if n:
                    result.events_deleted[table] = result.events_deleted.get(table, 0) + n
                start = end + 1
        result.batches_deleted += _in_tx(
            conn, "DELETE FROM ingest_batches WHERE id = ?", (batch_id,)
        )
    _in_tx(
        conn,
        "DELETE FROM raw_dicts WHERE id NOT IN "
        "(SELECT raw_dict_id FROM ingest_batches WHERE raw_dict_id IS NOT NULL)",
        (),
    )
    _in_tx(
        conn,
        "DELETE FROM sources WHERE id NOT IN (SELECT source_id FROM ingest_batches) "
        "AND id NOT IN (SELECT source_id FROM watch_files WHERE source_id IS NOT NULL)",
        (),
    )
    result.pages_freed = reclaim(conn)
    if result.total or result.batches_deleted:
        log.info(
            "retention purge",
            extra={
                "events": result.total,
                "batches": result.batches_deleted,
                "pages_freed": result.pages_freed,
            },
        )
    return result


def reclaim(conn: sqlite3.Connection) -> int:
    """Return free pages to the file system (cheap; no full rewrite)."""
    free = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    if free:
        # The pragma frees pages as its result rows are stepped: read it to the end.
        conn.execute("PRAGMA incremental_vacuum").fetchall()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return free


def compact(conn: sqlite3.Connection, *, full: bool = False) -> None:
    """``threatlens db compact``: reclaim space; ``full`` rewrites the whole file
    (needs free disk space equal to the database size, and blocks writers)."""
    reclaim(conn)
    if full:
        conn.execute("VACUUM")
    conn.execute("PRAGMA optimize")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


@dataclass(slots=True)
class TableStats:
    table: str
    events: int
    bytes: int


@dataclass(slots=True)
class SourceStats:
    name: str
    parser: str
    events: int
    approx_bytes: int
    batches: int
    last_event_at: int | None
    timezone: str | None


@dataclass(slots=True)
class StorageStats:
    db_bytes: int
    wal_bytes: int
    free_bytes: int
    tables: list[TableStats]
    sources: list[SourceStats]

    @property
    def total_events(self) -> int:
        return sum(t.events for t in self.tables)


def _object_bytes(conn: sqlite3.Connection) -> dict[str, int]:
    """Bytes per table including its indexes (needs the dbstat virtual table)."""
    try:
        rows = conn.execute(
            "SELECT coalesce(m.tbl_name, d.name) AS tbl, sum(d.pgsize) FROM dbstat d "
            "LEFT JOIN sqlite_master m ON m.name = d.name GROUP BY tbl"
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {r[0]: int(r[1]) for r in rows}


def storage_stats(conn: sqlite3.Connection, db_path: Path) -> StorageStats:
    store = EventStore(conn)
    sizes = _object_bytes(conn)
    tables: list[TableStats] = []
    for table in store.event_tables():
        n = int(conn.execute(f"SELECT count(*) FROM {quote_ident(table)}").fetchone()[0])
        tables.append(TableStats(table, n, sizes.get(table, 0)))
    bytes_per_event = {t.table: (t.bytes / t.events if t.events else 0.0) for t in tables}

    # Events per source: summed over batch ranges per table (live rows only).
    per_source: dict[int, list[float]] = {}
    for table, per_event in bytes_per_event.items():
        q = quote_ident(table)
        for row in conn.execute(
            f"SELECT b.source_id, count(*) FROM {q} e JOIN ingest_batches b ON b.id = e.tl_batch "
            "GROUP BY b.source_id"
        ):
            acc = per_source.setdefault(row[0], [0, 0.0])
            acc[0] += row[1]
            acc[1] += row[1] * per_event
    sources: list[SourceStats] = []
    for row in conn.execute(
        "SELECT s.id, s.name, s.parser, s.last_event_at, s.timezone, "
        "(SELECT count(*) FROM ingest_batches b WHERE b.source_id = s.id) AS batches "
        "FROM sources s ORDER BY s.name"
    ):
        events, approx = per_source.get(row["id"], [0, 0.0])
        sources.append(
            SourceStats(
                row["name"],
                row["parser"],
                int(events),
                int(approx),
                row["batches"],
                row["last_event_at"],
                row["timezone"],
            )
        )
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    free_pages = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    wal = db_path.with_name(db_path.name + "-wal")
    return StorageStats(
        db_bytes=db_path.stat().st_size if db_path.exists() else 0,
        wal_bytes=wal.stat().st_size if wal.exists() else 0,
        free_bytes=free_pages * page_size,
        tables=tables,
        sources=sources,
    )
