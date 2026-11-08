"""Event tables: one flattened table per Sigma log source (ADR-0002).

Each table has fixed provenance columns (prefixed ``tl_``) plus one column per
field seen so far. New fields become new columns (cheap in SQLite); fields that
cannot become columns (bad names, case collisions, column cap reached) go into
the ``tl_extra`` JSON column so nothing is lost.

All writes happen inside the caller's transaction, so the schema check
(``PRAGMA table_info``) and the inserts are atomic even with several writer
processes (web app + CLI).
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import zstandard

from threatlens.normalize.schema import Event, LogSource
from threatlens.normalize.values import sql_type_for, sql_value
from threatlens.timeutil import now_ms

# Provenance columns. "tl_" is reserved: event fields with this prefix go to tl_extra.
ID, TS, BATCH, RECORD, HASH, RAW, EXTRA = (
    "tl_id",
    "tl_ts",
    "tl_batch",
    "tl_record",
    "tl_hash",
    "tl_raw",
    "tl_extra",
)
RESERVED_PREFIX = "tl_"
MAX_FIELD_COLUMNS = 400
_FIELD_NAME = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_@.\-:/]{0,127}$")
_TABLE_NAME = re.compile(r"^ev_[a-z0-9_]{1,45}$")
# Fields analysts pivot on: indexed as soon as the column exists.
PIVOT_FIELDS = frozenset({"source.ip", "destination.ip", "user.name", "host.name"})

RAW_LEVEL = 3
RAW_DICT_SIZE = 16 * 1024
RAW_DICT_MIN_SAMPLES = 500


def quote_ident(name: str) -> str:
    """Quote an SQL identifier. Names come from logs: always quote, always escape."""
    return '"' + name.replace('"', '""') + '"'


def content_hash(table: str, raw: str, occurrence: int) -> int:
    """64-bit dedup key: same line, same table, same occurrence => same event."""
    h = hashlib.blake2b(digest_size=8)
    h.update(table.encode())
    h.update(b"\x1f")
    h.update(raw.encode("utf-8", "surrogatepass"))
    h.update(b"\x1f")
    h.update(str(occurrence).encode())
    return int.from_bytes(h.digest(), "big", signed=True)


@dataclass(slots=True)
class TableResult:
    table: str
    inserted: int = 0
    duplicates: int = 0
    min_id: int | None = None
    max_id: int | None = None


@dataclass(slots=True)
class InsertResult:
    tables: dict[str, TableResult] = field(default_factory=dict)

    @property
    def inserted(self) -> int:
        return sum(t.inserted for t in self.tables.values())

    @property
    def duplicates(self) -> int:
        return sum(t.duplicates for t in self.tables.values())


@dataclass(slots=True)
class PreparedEvent:
    event: Event
    hash: int


class RawCodec:
    """zstd compression of raw lines, optionally with a per-batch dictionary.

    Log lines are short and repetitive; a dictionary trained on a sample of the
    batch typically compresses them 3-5x better than plain zstd on each line.
    """

    def __init__(self, dict_data: bytes | None = None) -> None:
        zdict = zstandard.ZstdCompressionDict(dict_data) if dict_data else None
        self._c = zstandard.ZstdCompressor(level=RAW_LEVEL, dict_data=zdict)
        self._d = zstandard.ZstdDecompressor(dict_data=zdict)

    def compress(self, text: str) -> bytes:
        return self._c.compress(text.encode("utf-8", "surrogatepass"))

    def decompress(self, blob: bytes) -> str:
        return self._d.decompress(blob).decode("utf-8", "replace")

    @staticmethod
    def train(samples: Sequence[str]) -> bytes | None:
        if len(samples) < RAW_DICT_MIN_SAMPLES:
            return None
        try:
            zdict = zstandard.train_dictionary(
                RAW_DICT_SIZE, [s.encode("utf-8", "surrogatepass") for s in samples]
            )
        except zstandard.ZstdError:
            return None
        return zdict.as_bytes()


def store_raw_dict(conn: sqlite3.Connection, data: bytes) -> int:
    cur = conn.execute("INSERT INTO raw_dicts (dict, created_at) VALUES (?, ?)", (data, now_ms()))
    assert cur.lastrowid is not None  # noqa: S101 - sqlite always sets it
    return cur.lastrowid


def load_raw_codec(conn: sqlite3.Connection, dict_id: int | None) -> RawCodec:
    if dict_id is None:
        return RawCodec()
    row = conn.execute("SELECT dict FROM raw_dicts WHERE id = ?", (dict_id,)).fetchone()
    return RawCodec(row[0] if row else None)


class EventStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # ---------------------------------------------------------------- schema

    def table_columns(self, table: str) -> dict[str, str]:
        """Lower-cased column name -> actual column name."""
        rows = self.conn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()
        return {r[1].lower(): r[1] for r in rows}

    def ensure_table(self, logsource: LogSource) -> str:
        table = logsource.table_name
        if not _TABLE_NAME.match(table):
            raise ValueError(f"invalid event table name: {table!r}")
        exists = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        if exists:
            return table
        q = quote_ident(table)
        self.conn.execute(
            f"CREATE TABLE {q} ("
            f"{ID} INTEGER PRIMARY KEY, {TS} INTEGER NOT NULL, {BATCH} INTEGER NOT NULL, "
            f"{RECORD} INTEGER NOT NULL, {HASH} INTEGER NOT NULL UNIQUE, {RAW} BLOB, "
            f"{EXTRA} TEXT)"
        )
        self.conn.execute(f"CREATE INDEX {quote_ident(table + '__ts')} ON {q} ({TS})")
        self.conn.execute(
            "INSERT OR IGNORE INTO event_tables (table_name, category, product, service, "
            "created_at) VALUES (?, ?, ?, ?, ?)",
            (table, logsource.category, logsource.product, logsource.service, now_ms()),
        )
        return table

    def _add_column(self, table: str, name: str, sql_type: str) -> None:
        q = quote_ident(table)
        self.conn.execute(
            f"ALTER TABLE {q} ADD COLUMN {quote_ident(name)} {sql_type} COLLATE NOCASE"
        )
        if name in PIVOT_FIELDS:
            self.conn.execute(
                f"CREATE INDEX IF NOT EXISTS {quote_ident(f'{table}__{name}')} "
                f"ON {q} ({quote_ident(name)})"
            )
        self.conn.execute(
            "INSERT OR IGNORE INTO event_fields (table_name, field, sql_type, first_seen) "
            "VALUES (?, ?, ?, ?)",
            (table, name, sql_type, now_ms()),
        )

    def _plan_columns(self, table: str, events: Iterable[Event]) -> tuple[dict[str, str], set[str]]:
        """Decide which fields get columns (creating them) and which go to tl_extra.

        Returns (field -> column name, fields routed to tl_extra).
        """
        existing = self.table_columns(table)
        field_count = sum(1 for c in existing if not c.startswith(RESERVED_PREFIX))
        columns: dict[str, str] = {}
        overflow: set[str] = set()
        first_values: dict[str, Any] = {}
        for ev in events:
            for name, value in ev.fields.items():
                if name in columns or name in overflow:
                    continue
                low = name.lower()
                if (
                    not _FIELD_NAME.match(name)
                    or low.startswith(RESERVED_PREFIX)
                    or (low in existing and existing[low] != name)  # case collision
                ):
                    overflow.add(name)
                elif low in existing:
                    columns[name] = name
                elif value is not None or name not in first_values:
                    first_values[name] = value
        for name, value in first_values.items():
            if name in columns or name in overflow:
                continue
            low = name.lower()
            if low in existing:  # added by an earlier field in this chunk with other case
                overflow.add(name)
                continue
            if field_count >= MAX_FIELD_COLUMNS:
                overflow.add(name)
                continue
            self._add_column(table, name, sql_type_for(value))
            existing[low] = name
            columns[name] = name
            field_count += 1
        return columns, overflow

    # ---------------------------------------------------------------- writes

    def insert(
        self,
        events: Sequence[PreparedEvent],
        batch_id: int,
        raw_codec: RawCodec | None = None,
    ) -> InsertResult:
        """Insert events (any mix of log sources). Duplicates (same hash) are skipped."""
        result = InsertResult()
        by_source: dict[LogSource, list[PreparedEvent]] = {}
        for pe in events:
            by_source.setdefault(pe.event.logsource, []).append(pe)
        for logsource, group in by_source.items():
            table = self.ensure_table(logsource)
            columns, overflow = self._plan_columns(table, (pe.event for pe in group))
            field_names = sorted(columns)
            col_sql = ", ".join(quote_ident(columns[f]) for f in field_names)
            base = [TS, BATCH, RECORD, HASH, RAW, EXTRA]
            all_cols = ", ".join(base) + (f", {col_sql}" if col_sql else "")
            placeholders = ", ".join("?" * (len(base) + len(field_names)))
            rows = []
            for pe in group:
                ev = pe.event
                extra = {k: v for k, v in ev.fields.items() if k in overflow}
                extra.update(ev.extra)
                rows.append(
                    (
                        ev.ts,
                        batch_id,
                        ev.record_no,
                        pe.hash,
                        raw_codec.compress(ev.raw) if raw_codec and ev.raw else None,
                        json.dumps(extra, default=str, ensure_ascii=False) if extra else None,
                        *(sql_value(ev.fields.get(f)) for f in field_names),
                    )
                )
            q = quote_ident(table)
            before_max = self.conn.execute(f"SELECT max({ID}) FROM {q}").fetchone()[0] or 0
            before_changes = self.conn.total_changes
            self.conn.executemany(
                f"INSERT OR IGNORE INTO {q} ({all_cols}) VALUES ({placeholders})", rows
            )
            inserted = self.conn.total_changes - before_changes
            tr = TableResult(table=table, inserted=inserted, duplicates=len(rows) - inserted)
            if inserted:
                tr.min_id = before_max + 1
                tr.max_id = self.conn.execute(f"SELECT max({ID}) FROM {q}").fetchone()[0]
            result.tables[table] = tr
        return result

    # ---------------------------------------------------------------- reads

    def event_tables(self) -> list[str]:
        return [
            r[0]
            for r in self.conn.execute(
                "SELECT table_name FROM event_tables "
                "WHERE table_name IN (SELECT name FROM sqlite_master WHERE type = 'table') "
                "ORDER BY table_name"
            )
        ]

    def tables_with_field(self, field_name: str) -> list[str]:
        return [
            r[0]
            for r in self.conn.execute(
                "SELECT table_name FROM event_fields WHERE field = ? ORDER BY table_name",
                (field_name,),
            )
        ]
