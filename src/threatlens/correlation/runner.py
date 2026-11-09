"""Run a compiled correlation over a time range and record its alerts."""

from __future__ import annotations

import json
import sqlite3

from threatlens.alerts.store import CorrelationHit, RecordResult, RuleInfo, record_correlation
from threatlens.correlation.compiler import CompiledCorrelation, view_name
from threatlens.storage.db import transaction
from threatlens.storage.events import ID, TS, EventStore, quote_ident


def ensure_columns(conn: sqlite3.Connection, compiled: CompiledCorrelation) -> None:
    store = EventStore(conn)
    for table, fields in compiled.required_fields.items():
        existing = store.table_columns(table)
        missing = [f for f in fields if f.lower() not in existing and not f.startswith("tl_")]
        if missing:
            with transaction(conn):
                for f in missing:
                    conn.execute(
                        f"ALTER TABLE {quote_ident(table)} ADD COLUMN "
                        f"{quote_ident(f)} TEXT COLLATE NOCASE"
                    )


def create_views(conn: sqlite3.Connection, tables: set[str], start_ms: int, end_ms: int) -> None:
    """Temporary views restricting each source table to [start, end] of event time.
    Bounds are integers produced by ThreatLens, never user input."""
    lo, hi = int(start_ms), int(end_ms)
    for table in tables:
        view = quote_ident(view_name(table))
        conn.execute(f"DROP VIEW IF EXISTS temp.{view}")
        conn.execute(
            f"CREATE TEMP VIEW {view} AS SELECT * FROM {quote_ident(table)} "
            f"WHERE {TS} BETWEEN {lo} AND {hi}"
        )


def _drop_views(conn: sqlite3.Connection, tables: set[str]) -> None:
    for table in tables:
        conn.execute(f"DROP VIEW IF EXISTS temp.{quote_ident(view_name(table))}")


def run_correlation(
    conn: sqlite3.Connection,
    compiled: CompiledCorrelation,
    rule: RuleInfo,
    start_ms: int,
    end_ms: int,
    window_ms: int,
    origin: str,
) -> RecordResult:
    tables = set(compiled.source_tables.values())
    present = set(EventStore(conn).event_tables())
    if not tables <= present:
        return RecordResult()  # some referenced logs were never ingested: cannot match
    ensure_columns(conn, compiled)
    create_views(conn, tables, start_ms, end_ms)
    try:
        rows = conn.execute(compiled.sql).fetchall()
    finally:
        _drop_views(conn, tables)
    if not rows:
        return RecordResult()

    # Resolve "<table index>:<id>" event references and their timestamps.
    wanted: dict[str, set[int]] = {}
    parsed: list[tuple[dict[str, str], list[tuple[str, int]], sqlite3.Row]] = []
    for row in rows:
        refs = []
        for ref in json.loads(row["event_ids"] or "[]"):
            index, _, eid = str(ref).partition(":")
            table = compiled.source_tables.get(index)
            if table and eid.isdigit():
                refs.append((table, int(eid)))
                wanted.setdefault(table, set()).add(int(eid))
        raw_group = json.loads(row["group_keys"] or "{}")
        group = {
            compiled.entity_fields.get(k, k): str(v) for k, v in raw_group.items() if v is not None
        }
        parsed.append((group, refs, row))
    ts: dict[tuple[str, int], int] = {}
    for table, ids in wanted.items():
        id_list = sorted(ids)
        for i in range(0, len(id_list), 500):
            part = id_list[i : i + 500]
            marks = ",".join("?" * len(part))
            for eid, t in conn.execute(
                f"SELECT {ID}, {TS} FROM {quote_ident(table)} WHERE {ID} IN ({marks})", part
            ):
                ts[(table, eid)] = t
    hits = [
        CorrelationHit(
            group=group,
            events=[(t, eid, ts[(t, eid)]) for t, eid in refs if (t, eid) in ts],
            metric_type=str(row["metric_name"]),
            metric_value=row["metric_value"],
            window_start=int(float(row["window_start"]) * 1000),
            window_end=int(float(row["window_end"]) * 1000),
        )
        for group, refs, row in parsed
    ]
    with transaction(conn):
        return record_correlation(conn, rule, hits, compiled.base_rule_ids, window_ms, origin)
