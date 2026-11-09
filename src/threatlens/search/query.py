"""Field-filter search over one event table.

Builds parameterized SQL from a form: only field names that exist in the
table can be used (checked against the catalog, then quoted), and every value
is a bound parameter.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from threatlens.alerts.triage import EventView, event_view
from threatlens.storage.events import ID, TS, EventStore, quote_ident

OPERATORS = {
    "eq": "equals",
    "ne": "does not equal",
    "contains": "contains",
    "startswith": "starts with",
    "endswith": "ends with",
    "gt": ">",
    "lt": "<",
    "exists": "exists",
    "missing": "is missing",
}
MAX_CONDITIONS = 8
MAX_LIMIT = 1000


class SearchError(ValueError):
    pass


@dataclass(slots=True)
class Condition:
    field: str
    op: str
    value: str = ""


@dataclass(slots=True)
class SearchRequest:
    table: str
    conditions: list[Condition] = field(default_factory=list)
    start_ms: int | None = None
    end_ms: int | None = None
    limit: int = 200
    newest_first: bool = True


@dataclass(slots=True)
class SearchResult:
    events: list[EventView]
    columns: list[str]
    truncated: bool
    sql: str


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build(  # noqa: PLR0912 - one branch per operator
    conn: sqlite3.Connection, req: SearchRequest
) -> tuple[str, list[object]]:
    store = EventStore(conn)
    if req.table not in store.event_tables():
        raise SearchError("unknown event table")
    columns = store.table_columns(req.table)
    where: list[str] = []
    params: list[object] = []
    if req.start_ms is not None:
        where.append(f"{TS} >= ?")
        params.append(req.start_ms)
    if req.end_ms is not None:
        where.append(f"{TS} <= ?")
        params.append(req.end_ms)
    if len(req.conditions) > MAX_CONDITIONS:
        raise SearchError(f"at most {MAX_CONDITIONS} conditions")
    for cond in req.conditions:
        actual = columns.get(cond.field.lower())
        if actual is None or actual.startswith("tl_"):
            raise SearchError(f"unknown field {cond.field!r} in {req.table}")
        col = quote_ident(actual)
        op = cond.op
        if op == "eq":
            where.append(f"{col} = ?")
            params.append(cond.value)
        elif op == "ne":
            where.append(f"({col} IS NULL OR {col} != ?)")
            params.append(cond.value)
        elif op in ("contains", "startswith", "endswith"):
            v = _like_escape(cond.value)
            pattern = {"contains": f"%{v}%", "startswith": f"{v}%", "endswith": f"%{v}"}[op]
            where.append(f"{col} LIKE ? ESCAPE '\\'")
            params.append(pattern)
        elif op in ("gt", "lt"):
            try:
                number: object = float(cond.value)
            except ValueError:
                number = cond.value
            where.append(f"{col} {'>' if op == 'gt' else '<'} ?")
            params.append(number)
        elif op == "exists":
            where.append(f"{col} IS NOT NULL")
        elif op == "missing":
            where.append(f"{col} IS NULL")
        else:
            raise SearchError(f"unknown operator {op!r}")
    limit = max(1, min(req.limit, MAX_LIMIT))
    sql = f"SELECT * FROM {quote_ident(req.table)}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {TS} {'DESC' if req.newest_first else 'ASC'}, {ID} LIMIT {limit + 1}"
    return sql, params


def search(conn: sqlite3.Connection, req: SearchRequest) -> SearchResult:
    sql, params = build(conn, req)
    rows = conn.execute(sql, params).fetchall()
    limit = max(1, min(req.limit, MAX_LIMIT))
    events = [event_view(conn, req.table, r) for r in rows[:limit]]
    # Columns to show: fields that appear in the results, the searched ones first.
    seen: dict[str, None] = {c.field: None for c in req.conditions}
    for ev in events:
        for name in ev.fields:
            seen.setdefault(name, None)
    return SearchResult(events, list(seen), len(rows) > limit, sql)


def fields_of(conn: sqlite3.Connection, table: str) -> list[str]:
    return sorted(
        c for c in EventStore(conn).table_columns(table).values() if not c.startswith("tl_")
    )
