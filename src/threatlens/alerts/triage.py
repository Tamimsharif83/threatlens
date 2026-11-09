"""Alert triage: status, resolution, assignee, notes, history and matched events.

Every change is written to the audit log with ``target = "alert:<id>"``, which
also gives each alert its history.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from threatlens import audit
from threatlens.storage.events import (
    BATCH,
    EXTRA,
    ID,
    RAW,
    TS,
    EventStore,
    load_raw_codec,
    quote_ident,
)
from threatlens.timeutil import now_ms

STATUSES = ("new", "in_progress", "closed")
RESOLUTIONS = ("true_positive", "false_positive", "benign_true_positive")
MAX_NOTE = 10_000
MAX_EVENTS_SHOWN = 200
EVENTS_PER_PAGE = 25
# Shown on every event card next to the rule's own fields; the rest is folded away.
KEY_FIELDS = (
    "event.action",
    "host.name",
    "user.name",
    "source.ip",
    "destination.ip",
    "http.request.method",
    "url.original",
    "http.response.status_code",
    "process.command_line",
    "file.path",
    "dns.question.name",
    "message",
)


class TriageError(ValueError):
    """An invalid triage action (bad status, missing resolution ...)."""


def target(alert_id: int) -> str:
    return f"alert:{alert_id}"


def set_status(
    conn: sqlite3.Connection,
    alert_ids: Sequence[int],
    status: str,
    resolution: str | None,
    actor: str,
    ip: str | None = None,
) -> int:
    """Change status (closing requires a resolution; reopening clears it)."""
    if status not in STATUSES:
        raise TriageError(f"unknown status {status!r}")
    if status == "closed":
        if resolution not in RESOLUTIONS:
            raise TriageError("closing an alert requires a resolution (TP, FP or benign TP)")
    else:
        resolution = None
    changed = 0
    now = now_ms()
    for aid in alert_ids:
        row = conn.execute("SELECT status, resolution FROM alerts WHERE id = ?", (aid,)).fetchone()
        if row is None or (row[0], row[1]) == (status, resolution):
            continue
        conn.execute(
            "UPDATE alerts SET status = ?, resolution = ?, updated_at = ? WHERE id = ?",
            (status, resolution, now, aid),
        )
        audit.record(
            conn,
            "alert.status",
            actor=actor,
            target=target(aid),
            ip=ip,
            details={"from": row[0], "to": status, "resolution": resolution},
        )
        changed += 1
    return changed


def assign(
    conn: sqlite3.Connection,
    alert_ids: Sequence[int],
    assignee: str | None,
    actor: str,
    ip: str | None = None,
) -> int:
    if assignee is not None:
        ok = conn.execute(
            "SELECT 1 FROM users WHERE username = ? AND disabled = 0", (assignee,)
        ).fetchone()
        if not ok:
            raise TriageError(f"unknown or disabled user {assignee!r}")
    changed = 0
    now = now_ms()
    for aid in alert_ids:
        row = conn.execute("SELECT assignee FROM alerts WHERE id = ?", (aid,)).fetchone()
        if row is None or row[0] == assignee:
            continue
        conn.execute(
            "UPDATE alerts SET assignee = ?, updated_at = ? WHERE id = ?", (assignee, now, aid)
        )
        audit.record(
            conn,
            "alert.assign",
            actor=actor,
            target=target(aid),
            ip=ip,
            details={"from": row[0], "to": assignee},
        )
        changed += 1
    return changed


def add_note(
    conn: sqlite3.Connection, alert_id: int, author: str, body: str, ip: str | None = None
) -> None:
    text = body.strip()
    if not text:
        raise TriageError("note is empty")
    if len(text) > MAX_NOTE:
        raise TriageError(f"note is longer than {MAX_NOTE} characters")
    if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        raise TriageError("alert not found")
    now = now_ms()
    conn.execute(
        "INSERT INTO alert_notes (alert_id, author, body, created_at) VALUES (?, ?, ?, ?)",
        (alert_id, author, text, now),
    )
    conn.execute("UPDATE alerts SET updated_at = ? WHERE id = ?", (now, alert_id))
    audit.record(
        conn,
        "alert.note",
        actor=author,
        target=target(alert_id),
        ip=ip,
        details={"chars": len(text)},
    )


@dataclass(frozen=True, slots=True)
class Note:
    id: int
    author: str
    body: str
    created_at: int


def notes(conn: sqlite3.Connection, alert_id: int) -> list[Note]:
    return [
        Note(r[0], r[1], r[2], r[3])
        for r in conn.execute(
            "SELECT id, author, body, created_at FROM alert_notes WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        )
    ]


def history(conn: sqlite3.Connection, alert_id: int) -> list[audit.AuditEntry]:
    rows = conn.execute(
        "SELECT id, ts, actor, action, target, details, ip FROM audit_log WHERE target = ? "
        "ORDER BY id",
        (target(alert_id),),
    ).fetchall()
    return [
        audit.AuditEntry(r[0], r[1], r[2], r[3], r[4], json.loads(r[5] or "{}"), r[6]) for r in rows
    ]


@dataclass(slots=True)
class EventView:
    table: str
    id: int
    ts: int
    fields: dict[str, Any] = field(default_factory=dict)
    raw: str | None = None
    purged: bool = False


def load_events(conn: sqlite3.Connection, refs: Sequence[tuple[str, int, int]]) -> list[EventView]:
    """Load events by (table, id, ts) references; purged events are marked, not dropped."""
    existing = set(EventStore(conn).event_tables())
    by_table: dict[str, list[tuple[int, int]]] = {}
    for table, eid, ts in refs:
        by_table.setdefault(table, []).append((eid, ts))
    views: list[EventView] = []
    for table, items in by_table.items():
        rows: dict[int, sqlite3.Row] = {}
        if table in existing:
            ids = [eid for eid, _ in items]
            placeholders = ",".join("?" * len(ids))
            for row in conn.execute(
                f"SELECT * FROM {quote_ident(table)} WHERE {ID} IN ({placeholders})", ids
            ):
                rows[row[ID]] = row
        for eid, ts in items:
            row = rows.get(eid)
            views.append(
                event_view(conn, table, row) if row else EventView(table, eid, ts, purged=True)
            )
    views.sort(key=lambda v: (v.ts, v.id))
    return views


def event_view(conn: sqlite3.Connection, table: str, row: sqlite3.Row) -> EventView:
    fields: dict[str, Any] = {}
    for key in row.keys():  # noqa: SIM118 - sqlite3.Row iterates values, not keys
        if key.startswith("tl_") or row[key] is None:
            continue
        fields[key] = row[key]
    if row[EXTRA]:
        try:
            fields.update(json.loads(row[EXTRA]))
        except json.JSONDecodeError:
            fields["tl_extra"] = row[EXTRA]
    raw = None
    if row[RAW] is not None:
        batch = conn.execute(
            "SELECT raw_dict_id FROM ingest_batches WHERE id = ?", (row[BATCH],)
        ).fetchone()
        try:
            raw = load_raw_codec(conn, batch[0] if batch else None).decompress(row[RAW])
        except Exception:  # corrupt/expired dictionary: show the event without its raw line
            raw = None
    return EventView(table, row[ID], row[TS], dict(sorted(fields.items())), raw)


def alert_events(
    conn: sqlite3.Connection, alert_id: int, limit: int = MAX_EVENTS_SHOWN, offset: int = 0
) -> list[EventView]:
    refs = conn.execute(
        "SELECT table_name, event_id, event_ts FROM alert_events WHERE alert_id = ? "
        "ORDER BY event_ts, event_id LIMIT ? OFFSET ?",
        (alert_id, limit, offset),
    ).fetchall()
    return load_events(conn, [(r[0], r[1], r[2]) for r in refs])


def alert_event_tables(conn: sqlite3.Connection, alert_id: int) -> tuple[int, list[str]]:
    """How many events an alert links to, and the tables they are in."""
    rows = conn.execute(
        "SELECT table_name, count(*) FROM alert_events WHERE alert_id = ? GROUP BY 1 ORDER BY 1",
        (alert_id,),
    ).fetchall()
    return sum(r[1] for r in rows), [r[0] for r in rows]
