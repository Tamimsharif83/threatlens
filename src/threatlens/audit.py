"""Append-only audit log of analyst and system actions."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from threatlens.timeutil import now_ms


@dataclass(frozen=True, slots=True)
class AuditEntry:
    id: int
    ts: int
    actor: str | None
    action: str
    target: str | None
    details: dict[str, Any]
    ip: str | None


def record(
    conn: sqlite3.Connection,
    action: str,
    *,
    actor: str | None = None,
    target: str | None = None,
    details: dict[str, Any] | None = None,
    ip: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, target, details, ip) VALUES (?, ?, ?, ?, ?, ?)",
        (
            now_ms(),
            actor,
            action,
            target,
            json.dumps(details or {}, separators=(",", ":"), default=str),
            ip,
        ),
    )


def recent(conn: sqlite3.Connection, limit: int = 100) -> list[AuditEntry]:
    rows = conn.execute(
        "SELECT id, ts, actor, action, target, details, ip FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        AuditEntry(
            id=r["id"],
            ts=r["ts"],
            actor=r["actor"],
            action=r["action"],
            target=r["target"],
            details=json.loads(r["details"] or "{}"),
            ip=r["ip"],
        )
        for r in rows
    ]
