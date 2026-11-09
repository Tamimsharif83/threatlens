"""Suppressions (allowlist): known-good matches that must not create alerts.

An entry says: for rule R (or every rule), a match whose field F equals value V
(case-insensitive, like Sigma) is not alerted. Every entry needs a reason and an
author, may expire, is audited, and counts how often it suppressed something,
so stale or over-broad entries are visible.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass

from threatlens import audit
from threatlens.timeutil import now_ms

_FIELD = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_@.\-:/]{0,127}$")
MAX_VALUE = 1024
MAX_REASON = 2000


class SuppressionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Suppression:
    id: int
    rule_id: str | None
    field: str
    value: str
    reason: str
    created_by: str
    created_at: int
    expires_at: int | None
    enabled: bool
    hits: int
    last_hit_at: int | None

    def matches(self, values: Mapping[str, object]) -> bool:
        v = values.get(self.field)
        return v is not None and str(v).casefold() == self.value.casefold()

    def expired(self, now: int) -> bool:
        return self.expires_at is not None and self.expires_at <= now


def _row(r: sqlite3.Row) -> Suppression:
    return Suppression(
        r["id"],
        r["rule_id"],
        r["field"],
        r["value"],
        r["reason"],
        r["created_by"],
        r["created_at"],
        r["expires_at"],
        bool(r["enabled"]),
        r["hits"],
        r["last_hit_at"],
    )


def list_all(conn: sqlite3.Connection) -> list[Suppression]:
    return [_row(r) for r in conn.execute("SELECT * FROM suppressions ORDER BY id DESC")]


def active_for_rule(
    conn: sqlite3.Connection, rule_id: str, now: int | None = None
) -> list[Suppression]:
    now = now if now is not None else now_ms()
    rows = conn.execute(
        "SELECT * FROM suppressions WHERE enabled = 1 AND (rule_id IS NULL OR rule_id = ?) "
        "AND (expires_at IS NULL OR expires_at > ?)",
        (rule_id, now),
    ).fetchall()
    return [_row(r) for r in rows]


def create(
    conn: sqlite3.Connection,
    *,
    rule_id: str | None,
    field: str,
    value: str,
    reason: str,
    actor: str,
    expires_at: int | None = None,
    ip: str | None = None,
) -> int:
    field, value, reason = field.strip(), value.strip(), reason.strip()
    if not _FIELD.match(field):
        raise SuppressionError("field must be a field name such as source.ip")
    if not value or len(value) > MAX_VALUE:
        raise SuppressionError(f"value must be 1-{MAX_VALUE} characters")
    if not reason or len(reason) > MAX_REASON:
        raise SuppressionError("a reason is required (why is this known-good?)")
    if expires_at is not None and expires_at <= now_ms():
        raise SuppressionError("expiry must be in the future")
    if rule_id and conn.execute("SELECT 1 FROM rules WHERE id = ?", (rule_id,)).fetchone() is None:
        raise SuppressionError("unknown rule")
    cur = conn.execute(
        "INSERT INTO suppressions (rule_id, field, value, reason, created_by, created_at, "
        "expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rule_id or None, field, value, reason, actor, now_ms(), expires_at),
    )
    sid = cur.lastrowid
    assert sid is not None  # noqa: S101
    audit.record(
        conn,
        "suppression.create",
        actor=actor,
        target=f"suppression:{sid}",
        ip=ip,
        details={
            "rule_id": rule_id,
            "field": field,
            "value": value,
            "reason": reason,
            "expires_at": expires_at,
        },
    )
    return sid


def set_enabled(
    conn: sqlite3.Connection, sid: int, enabled: bool, actor: str, ip: str | None = None
) -> None:
    n = conn.execute("UPDATE suppressions SET enabled = ? WHERE id = ?", (int(enabled), sid))
    if not n.rowcount:
        raise SuppressionError("suppression not found")
    audit.record(
        conn,
        "suppression.enable" if enabled else "suppression.disable",
        actor=actor,
        target=f"suppression:{sid}",
        ip=ip,
    )


def delete(conn: sqlite3.Connection, sid: int, actor: str, ip: str | None = None) -> None:
    row = conn.execute("SELECT * FROM suppressions WHERE id = ?", (sid,)).fetchone()
    if row is None:
        raise SuppressionError("suppression not found")
    conn.execute("DELETE FROM suppressions WHERE id = ?", (sid,))
    audit.record(
        conn,
        "suppression.delete",
        actor=actor,
        target=f"suppression:{sid}",
        ip=ip,
        details={"field": row["field"], "value": row["value"], "hits": row["hits"]},
    )


def record_hits(conn: sqlite3.Connection, rule_id: str, hits: Mapping[int, int]) -> None:
    if not hits:
        return
    now = now_ms()
    conn.executemany(
        "UPDATE suppressions SET hits = hits + ?, last_hit_at = ? WHERE id = ?",
        [(n, now, sid) for sid, n in hits.items()],
    )
    conn.execute(
        "UPDATE rules SET suppressed = suppressed + ? WHERE id = ?", (sum(hits.values()), rule_id)
    )
