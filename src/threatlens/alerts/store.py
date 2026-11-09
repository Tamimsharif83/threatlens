"""Turning rule matches into alerts: grouping, throttling and event references.

Matches of the same rule for the same *primary entity* that are no more than
``window`` apart (in event time) become one alert with a counter, as long as
that alert is not closed. The primary entity is the first present of
source IP, user name, host name, destination IP: a brute force from one IP
against many user names is one alert, not one per user name. Each matched event is referenced
once per rule (``alert_events``), so re-scanning data never double-counts.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from threatlens.timeutil import now_ms

ENTITY_FIELDS = ("source.ip", "user.name", "host.name", "destination.ip")
LEVELS = ("informational", "low", "medium", "high", "critical")


@dataclass(frozen=True, slots=True)
class Match:
    table: str
    event_id: int
    ts: int
    entities: dict[str, str]


@dataclass(frozen=True, slots=True)
class RuleInfo:
    id: str
    title: str
    level: str
    tags: list[str]


@dataclass(slots=True)
class RecordResult:
    new_alerts: list[int] = field(default_factory=list)
    updated_alerts: set[int] = field(default_factory=set)
    events: int = 0  # new matched events (not seen before for this rule)

    def merge(self, other: RecordResult) -> None:
        self.new_alerts.extend(other.new_alerts)
        self.updated_alerts |= other.updated_alerts
        self.events += other.events


def entities_from_row(row: sqlite3.Row) -> dict[str, str]:
    keys = row.keys()
    out: dict[str, str] = {}
    for f in ENTITY_FIELDS:
        if f in keys and row[f] not in (None, ""):
            out[f] = str(row[f])[:256]
    return out


def primary_entity(entities: dict[str, str]) -> dict[str, str]:
    for f in ENTITY_FIELDS:
        if f in entities:
            return {f: entities[f]}
    return {}


def group_key(rule_id: str, entities: dict[str, str]) -> str:
    primary = primary_entity(entities)
    return rule_id + "|" + json.dumps(primary, sort_keys=True, separators=(",", ":"))


def record_matches(
    conn: sqlite3.Connection,
    rule: RuleInfo,
    matches: Iterable[Match],
    window_ms: int,
    origin: str,
) -> RecordResult:
    """Must be called inside a write transaction."""
    result = RecordResult()
    now = now_ms()
    level = rule.level if rule.level in LEVELS else "medium"
    open_alerts: dict[str, dict[str, Any]] = {}  # group key -> {id, first, last}

    for m in sorted(matches, key=lambda m: (m.ts, m.event_id)):
        seen = conn.execute(
            "SELECT 1 FROM alert_events WHERE rule_id = ? AND table_name = ? AND event_id = ?",
            (rule.id, m.table, m.event_id),
        ).fetchone()
        if seen:
            continue
        key = group_key(rule.id, m.entities)
        current = open_alerts.get(key)
        if current is None:
            row = conn.execute(
                "SELECT id, first_seen, last_seen, entities FROM alerts WHERE group_key = ? AND "
                "status != 'closed' ORDER BY last_seen DESC LIMIT 1",
                (key,),
            ).fetchone()
            if row is not None:
                current = {
                    "id": row[0],
                    "first": row[1],
                    "last": row[2],
                    "entities": json.loads(row[3]),
                }
        if (
            current is not None
            and window_ms > 0
            and (
                current["last"] - window_ms <= m.ts <= current["last"] + window_ms
                or current["first"] <= m.ts <= current["last"]
            )
        ):
            current["first"] = min(current["first"], m.ts)
            current["last"] = max(current["last"], m.ts)
            # Keep only entity values shared by every event of the alert.
            current["entities"] = {
                k: v for k, v in current["entities"].items() if m.entities.get(k) == v
            }
            conn.execute(
                "UPDATE alerts SET event_count = event_count + 1, first_seen = ?, "
                "last_seen = ?, entities = ?, updated_at = ? WHERE id = ?",
                (
                    current["first"],
                    current["last"],
                    json.dumps(current["entities"], sort_keys=True),
                    now,
                    current["id"],
                ),
            )
            if current["id"] not in result.new_alerts:
                result.updated_alerts.add(current["id"])
        else:
            cur = conn.execute(
                "INSERT INTO alerts (rule_id, rule_title, level, tags, origin, group_key, "
                "entities, first_seen, last_seen, event_count, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (
                    rule.id,
                    rule.title,
                    level,
                    json.dumps(rule.tags),
                    origin,
                    key,
                    json.dumps(m.entities, sort_keys=True),
                    m.ts,
                    m.ts,
                    now,
                    now,
                ),
            )
            assert cur.lastrowid is not None  # noqa: S101
            current = {
                "id": cur.lastrowid,
                "first": m.ts,
                "last": m.ts,
                "entities": dict(m.entities),
            }
            result.new_alerts.append(cur.lastrowid)
        open_alerts[key] = current
        conn.execute(
            "INSERT INTO alert_events (rule_id, table_name, event_id, alert_id, event_ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (rule.id, m.table, m.event_id, current["id"], m.ts),
        )
        result.events += 1

    if result.events:
        conn.execute(
            "UPDATE rules SET hits = hits + ?, alerts = alerts + ?, last_fired_at = ? WHERE id = ?",
            (result.events, len(result.new_alerts), now, rule.id),
        )
    return result


# ---------------------------------------------------------------- reads


@dataclass(frozen=True, slots=True)
class AlertRow:
    id: int
    rule_id: str
    rule_title: str
    level: str
    tags: list[str]
    origin: str
    entities: dict[str, str]
    first_seen: int
    last_seen: int
    event_count: int
    status: str
    resolution: str | None
    assignee: str | None
    created_at: int
    kind: str = "detection"
    metric: dict[str, Any] | None = None


def _alert(row: sqlite3.Row) -> AlertRow:
    return AlertRow(
        id=row["id"],
        rule_id=row["rule_id"],
        rule_title=row["rule_title"],
        level=row["level"],
        tags=json.loads(row["tags"]),
        origin=row["origin"],
        entities=json.loads(row["entities"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        event_count=row["event_count"],
        status=row["status"],
        resolution=row["resolution"],
        assignee=row["assignee"],
        created_at=row["created_at"],
        kind=row["kind"],
        metric=json.loads(row["metric"]) if row["metric"] else None,
    )


def list_alerts(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    level: str | None = None,
    rule_id: str | None = None,
    limit: int = 100,
) -> list[AlertRow]:
    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status)
    if level:
        where.append("level = ?")
        params.append(level)
    if rule_id:
        where.append("rule_id = ?")
        params.append(rule_id)
    sql = "SELECT * FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY last_seen DESC, id DESC LIMIT ?"
    return [_alert(r) for r in conn.execute(sql, (*params, limit))]


def get_alert(conn: sqlite3.Connection, alert_id: int) -> AlertRow | None:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _alert(row) if row else None


def counts_by_level(conn: sqlite3.Connection, open_only: bool = True) -> dict[str, int]:
    sql = "SELECT level, count(*) FROM alerts"
    if open_only:
        sql += " WHERE status != 'closed'"
    counts = dict(conn.execute(sql + " GROUP BY level").fetchall())
    return {lvl: int(counts.get(lvl, 0)) for lvl in reversed(LEVELS)}


def top_rules(conn: sqlite3.Connection, limit: int = 10) -> list[tuple[str, str, int, int]]:
    """(rule id, title, alerts, events) for the noisiest rules."""
    rows = conn.execute(
        "SELECT rule_id, max(rule_title), count(*), sum(event_count) FROM alerts "
        "GROUP BY rule_id ORDER BY sum(event_count) DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [(r[0], r[1], int(r[2]), int(r[3])) for r in rows]


# ---------------------------------------------------------------- correlation alerts


@dataclass(frozen=True, slots=True)
class CorrelationHit:
    """One sliding-window result of a correlation rule."""

    group: dict[str, str]  # group-by key -> value (keys mapped to stored field names)
    events: list[tuple[str, int, int]]  # (table, event id, event ts)
    metric_type: str
    metric_value: float | int | None
    window_start: int  # ms
    window_end: int  # ms


def record_correlation(
    conn: sqlite3.Connection,
    rule: RuleInfo,
    hits: Iterable[CorrelationHit],
    base_rule_ids: tuple[str, ...],
    window_ms: int,
    origin: str,
) -> RecordResult:
    """Merge window results into one alert per group (must be called inside a transaction).

    The backend returns one row per sliding window, so the same burst shows up in
    many overlapping windows. Events already referenced by this correlation are
    skipped; a window with no new events changes nothing. New events join the
    group's open alert when they are within ``window_ms`` of it, and every base-rule
    alert on the same events is linked as a child.
    """
    result = RecordResult()
    now = now_ms()
    level = rule.level if rule.level in LEVELS else "medium"
    marks = ",".join("?" * len(base_rule_ids))
    for hit in sorted(hits, key=lambda h: (h.window_start, h.window_end)):
        new_events = [
            (t, eid, ts)
            for t, eid, ts in hit.events
            if conn.execute(
                "SELECT 1 FROM alert_events WHERE rule_id = ? AND table_name = ? AND event_id = ?",
                (rule.id, t, eid),
            ).fetchone()
            is None
        ]
        if not new_events:
            continue
        first = min(ts for _, _, ts in new_events)
        last = max(ts for _, _, ts in new_events)
        key = rule.id + "|" + json.dumps(hit.group, sort_keys=True, separators=(",", ":"))
        metric = json.dumps(
            {
                "type": hit.metric_type,
                "value": hit.metric_value,
                "window_start": hit.window_start,
                "window_end": hit.window_end,
            }
        )
        row = conn.execute(
            "SELECT id, first_seen, last_seen FROM alerts WHERE group_key = ? AND "
            "status != 'closed' ORDER BY last_seen DESC LIMIT 1",
            (key,),
        ).fetchone()
        if row is not None and first <= row[2] + window_ms:
            alert_id = row[0]
            conn.execute(
                "UPDATE alerts SET event_count = event_count + ?, first_seen = min(first_seen, ?),"
                " last_seen = max(last_seen, ?), metric = ?, updated_at = ? WHERE id = ?",
                (len(new_events), first, last, metric, now, alert_id),
            )
            if alert_id not in result.new_alerts:
                result.updated_alerts.add(alert_id)
        else:
            cur = conn.execute(
                "INSERT INTO alerts (rule_id, rule_title, level, tags, origin, group_key, "
                "entities, first_seen, last_seen, event_count, created_at, updated_at, kind, "
                "metric) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'correlation', ?)",
                (
                    rule.id,
                    rule.title,
                    level,
                    json.dumps(rule.tags),
                    origin,
                    key,
                    json.dumps(hit.group, sort_keys=True),
                    first,
                    last,
                    len(new_events),
                    now,
                    now,
                    metric,
                ),
            )
            assert cur.lastrowid is not None  # noqa: S101
            alert_id = cur.lastrowid
            result.new_alerts.append(alert_id)
        conn.executemany(
            "INSERT OR IGNORE INTO alert_events (rule_id, table_name, event_id, alert_id, "
            "event_ts) VALUES (?, ?, ?, ?, ?)",
            [(rule.id, t, eid, alert_id, ts) for t, eid, ts in new_events],
        )
        result.events += len(new_events)
        if base_rule_ids:
            for t, eid, _ in new_events:
                conn.execute(
                    "INSERT OR IGNORE INTO alert_links (parent_id, child_id) "
                    f"SELECT ?, alert_id FROM alert_events WHERE rule_id IN ({marks}) "
                    "AND table_name = ? AND event_id = ?",
                    (alert_id, *base_rule_ids, t, eid),
                )
    if result.events:
        conn.execute(
            "UPDATE rules SET hits = hits + ?, alerts = alerts + ?, last_fired_at = ? WHERE id = ?",
            (result.events, len(result.new_alerts), now, rule.id),
        )
    return result


def linked_alerts(conn: sqlite3.Connection, alert_id: int) -> tuple[list[AlertRow], list[AlertRow]]:
    """(children, parents) of an alert."""
    children = [
        _alert(r)
        for r in conn.execute(
            "SELECT a.* FROM alert_links l JOIN alerts a ON a.id = l.child_id "
            "WHERE l.parent_id = ? ORDER BY a.first_seen",
            (alert_id,),
        )
    ]
    parents = [
        _alert(r)
        for r in conn.execute(
            "SELECT a.* FROM alert_links l JOIN alerts a ON a.id = l.parent_id "
            "WHERE l.child_id = ? ORDER BY a.first_seen",
            (alert_id,),
        )
    ]
    return children, parents
