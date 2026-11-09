"""Cases: investigations that group alerts, with notes, timeline annotations and IOCs.

Every change is audited with ``target = "case:<id>"``.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from threatlens import audit
from threatlens.alerts.store import AlertRow, alert_from_row
from threatlens.alerts.triage import EventView, load_events
from threatlens.attack.catalog import load as load_catalog
from threatlens.timeutil import now_ms

SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("open", "investigating", "contained", "closed")
IOC_KINDS = ("ip", "domain", "url", "user_agent", "user", "file_hash", "file_name", "other")
REPORT_SECTIONS = ("summary", "scope", "impact", "root_cause", "recommendations", "appendix")
MAX_TEXT = 20_000
MAX_TITLE = 200
MAX_IOC = 2048
TIMELINE_EVENTS = 500

# Event fields that become IOCs automatically.
IOC_FIELDS: dict[str, str] = {
    "source.ip": "ip",
    "destination.ip": "ip",
    "client.ip": "ip",
    "destination.domain": "domain",
    "url.domain": "domain",
    "url.original": "url",
    "user_agent.original": "user_agent",
    "user.name": "user",
    "user.target.name": "user",
    "file.hash.sha256": "file_hash",
    "file.hash.sha1": "file_hash",
    "file.hash.md5": "file_hash",
    "file.name": "file_name",
}
_HEX_HASH = re.compile(r"^[0-9a-fA-F]{32}([0-9a-fA-F]{8})?([0-9a-fA-F]{24})?$")


class CaseError(ValueError):
    pass


def target(case_id: int) -> str:
    return f"case:{case_id}"


@dataclass(slots=True)
class Case:
    id: int
    title: str
    description: str | None
    severity: str
    status: str
    assignee: str | None
    created_by: str
    created_at: int
    updated_at: int
    closed_at: int | None
    sections: dict[str, str | None] = field(default_factory=dict)


def _case(row: sqlite3.Row) -> Case:
    return Case(
        row["id"],
        row["title"],
        row["description"],
        row["severity"],
        row["status"],
        row["assignee"],
        row["created_by"],
        row["created_at"],
        row["updated_at"],
        row["closed_at"],
        {s: row[s] for s in REPORT_SECTIONS},
    )


def _text(value: str | None, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) > limit:
        raise CaseError(f"text is longer than {limit} characters")
    return value or None


def create(
    conn: sqlite3.Connection,
    *,
    title: str,
    severity: str,
    actor: str,
    description: str | None = None,
    alert_ids: Sequence[int] = (),
    ip: str | None = None,
) -> int:
    clean = _text(title, MAX_TITLE)
    if not clean:
        raise CaseError("a case needs a title")
    if severity not in SEVERITIES:
        raise CaseError("unknown severity")
    now = now_ms()
    cur = conn.execute(
        "INSERT INTO cases (title, description, severity, created_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (clean, _text(description), severity, actor, now, now),
    )
    case_id = cur.lastrowid
    assert case_id is not None  # noqa: S101
    audit.record(
        conn,
        "case.create",
        actor=actor,
        target=target(case_id),
        ip=ip,
        details={"title": clean, "severity": severity},
    )
    if alert_ids:
        add_alerts(conn, case_id, alert_ids, actor, ip)
    return case_id


def get(conn: sqlite3.Connection, case_id: int) -> Case | None:
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return _case(row) if row else None


def list_cases(conn: sqlite3.Connection, status: str | None = None) -> list[dict[str, Any]]:
    sql = (
        "SELECT c.*, (SELECT count(*) FROM case_alerts ca WHERE ca.case_id = c.id) AS n_alerts,"
        " (SELECT count(*) FROM case_iocs i WHERE i.case_id = c.id) AS n_iocs FROM cases c"
    )
    args: list[object] = []
    if status == "active":
        sql += " WHERE c.status != 'closed'"
    elif status in STATUSES:
        sql += " WHERE c.status = ?"
        args.append(status)
    sql += " ORDER BY c.updated_at DESC LIMIT 500"
    return [dict(r) for r in conn.execute(sql, args)]


def update(  # noqa: PLR0912 - one branch per editable field
    conn: sqlite3.Connection, case_id: int, actor: str, ip: str | None = None, **changes: str | None
) -> None:
    case = get(conn, case_id)
    if case is None:
        raise CaseError("case not found")
    sets: dict[str, object] = {}
    if "title" in changes:
        title = _text(changes["title"], MAX_TITLE)
        if not title:
            raise CaseError("a case needs a title")
        sets["title"] = title
    if "description" in changes:
        sets["description"] = _text(changes["description"])
    if "severity" in changes:
        if changes["severity"] not in SEVERITIES:
            raise CaseError("unknown severity")
        sets["severity"] = changes["severity"]
    if "status" in changes:
        if changes["status"] not in STATUSES:
            raise CaseError("unknown status")
        sets["status"] = changes["status"]
        sets["closed_at"] = now_ms() if changes["status"] == "closed" else None
    if "assignee" in changes:
        who = changes["assignee"] or None
        if (
            who
            and not conn.execute(
                "SELECT 1 FROM users WHERE username = ? AND disabled = 0", (who,)
            ).fetchone()
        ):
            raise CaseError("unknown or disabled user")
        sets["assignee"] = who
    for section in REPORT_SECTIONS:
        if section in changes:
            sets[section] = _text(changes[section])
    if not sets:
        return
    sets["updated_at"] = now_ms()
    assignments = ", ".join(f"{k} = ?" for k in sets)  # keys come from the fixed lists above
    conn.execute(
        f"UPDATE cases SET {assignments} WHERE id = ?",  # noqa: S608 - fixed keys
        (*sets.values(), case_id),
    )
    audit.record(
        conn,
        "case.update",
        actor=actor,
        target=target(case_id),
        ip=ip,
        details={
            k: (v if k in ("status", "severity", "assignee", "title") else "edited")
            for k, v in sets.items()
            if k != "updated_at"
        },
    )


def add_alerts(
    conn: sqlite3.Connection,
    case_id: int,
    alert_ids: Sequence[int],
    actor: str,
    ip: str | None = None,
) -> int:
    if get(conn, case_id) is None:
        raise CaseError("case not found")
    now = now_ms()
    added = 0
    for aid in alert_ids:
        if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (aid,)).fetchone() is None:
            continue
        cur = conn.execute(
            "INSERT OR IGNORE INTO case_alerts (case_id, alert_id, added_by, added_at) "
            "VALUES (?, ?, ?, ?)",
            (case_id, aid, actor, now),
        )
        added += cur.rowcount
    if added:
        conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
        audit.record(
            conn,
            "case.add_alerts",
            actor=actor,
            target=target(case_id),
            ip=ip,
            details={"alerts": list(alert_ids)[:100], "added": added},
        )
    return added


def remove_alert(
    conn: sqlite3.Connection, case_id: int, alert_id: int, actor: str, ip: str | None = None
) -> None:
    n = conn.execute(
        "DELETE FROM case_alerts WHERE case_id = ? AND alert_id = ?", (case_id, alert_id)
    ).rowcount
    if n:
        audit.record(
            conn,
            "case.remove_alert",
            actor=actor,
            target=target(case_id),
            ip=ip,
            details={"alert": alert_id},
        )


def case_alerts(conn: sqlite3.Connection, case_id: int) -> list[AlertRow]:
    return [
        alert_from_row(r)
        for r in conn.execute(
            "SELECT a.* FROM case_alerts ca JOIN alerts a ON a.id = ca.alert_id "
            "WHERE ca.case_id = ? ORDER BY a.first_seen",
            (case_id,),
        )
    ]


def cases_for_alert(conn: sqlite3.Connection, alert_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT c.id, c.title, c.status FROM case_alerts ca JOIN cases c ON c.id = ca.case_id "
        "WHERE ca.alert_id = ? ORDER BY c.id",
        (alert_id,),
    ).fetchall()


# ---------------------------------------------------------------- notes & annotations


def add_note(
    conn: sqlite3.Connection, case_id: int, author: str, body: str, ip: str | None = None
) -> None:
    text = _text(body)
    if not text:
        raise CaseError("note is empty")
    if get(conn, case_id) is None:
        raise CaseError("case not found")
    now = now_ms()
    conn.execute(
        "INSERT INTO case_notes (case_id, author, body, created_at) VALUES (?, ?, ?, ?)",
        (case_id, author, text, now),
    )
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
    audit.record(conn, "case.note", actor=author, target=target(case_id), ip=ip)


def notes(conn: sqlite3.Connection, case_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM case_notes WHERE case_id = ? ORDER BY id", (case_id,)
    ).fetchall()


def add_annotation(
    conn: sqlite3.Connection, case_id: int, ts: int, author: str, body: str, ip: str | None = None
) -> None:
    text = _text(body, 2000)
    if not text:
        raise CaseError("annotation is empty")
    if get(conn, case_id) is None:
        raise CaseError("case not found")
    conn.execute(
        "INSERT INTO case_annotations (case_id, ts, author, body, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (case_id, ts, author, text, now_ms()),
    )
    audit.record(conn, "case.annotate", actor=author, target=target(case_id), ip=ip)


def delete_annotation(
    conn: sqlite3.Connection, case_id: int, annotation_id: int, actor: str, ip: str | None = None
) -> None:
    n = conn.execute(
        "DELETE FROM case_annotations WHERE id = ? AND case_id = ?", (annotation_id, case_id)
    ).rowcount
    if not n:
        raise CaseError("annotation not found")
    audit.record(conn, "case.annotation_delete", actor=actor, target=target(case_id), ip=ip)


# ---------------------------------------------------------------- IOCs


def _ioc_kind_ok(kind: str, value: str) -> str | None:
    if kind == "file_hash" and not _HEX_HASH.match(value):
        return None
    return kind


def extract_iocs(conn: sqlite3.Connection, case_id: int, actor: str, ip: str | None = None) -> int:
    """(Re)build the automatic IOC list from every event of the case's alerts."""
    refs = conn.execute(
        "SELECT ae.table_name, ae.event_id, ae.event_ts FROM case_alerts ca "
        "JOIN alert_events ae ON ae.alert_id = ca.alert_id WHERE ca.case_id = ?",
        (case_id,),
    ).fetchall()
    found: dict[tuple[str, str], list[int]] = {}
    events = load_events(conn, [(r[0], r[1], r[2]) for r in refs])
    for ev in events:
        if ev.purged:
            continue
        for fld, kind in IOC_FIELDS.items():
            value = ev.fields.get(fld)
            if value in (None, "", "-"):
                continue
            text = str(value)[:MAX_IOC]
            k = _ioc_kind_ok(kind, text)
            if k is None:
                continue
            stats = found.setdefault((k, text), [0, ev.ts, ev.ts])
            stats[0] += 1
            stats[1] = min(stats[1], ev.ts)
            stats[2] = max(stats[2], ev.ts)
    now = now_ms()
    conn.execute("DELETE FROM case_iocs WHERE case_id = ? AND origin = 'auto'", (case_id,))
    conn.executemany(
        "INSERT INTO case_iocs (case_id, kind, value, origin, occurrences, first_seen, last_seen, "
        "added_at) VALUES (?, ?, ?, 'auto', ?, ?, ?, ?) ON CONFLICT (case_id, kind, value) DO "
        "UPDATE SET occurrences = excluded.occurrences, first_seen = excluded.first_seen, "
        "last_seen = excluded.last_seen",
        [(case_id, k, v, s[0], s[1], s[2], now) for (k, v), s in found.items()],
    )
    audit.record(
        conn,
        "case.extract_iocs",
        actor=actor,
        target=target(case_id),
        ip=ip,
        details={"iocs": len(found), "events": len(events)},
    )
    return len(found)


def add_ioc(
    conn: sqlite3.Connection,
    case_id: int,
    kind: str,
    value: str,
    note: str | None,
    actor: str,
    ip: str | None = None,
) -> None:
    if kind not in IOC_KINDS:
        raise CaseError("unknown IOC type")
    text = value.strip()
    if not text or len(text) > MAX_IOC:
        raise CaseError(f"IOC value must be 1-{MAX_IOC} characters")
    if _ioc_kind_ok(kind, text) is None:
        raise CaseError("a file hash must be an MD5, SHA-1 or SHA-256 hex string")
    if get(conn, case_id) is None:
        raise CaseError("case not found")
    conn.execute(
        "INSERT INTO case_iocs (case_id, kind, value, origin, note, added_by, added_at) "
        "VALUES (?, ?, ?, 'manual', ?, ?, ?) ON CONFLICT (case_id, kind, value) DO UPDATE SET "
        "note = excluded.note, origin = 'manual', added_by = excluded.added_by",
        (case_id, kind, text, _text(note, 2000), actor, now_ms()),
    )
    audit.record(
        conn,
        "case.add_ioc",
        actor=actor,
        target=target(case_id),
        ip=ip,
        details={"kind": kind, "value": text[:200]},
    )


def delete_ioc(
    conn: sqlite3.Connection, case_id: int, ioc_id: int, actor: str, ip: str | None = None
) -> None:
    n = conn.execute(
        "DELETE FROM case_iocs WHERE id = ? AND case_id = ?", (ioc_id, case_id)
    ).rowcount
    if not n:
        raise CaseError("IOC not found")
    audit.record(conn, "case.delete_ioc", actor=actor, target=target(case_id), ip=ip)


def iocs(conn: sqlite3.Connection, case_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM case_iocs WHERE case_id = ? ORDER BY kind, occurrences DESC, value",
        (case_id,),
    ).fetchall()


# ---------------------------------------------------------------- timeline


@dataclass(slots=True)
class TimelineEntry:
    ts: int
    kind: str  # alert | event | annotation
    title: str
    detail: str = ""
    alert: AlertRow | None = None
    event: EventView | None = None
    annotation_id: int | None = None
    author: str | None = None


def _event_summary(ev: EventView) -> str:
    """One readable line per event: the first pattern whose fields are all present."""
    f = ev.fields
    patterns = (
        ("url.original",),  # web logs: the whole request line ("GET /x HTTP/1.1")
        ("http.request.method", "url.path"),
        ("event.action", "user.name"),
        ("event.action", "file.name"),
        ("message",),
        ("event.action",),
    )
    for keys in patterns:
        if all(f.get(k) not in (None, "") for k in keys):
            who = f.get("source.ip")
            return (f"{who} " if who else "") + " ".join(str(f[k]) for k in keys)
    return ", ".join(f"{k}={v}" for k, v in list(f.items())[:4])


def timeline(
    conn: sqlite3.Connection, case_id: int, max_events: int = TIMELINE_EVENTS
) -> tuple[list[TimelineEntry], int]:
    """Alerts, their events and annotations, merged in event-time order.
    Returns (entries, number of events not shown because of the cap)."""
    entries: list[TimelineEntry] = []
    alerts = case_alerts(conn, case_id)
    for a in alerts:
        entries.append(
            TimelineEntry(
                a.first_seen,
                "alert",
                a.rule_title,
                f"{a.level} · {a.event_count} event(s)",
                alert=a,
            )
        )
    refs = conn.execute(
        "SELECT DISTINCT ae.table_name, ae.event_id, ae.event_ts FROM case_alerts ca "
        "JOIN alert_events ae ON ae.alert_id = ca.alert_id WHERE ca.case_id = ? "
        "ORDER BY ae.event_ts",
        (case_id,),
    ).fetchall()
    shown = refs[:max_events]
    for ev in load_events(conn, [(r[0], r[1], r[2]) for r in shown]):
        entries.append(
            TimelineEntry(
                ev.ts,
                "event",
                ev.table.removeprefix("ev_"),
                "(purged by retention)" if ev.purged else _event_summary(ev),
                event=ev,
            )
        )
    for r in conn.execute("SELECT * FROM case_annotations WHERE case_id = ?", (case_id,)):
        entries.append(
            TimelineEntry(
                r["ts"], "annotation", r["body"], annotation_id=r["id"], author=r["author"]
            )
        )
    order = {"annotation": 0, "alert": 1, "event": 2}
    entries.sort(key=lambda e: (e.ts, order[e.kind]))
    return entries, max(0, len(refs) - len(shown))


def attack_findings(alerts: Sequence[AlertRow]) -> list[dict[str, Any]]:
    """Group the case's alerts by ATT&CK technique tag (``attack.t1190`` ...)."""
    catalog = load_catalog()
    tactic_names = catalog.tactic_names()
    by_tech: dict[str, dict[str, Any]] = {}
    for a in alerts:
        tactics = [
            t.removeprefix("attack.") for t in a.tags if t.removeprefix("attack.") in tactic_names
        ]
        techniques = [
            t.removeprefix("attack.").upper()
            for t in a.tags
            if re.match(r"^attack\.t\d{4}(\.\d{3})?$", t)
        ] or ["(untagged)"]
        for tech in techniques:
            item = by_tech.setdefault(
                tech,
                {
                    "technique": tech,
                    "name": catalog.name(tech) if tech != "(untagged)" else "",
                    "tactics": set(),
                    "alerts": [],
                },
            )
            item["tactics"].update(tactics)
            item["alerts"].append(a)
    out = []
    for tech in sorted(by_tech):
        item = by_tech[tech]
        item["tactics"] = [tactic_names.get(t, t) for t in sorted(item["tactics"])]
        out.append(item)
    return out


def iocs_json(rows: Sequence[sqlite3.Row]) -> str:
    return json.dumps(
        [
            {
                k: r[k]
                for k in (
                    "kind",
                    "value",
                    "origin",
                    "note",
                    "occurrences",
                    "first_seen",
                    "last_seen",
                )
            }
            for r in rows
        ],
        indent=2,
        ensure_ascii=False,
    )
