"""Alert queue and alert detail (triage)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from starlette.datastructures import FormData

from threatlens.alerts.store import LEVELS, AlertRow, counts_by_level, get_alert, linked_alerts
from threatlens.alerts.triage import (
    RESOLUTIONS,
    STATUSES,
    TriageError,
    add_note,
    alert_events,
    assign,
    history,
    notes,
    set_status,
)
from threatlens.services import Services
from threatlens.storage.db import transaction
from threatlens.web.deps import DbDep, SessionDep, client_ip
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)
SORTS = {
    "last_seen": "last_seen DESC",
    "first_seen": "first_seen DESC",
    "severity": "CASE level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
    "WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC",
    "events": "event_count DESC",
}
PAGE = 100
HOUR_MS = 3_600_000


def _users(db: sqlite3.Connection) -> list[str]:
    return [
        r[0] for r in db.execute("SELECT username FROM users WHERE disabled = 0 ORDER BY username")
    ]


def _queue(db: sqlite3.Connection, params: dict[str, str], me: str) -> list[dict[str, Any]]:
    where, args = [], []
    st = params.get("status", "open")
    if st == "open":
        where.append("status != 'closed'")
    elif st in STATUSES:
        where.append("status = ?")
        args.append(st)
    if params.get("level") in LEVELS:
        where.append("level = ?")
        args.append(params["level"])
    if params.get("rule"):
        where.append("rule_id = ?")
        args.append(params["rule"])
    assignee = params.get("assignee", "")
    if assignee == "me":
        where.append("assignee = ?")
        args.append(me)
    elif assignee == "none":
        where.append("assignee IS NULL")
    elif assignee:
        where.append("assignee = ?")
        args.append(assignee)
    if params.get("q"):
        where.append("(entities LIKE ? ESCAPE '\\' OR rule_title LIKE ? ESCAPE '\\')")
        q = "%" + params["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args += [q, q]
    sql = "SELECT * FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {SORTS.get(params.get('sort', ''), SORTS['last_seen'])} LIMIT {PAGE}"
    out = []
    for r in db.execute(sql, args):
        d = dict(r)
        d["entities"] = json.loads(r["entities"])
        out.append(d)
    return out


@router.get("/alerts")
def alerts_page(request: Request, session: SessionDep, db: DbDep) -> Response:
    params = {k: v[:200] for k, v in request.query_params.items()}
    params.setdefault("status", "open")
    rules = db.execute("SELECT DISTINCT rule_id, rule_title FROM alerts ORDER BY rule_title")
    return render(
        request,
        "alerts.html",
        {
            "active": "alerts",
            "alerts": _queue(db, params, session.user.username),
            "counts": counts_by_level(db),
            "levels": list(reversed(LEVELS)),
            "statuses": STATUSES,
            "resolutions": RESOLUTIONS,
            "params": params,
            "rules": rules.fetchall(),
            "users": _users(db),
            "page_size": PAGE,
            "message": request.query_params.get("msg"),
        },
    )


def _ids(form: FormData) -> list[int]:
    ids = []
    for v in form.getlist("ids"):
        if isinstance(v, str) and v.isdigit():
            ids.append(int(v))
    return ids[:1000]


def _apply(
    db: sqlite3.Connection, form: FormData, ids: list[int], actor: str, ip: str | None
) -> str:
    action = str(form.get("action", ""))
    if action == "status":
        new_status = str(form.get("status", ""))
        resolution = str(form.get("resolution", "")) or None
        with transaction(db):
            n = set_status(db, ids, new_status, resolution, actor, ip)
        return f"{n} alert(s) set to {new_status.replace('_', ' ')}."
    if action == "assign":
        who = str(form.get("assignee", ""))
        target = actor if who == "me" else (who or None)
        with transaction(db):
            n = assign(db, ids, target, actor, ip)
        return f"{n} alert(s) assigned to {target or 'nobody'}."
    raise TriageError("unknown action")


@router.post("/alerts/bulk")
async def bulk(request: Request, session: SessionDep, db: DbDep) -> Response:
    form = await request.form(max_files=0, max_fields=1100)
    ids = _ids(form)
    back = str(form.get("back", "/alerts"))
    if not back.startswith("/alerts"):
        back = "/alerts"
    if not ids:
        message = "Select at least one alert."
    else:
        try:
            message = _apply(db, form, ids, session.user.username, client_ip(request))
        except TriageError as exc:
            message = str(exc)
    sep = "&" if "?" in back else "?"
    return RedirectResponse(f"{back}{sep}msg={quote(message)}", status.HTTP_303_SEE_OTHER)


def _alert_or_404(db: sqlite3.Connection, alert_id: int) -> AlertRow:
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    return alert


@router.get("/alerts/{alert_id}")
def alert_detail(
    request: Request, alert_id: int, session: SessionDep, db: DbDep, error: str | None = None
) -> Response:
    alert = _alert_or_404(db, alert_id)
    services: Services = request.app.state.services
    compiled = [
        c for c in services.detection.compiled_for(db, alert.rule_id) if not isinstance(c, str)
    ]
    rule_fields = sorted({f for c in compiled for f in c.fields})
    corr = services.detection.compiled_correlation_for(db, alert.rule_id)
    if corr is not None and not isinstance(corr, str):
        rule_fields = sorted(
            {f for fs in corr.required_fields.values() for f in fs if not f.startswith("tl_")}
        )
    children, parents = linked_alerts(db, alert_id)
    rule = db.execute(
        "SELECT yaml, description, load_error FROM rules WHERE id = ?", (alert.rule_id,)
    ).fetchone()
    events = alert_events(db, alert_id)
    pivots = []
    for name, value in alert.entities.items():
        pivots.append(
            {
                "field": name,
                "value": value,
                "start": alert.first_seen - HOUR_MS,
                "end": alert.last_seen + HOUR_MS,
            }
        )
    return render(
        request,
        "alert.html",
        {
            "active": "alerts",
            "a": alert,
            "rule": rule,
            "rule_fields": rule_fields,
            "events": events,
            "events_total": alert.event_count,
            "notes": notes(db, alert_id),
            "history": history(db, alert_id),
            "statuses": STATUSES,
            "resolutions": RESOLUTIONS,
            "users": _users(db),
            "pivots": pivots,
            "tables": sorted({e.table for e in events}),
            "error": error,
            "children": children,
            "parents": parents,
        },
    )


@router.post("/alerts/{alert_id}/{action}")
async def alert_action(
    request: Request, alert_id: int, action: str, session: SessionDep, db: DbDep
) -> Response:
    _alert_or_404(db, alert_id)
    form = await request.form(max_files=0, max_fields=20)
    actor, ip = session.user.username, client_ip(request)
    error = None
    try:
        if action == "note":
            with transaction(db):
                add_note(db, alert_id, actor, str(form.get("body", "")), ip)
        elif action in ("status", "assign"):
            _apply(db, form, [alert_id], actor, ip)
        else:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown action")
    except TriageError as exc:
        error = str(exc)
    if error:
        return RedirectResponse(
            f"/alerts/{alert_id}?error={quote(error)}", status.HTTP_303_SEE_OTHER
        )
    return RedirectResponse(f"/alerts/{alert_id}", status.HTTP_303_SEE_OTHER)
