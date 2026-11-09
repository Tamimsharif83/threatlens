"""Tuning: suppressions (allowlist) and the Sigma filters in effect, plus the audit log."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response

from threatlens import audit
from threatlens.alerts import suppress
from threatlens.services import Services
from threatlens.storage.db import transaction
from threatlens.web.deps import AdminDep, DbDep, SessionDep, client_ip
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)
AUDIT_PAGE = 200


def _page(
    request: Request,
    db: sqlite3.Connection,
    *,
    error: str | None = None,
    form: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    rules = db.execute("SELECT id, title FROM rules WHERE kind = 'detection' ORDER BY title")
    filters = db.execute(
        "SELECT id, title, path, yaml, load_error FROM sigma_filters ORDER BY title"
    ).fetchall()
    return render(
        request,
        "tuning.html",
        {
            "active": "tuning",
            "suppressions": suppress.list_all(db),
            "rules": rules.fetchall(),
            "filters": filters,
            "error": error,
            "message": request.query_params.get("msg"),
            "form": form
            or {
                k: v for k, v in request.query_params.items() if k in ("rule_id", "field", "value")
            },
            "now": int(datetime.now(UTC).timestamp() * 1000),
        },
        status_code=status_code,
    )


@router.get("/tuning")
def tuning_page(request: Request, session: SessionDep, db: DbDep) -> Response:
    return _page(request, db)


@router.post("/tuning/suppressions")
async def create_suppression(request: Request, session: SessionDep, db: DbDep) -> Response:
    form = await request.form(max_files=0, max_fields=20)
    data = {k: str(form.get(k, "")) for k in ("rule_id", "field", "value", "reason", "expires")}
    expires_at = None
    if data["expires"]:
        try:
            expires_at = int(
                datetime.fromisoformat(data["expires"]).replace(tzinfo=UTC).timestamp() * 1000
            )
        except ValueError:
            return _page(request, db, error="Invalid expiry date.", form=data, status_code=400)
    try:
        with transaction(db):
            suppress.create(
                db,
                rule_id=data["rule_id"] or None,
                field=data["field"],
                value=data["value"],
                reason=data["reason"],
                actor=session.user.username,
                expires_at=expires_at,
                ip=client_ip(request),
            )
    except suppress.SuppressionError as exc:
        return _page(request, db, error=str(exc), form=data, status_code=400)
    return RedirectResponse(f"/tuning?msg={quote('Suppression added.')}", status.HTTP_303_SEE_OTHER)


@router.post("/tuning/suppressions/{sid}/{action}")
def suppression_action(
    request: Request, sid: int, action: str, session: SessionDep, db: DbDep
) -> Response:
    try:
        with transaction(db):
            if action in ("enable", "disable"):
                suppress.set_enabled(
                    db, sid, action == "enable", session.user.username, client_ip(request)
                )
            elif action == "delete":
                suppress.delete(db, sid, session.user.username, client_ip(request))
            else:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown action")
    except suppress.SuppressionError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return RedirectResponse(
        f"/tuning?msg={quote(f'Suppression {action}d.')}", status.HTTP_303_SEE_OTHER
    )


@router.post("/tuning/reload")
def reload_filters(request: Request, session: SessionDep, db: DbDep) -> Response:
    services: Services = request.app.state.services
    report = services.detection.reload(db, session.user.username)
    with transaction(db):
        audit.record(
            db,
            "rules.reload",
            actor=session.user.username,
            ip=client_ip(request),
            details={"loaded": report.loaded, "filters": report.filters},
        )
    return RedirectResponse(
        f"/tuning?msg={quote(f'Reloaded {report.loaded} rules and {report.filters} filters.')}",
        status.HTTP_303_SEE_OTHER,
    )


@router.get("/audit")
def audit_page(
    request: Request,
    session: AdminDep,
    db: DbDep,
    action: str | None = None,
    actor: str | None = None,
    before: int | None = None,
) -> Response:
    where: list[str] = []
    args: list[object] = []
    if action:
        where.append("action LIKE ? ESCAPE '\\'")
        args.append(action.replace("%", "\\%").replace("_", "\\_") + "%")
    if actor:
        where.append("actor = ?")
        args.append(actor)
    if before:
        where.append("id < ?")
        args.append(before)
    sql = "SELECT id, ts, actor, action, target, details, ip FROM audit_log"
    if where:
        sql += " WHERE " + " AND ".join(where)
    rows = db.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, AUDIT_PAGE + 1)).fetchall()
    entries = [
        audit.AuditEntry(r[0], r[1], r[2], r[3], r[4], json.loads(r[5] or "{}"), r[6])
        for r in rows[:AUDIT_PAGE]
    ]
    return render(
        request,
        "audit.html",
        {
            "active": "audit",
            "entries": entries,
            "more": len(rows) > AUDIT_PAGE,
            "action": action or "",
            "actor": actor or "",
        },
    )
