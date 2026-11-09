"""Cases: list, create (from alerts), case page, timeline, IOCs, notes, report export."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from starlette.datastructures import FormData

from threatlens.cases import store
from threatlens.export import to_csv
from threatlens.reports.render import SECTION_TITLES, render_html, render_markdown
from threatlens.storage.db import transaction
from threatlens.timeutil import ms_to_iso
from threatlens.web.deps import DbDep, SessionDep, client_ip
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _ids(form: FormData) -> list[int]:
    return [int(v) for v in form.getlist("ids") if isinstance(v, str) and v.isdigit()][:1000]


def _users(db: DbDep) -> list[str]:
    return [
        r[0] for r in db.execute("SELECT username FROM users WHERE disabled = 0 ORDER BY username")
    ]


@router.get("/cases")
def cases_page(
    request: Request, session: SessionDep, db: DbDep, status_filter: str = "active"
) -> Response:
    return render(
        request,
        "cases.html",
        {
            "active": "cases",
            "cases": store.list_cases(db, status_filter),
            "status_filter": status_filter,
            "statuses": store.STATUSES,
            "severities": store.SEVERITIES,
            "message": request.query_params.get("msg"),
        },
    )


@router.post("/cases")
async def create_case(request: Request, session: SessionDep, db: DbDep) -> Response:
    form = await request.form(max_files=0, max_fields=1100)
    ids = _ids(form)
    existing = str(form.get("case_id", ""))
    actor, ip = session.user.username, client_ip(request)
    try:
        with transaction(db):
            if existing.isdigit():
                case_id = int(existing)
                store.add_alerts(db, case_id, ids, actor, ip)
            else:
                title = str(form.get("title", "")).strip()
                if not title and ids:
                    first = db.execute(
                        "SELECT rule_title FROM alerts WHERE id = ?", (ids[0],)
                    ).fetchone()
                    title = f"Investigation: {first[0]}" if first else ""
                case_id = store.create(
                    db,
                    title=title,
                    severity=str(form.get("severity", "medium")),
                    description=str(form.get("description", "")) or None,
                    actor=actor,
                    alert_ids=ids,
                    ip=ip,
                )
    except store.CaseError as exc:
        return RedirectResponse(f"/cases?msg={quote(str(exc))}", status.HTTP_303_SEE_OTHER)
    return RedirectResponse(f"/cases/{case_id}", status.HTTP_303_SEE_OTHER)


def _case_or_404(db: DbDep, case_id: int) -> store.Case:
    case = store.get(db, case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
    return case


@router.get("/cases/{case_id}")
def case_page(request: Request, case_id: int, session: SessionDep, db: DbDep) -> Response:
    case = _case_or_404(db, case_id)
    entries, hidden = store.timeline(db, case_id)
    alerts = store.case_alerts(db, case_id)
    return render(
        request,
        "case.html",
        {
            "active": "cases",
            "case": case,
            "alerts": alerts,
            "findings": store.attack_findings(alerts),
            "timeline": entries,
            "timeline_hidden": hidden,
            "iocs": store.iocs(db, case_id),
            "ioc_kinds": store.IOC_KINDS,
            "notes": store.notes(db, case_id),
            "statuses": store.STATUSES,
            "severities": store.SEVERITIES,
            "users": _users(db),
            "sections": SECTION_TITLES,
            "error": request.query_params.get("error"),
            "message": request.query_params.get("msg"),
        },
    )


def _parse_ts(value: str) -> int:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise store.CaseError("invalid time (use the date picker, UTC)") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp() * 1000)


@router.post("/cases/{case_id}/{action}")
async def case_action(
    request: Request, case_id: int, action: str, session: SessionDep, db: DbDep
) -> Response:
    _case_or_404(db, case_id)
    form = await request.form(max_files=0, max_fields=40)
    actor, ip = session.user.username, client_ip(request)
    msg = None
    anchor = ""
    try:
        with transaction(db):
            if action == "update":
                fields = {
                    k: str(form.get(k))
                    for k in ("title", "severity", "status", "assignee", "description")
                    if k in form
                }
                store.update(db, case_id, actor, ip, **fields)
                msg = "Case updated."
            elif action == "report":
                fields = {k: str(form.get(k, "")) for k in SECTION_TITLES if k in form}
                store.update(db, case_id, actor, ip, **fields)
                msg, anchor = "Report sections saved.", "#report"
            elif action == "note":
                store.add_note(db, case_id, actor, str(form.get("body", "")), ip)
                anchor = "#notes"
            elif action == "annotate":
                store.add_annotation(
                    db,
                    case_id,
                    _parse_ts(str(form.get("ts", ""))),
                    actor,
                    str(form.get("body", "")),
                    ip,
                )
                anchor = "#timeline"
            elif action == "delete-annotation":
                store.delete_annotation(
                    db, case_id, int(str(form.get("annotation_id", "0"))), actor, ip
                )
                anchor = "#timeline"
            elif action == "remove-alert":
                store.remove_alert(db, case_id, int(str(form.get("alert_id", "0"))), actor, ip)
            elif action == "extract-iocs":
                n = store.extract_iocs(db, case_id, actor, ip)
                msg, anchor = f"{n} IOC(s) extracted from the case's events.", "#iocs"
            elif action == "add-ioc":
                store.add_ioc(
                    db,
                    case_id,
                    str(form.get("kind", "")),
                    str(form.get("value", "")),
                    str(form.get("note", "")) or None,
                    actor,
                    ip,
                )
                anchor = "#iocs"
            elif action == "delete-ioc":
                store.delete_ioc(db, case_id, int(str(form.get("ioc_id", "0"))), actor, ip)
                anchor = "#iocs"
            else:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown action")
    except (store.CaseError, ValueError) as exc:
        return RedirectResponse(
            f"/cases/{case_id}?error={quote(str(exc))}", status.HTTP_303_SEE_OTHER
        )
    suffix = f"?msg={quote(msg)}" if msg else ""
    return RedirectResponse(f"/cases/{case_id}{suffix}{anchor}", status.HTTP_303_SEE_OTHER)


def _filename(case: store.Case, ext: str) -> str:
    slug = _SAFE_NAME.sub("-", case.title.lower()).strip("-")[:60] or "case"
    return f"threatlens-case-{case.id}-{slug}.{ext}"


def _download(body: str, media: str, name: str) -> Response:
    return Response(
        body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'}
    )


@router.get("/cases/{case_id}/report.md")
def report_md(case_id: int, session: SessionDep, db: DbDep) -> Response:
    case = _case_or_404(db, case_id)
    return _download(
        render_markdown(db, case_id), "text/markdown; charset=utf-8", _filename(case, "md")
    )


@router.get("/cases/{case_id}/report.html")
def report_html(case_id: int, session: SessionDep, db: DbDep) -> Response:
    case = _case_or_404(db, case_id)
    return _download(render_html(db, case_id), "text/html; charset=utf-8", _filename(case, "html"))


@router.get("/cases/{case_id}/iocs.{fmt}")
def export_iocs(case_id: int, fmt: str, session: SessionDep, db: DbDep) -> Response:
    case = _case_or_404(db, case_id)
    rows = store.iocs(db, case_id)
    if fmt == "json":
        return _download(store.iocs_json(rows), "application/json", _filename(case, "iocs.json"))
    if fmt == "csv":
        body = to_csv(
            ["type", "value", "origin", "occurrences", "first_seen", "last_seen", "note"],
            [
                [
                    r["kind"],
                    r["value"],
                    r["origin"],
                    r["occurrences"],
                    ms_to_iso(r["first_seen"]) if r["first_seen"] else "",
                    ms_to_iso(r["last_seen"]) if r["last_seen"] else "",
                    r["note"] or "",
                ]
                for r in rows
            ],
        )
        return _download(body, "text/csv; charset=utf-8", _filename(case, "iocs.csv"))
    raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown format")
