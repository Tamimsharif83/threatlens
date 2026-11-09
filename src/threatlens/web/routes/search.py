"""Search & Hunt: field-filter search, event view, read-only SQL hunt console,
saved hunts and CSV export."""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse, Response

from threatlens import audit
from threatlens.alerts.triage import event_view
from threatlens.auth.users import Role
from threatlens.export import to_csv
from threatlens.search.hunt import HuntResult, run_hunt
from threatlens.search.query import (
    OPERATORS,
    Condition,
    SearchError,
    SearchRequest,
    fields_of,
    search,
)
from threatlens.storage.db import transaction
from threatlens.storage.events import ID, EventStore, quote_ident
from threatlens.timeutil import now_ms
from threatlens.web.deps import DbDep, SessionDep, SettingsDep, client_ip
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)
CONDITION_ROWS = 4
ATTACK_TAG = re.compile(r"^attack\.[a-z0-9._-]{1,60}$")
EXAMPLE_HUNT = (
    "-- Read-only SQL over the event tables (ev_*). Field names are columns: quote them.\n"
    'SELECT "source.ip", count(*) AS requests, count(DISTINCT "url.path") AS paths\n'
    "FROM ev_webserver\n"
    'WHERE "http.response.status_code" >= 400\n'
    'GROUP BY "source.ip"\n'
    "ORDER BY requests DESC\n"
    "LIMIT 20"
)


MAX_MS = 253_402_300_799_999  # 9999-12-31T23:59:59.999Z, the last datetime Python renders


def _parse_time(value: str | None) -> int | None:
    """Accept unix ms (pivot links) or a datetime-local value, read as UTC."""
    if not value:
        return None
    if value.isascii() and value.isdigit():  # "²".isdigit() is True too
        ms = int(value[:20])
        return ms if ms <= MAX_MS else None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return int(dt.timestamp() * 1000)
    except (ValueError, OverflowError, OSError):
        return None


def _local(ms: int | None) -> str:
    if ms is None:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S")


@router.get("/search")
def search_page(request: Request, session: SessionDep, db: DbDep) -> Response:
    q = request.query_params
    tables = EventStore(db).event_tables()
    table = q.get("table") or (tables[0] if tables else "")
    conditions = []
    for i in range(1, CONDITION_ROWS + 1):
        f = (q.get(f"f{i}") or "").strip()
        if f:
            conditions.append(Condition(f, q.get(f"op{i}") or "eq", q.get(f"v{i}") or ""))
    start, end = _parse_time(q.get("start")), _parse_time(q.get("end"))
    result, error = None, None
    if q.get("run") and table:
        try:
            limit = int(q.get("limit") or 200)
        except ValueError:
            limit = 200
        try:
            result = search(
                db,
                SearchRequest(
                    table, conditions, start, end, limit, newest_first=q.get("order") != "asc"
                ),
            )
        except SearchError as exc:
            error = str(exc)
    rows = [
        *conditions,
        *[Condition("", "eq", "") for _ in range(CONDITION_ROWS - len(conditions))],
    ]
    return render(
        request,
        "search.html",
        {
            "active": "hunt",
            "tables": tables,
            "table": table,
            "fields": fields_of(db, table) if table in tables else [],
            "rows": rows,
            "operators": OPERATORS,
            "start": _local(start),
            "end": _local(end),
            "limit": q.get("limit") or "200",
            "order": q.get("order") or "desc",
            "result": result,
            "error": error,
        },
    )


@router.get("/events/{table}/{event_id}")
def event_page(
    request: Request, table: str, event_id: int, session: SessionDep, db: DbDep
) -> Response:
    if table not in EventStore(db).event_tables():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown event table")
    row = db.execute(
        f"SELECT * FROM {quote_ident(table)} WHERE {ID} = ?",  # noqa: S608 - catalog table
        (event_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "event not found (purged?)")
    view = event_view(db, table, row)
    batch = db.execute(
        "SELECT b.id, b.file_name, b.origin, s.name FROM ingest_batches b "
        "JOIN sources s ON s.id = b.source_id WHERE b.id = ?",
        (row["tl_batch"],),
    ).fetchone()
    alerts = db.execute(
        "SELECT a.id, a.rule_title, a.level FROM alert_events ae JOIN alerts a ON a.id = "
        "ae.alert_id WHERE ae.table_name = ? AND ae.event_id = ?",
        (table, event_id),
    ).fetchall()
    return render(
        request,
        "event.html",
        {"active": "hunt", "e": view, "batch": batch, "record": row["tl_record"], "alerts": alerts},
    )


# ---------------------------------------------------------------- hunt console


def _saved(db: sqlite3.Connection) -> list[sqlite3.Row]:
    return db.execute("SELECT * FROM saved_hunts ORDER BY name").fetchall()


def _hunt_page(
    request: Request,
    db: sqlite3.Connection,
    sql: str,
    *,
    result: HuntResult | None = None,
    message: str | None = None,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    store = EventStore(db)
    schema = {t: fields_of(db, t) for t in store.event_tables()}
    return render(
        request,
        "hunt.html",
        {
            "active": "hunt",
            "sql": sql,
            "result": result,
            "saved": _saved(db),
            "schema": schema,
            "message": message,
            "error": error,
            "limits": request.app.state.settings,
        },
        status_code=status_code,
    )


@router.get("/hunt")
def hunt_page(
    request: Request, session: SessionDep, db: DbDep, saved: int | None = None
) -> Response:
    sql = EXAMPLE_HUNT
    if saved is not None:
        row = db.execute("SELECT sql FROM saved_hunts WHERE id = ?", (saved,)).fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "saved hunt not found")
        sql = row[0]
    return _hunt_page(request, db, sql)


@router.post("/hunt")
async def hunt_run(
    request: Request, session: SessionDep, db: DbDep, settings: SettingsDep
) -> Response:
    form = await request.form(max_files=0, max_fields=20)
    sql = str(form.get("sql", ""))[:20_000]
    # In a worker thread: a query may run for the whole time limit.
    result = await run_in_threadpool(
        run_hunt,
        settings.db_path,
        sql,
        row_limit=settings.hunt_row_limit,
        timeout_s=settings.hunt_timeout_seconds,
        admin=session.user.role is Role.ADMIN,
    )
    with transaction(db):
        audit.record(
            db,
            "hunt.run",
            actor=session.user.username,
            ip=client_ip(request),
            details={"sql": sql[:2000], "rows": len(result.rows), "error": result.error},
        )
    if form.get("format") == "csv" and result.error is None:
        body = to_csv(result.columns, result.rows)
        return Response(
            body,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="threatlens-hunt.csv"'},
        )
    return _hunt_page(request, db, sql, result=result, status_code=400 if result.error else 200)


@router.post("/hunt/saved")
async def save_hunt(request: Request, session: SessionDep, db: DbDep) -> Response:
    form = await request.form(max_files=0, max_fields=20)
    name = str(form.get("name", "")).strip()[:120]
    sql = str(form.get("sql", "")).strip()[:20_000]
    description = str(form.get("description", "")).strip()[:2000] or None
    tag = str(form.get("attack_tag", "")).strip().lower() or None
    error = None
    if not name or not sql:
        error = "A saved hunt needs a name and a query."
    elif tag and not ATTACK_TAG.match(tag):
        error = "ATT&CK tag must look like attack.t1110 or attack.credential-access."
    if error:
        return _hunt_page(request, db, sql, error=error, status_code=400)
    now = now_ms()
    with transaction(db):
        db.execute(
            "INSERT INTO saved_hunts (name, description, attack_tag, sql, created_by, created_at, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (name) DO UPDATE SET "
            "description = excluded.description, attack_tag = excluded.attack_tag, "
            "sql = excluded.sql, updated_at = excluded.updated_at",
            (name, description, tag, sql, session.user.username, now, now),
        )
        audit.record(
            db, "hunt.save", actor=session.user.username, target=name, ip=client_ip(request)
        )
    return _hunt_page(request, db, sql, message=f"Saved hunt '{name}'.")


@router.post("/hunt/saved/{hunt_id}/delete")
def delete_hunt(request: Request, hunt_id: int, session: SessionDep, db: DbDep) -> Response:
    with transaction(db):
        row = db.execute("SELECT name FROM saved_hunts WHERE id = ?", (hunt_id,)).fetchone()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "saved hunt not found")
        db.execute("DELETE FROM saved_hunts WHERE id = ?", (hunt_id,))
        audit.record(
            db, "hunt.delete", actor=session.user.username, target=row[0], ip=client_ip(request)
        )
    return RedirectResponse(f"/hunt?msg={quote('deleted')}", status.HTTP_303_SEE_OTHER)
