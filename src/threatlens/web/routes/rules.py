"""Rules page (list, enable/disable, reload, details, tests, retro-hunt) and the
first version of the alert list (the full triage queue arrives in Phase 3)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response

from threatlens import audit
from threatlens.alerts.store import list_alerts
from threatlens.config import Settings
from threatlens.detection.compiler import CompiledRule
from threatlens.services import Services
from threatlens.storage.db import connect, transaction
from threatlens.web.deps import DbDep, SessionDep, SettingsDep, client_ip
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)


def _services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


def rule_rows(db: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = db.execute(
        "SELECT id, title, kind, origin, path, level, status, enabled, load_error, test_status, "
        "test_message, hits, alerts, last_fired_at, logsource, tags, warnings, "
        "correlation_only FROM rules "
        "ORDER BY origin DESC, title"
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["logsource"] = json.loads(r["logsource"])
        d["tags"] = json.loads(r["tags"])
        d["warnings"] = json.loads(r["warnings"])
        out.append(d)
    return out


def _rules_page(
    request: Request, db: sqlite3.Connection, message: str | None = None, error: str | None = None
) -> Response:
    rules = rule_rows(db)
    file_errors = db.execute("SELECT path, error FROM rule_load_errors ORDER BY path").fetchall()
    return render(
        request,
        "rules.html",
        {
            "active": "rules",
            "rules": rules,
            "file_errors": file_errors,
            "message": message,
            "error": error,
            "summary": {
                "total": len(rules),
                "enabled": sum(1 for r in rules if r["enabled"]),
                "errors": sum(1 for r in rules if r["load_error"]) + len(file_errors),
                "failing_tests": sum(1 for r in rules if r["test_status"] == "fail"),
            },
            "rules_dir": str(request.app.state.settings.rules_path),
        },
    )


@router.get("/rules")
def rules_page(request: Request, session: SessionDep, db: DbDep) -> Response:
    return _rules_page(request, db)


@router.post("/rules/reload")
def reload_rules(request: Request, session: SessionDep, db: DbDep) -> Response:
    services = _services(request)
    report = services.detection.reload(db, session.user.username)
    services.detection.run_tests(db)
    with transaction(db):
        audit.record(
            db,
            "rules.reload",
            actor=session.user.username,
            details={
                "loaded": report.loaded,
                "errors": report.errors,
                "file_errors": len(report.file_errors),
                "removed": report.removed,
            },
            ip=client_ip(request),
        )
    return _rules_page(
        request,
        db,
        message=f"Reloaded {report.loaded} rule(s): {report.errors} with errors, "
        f"{len(report.file_errors)} unreadable file(s), {report.removed} removed.",
    )


def _rule(db: sqlite3.Connection, rule_id: str) -> sqlite3.Row:
    row: sqlite3.Row | None = db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    return row


@router.post("/rules/{rule_id}/{action}")
def rule_action(
    request: Request,
    rule_id: str,
    action: str,
    session: SessionDep,
    db: DbDep,
    settings: SettingsDep,
) -> Response:
    row = _rule(db, rule_id)
    actor = session.user.username
    services = _services(request)
    if action in ("enable", "disable"):
        services.detection.set_enabled(db, rule_id, action == "enable", actor)
        with transaction(db):
            audit.record(
                db,
                f"rule.{action}",
                actor=actor,
                target=rule_id,
                details={"title": row["title"]},
                ip=client_ip(request),
            )
        if request.headers.get("hx-request"):
            return render(request, "_rule_toggle.html", {"r": dict(_rule(db, rule_id))})
        return RedirectResponse("/rules", status.HTTP_303_SEE_OTHER)
    if action == "test":
        services.detection.run_tests(db, rule_id)
        return RedirectResponse(f"/rules/{rule_id}", status.HTTP_303_SEE_OTHER)
    if action == "retro-hunt":
        if row["kind"] not in ("detection", "correlation") or row["load_error"]:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "this rule cannot run")
        job = services.worker.submit_task(
            f"retro-hunt: {row['title']}", _retro_task(settings, services, rule_id)
        )
        with transaction(db):
            audit.record(
                db,
                "rule.retro_hunt",
                actor=actor,
                target=rule_id,
                details={"job": job.id},
                ip=client_ip(request),
            )
        return RedirectResponse(f"/rules/{rule_id}?hunt={job.id}", status.HTTP_303_SEE_OTHER)
    raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown action")


def _retro_task(settings: Settings, services: Services, rule_id: str) -> Callable[[], str]:
    def task() -> str:
        conn = connect(settings.db_path)
        try:
            run = services.detection.retro_hunt(conn, rule_id)
        finally:
            conn.close()
        if run.errors:
            return "; ".join(run.errors.values())
        return (
            f"{run.result.events} new matching event(s), {len(run.result.new_alerts)} new alert(s)"
        )

    return task


@router.get("/rules/{rule_id}")
def rule_detail(
    request: Request, rule_id: str, session: SessionDep, db: DbDep, hunt: str | None = None
) -> Response:
    row = _rule(db, rule_id)
    engine = _services(request).detection
    compiled: list[CompiledRule | str] = engine.compiled_for(db, rule_id)
    correlation = engine.compiled_correlation_for(db, rule_id)
    referenced = []
    if correlation is not None and not isinstance(correlation, str):
        marks = ",".join("?" * len(correlation.base_rule_ids))
        referenced = db.execute(
            f"SELECT id, title FROM rules WHERE id IN ({marks})",  # noqa: S608 - placeholders only
            correlation.base_rule_ids,
        ).fetchall()
    job = _services(request).worker.get(hunt) if hunt else None
    return render(
        request,
        "rule.html",
        {
            "active": "rules",
            "r": dict(row),
            "tags": json.loads(row["tags"]),
            "logsource": json.loads(row["logsource"]),
            "warnings": json.loads(row["warnings"]),
            "compiled": [c for c in compiled if isinstance(c, CompiledRule)],
            "compile_errors": [c for c in compiled if isinstance(c, str)],
            "alerts": list_alerts(db, rule_id=rule_id, limit=20),
            "correlation": correlation if not isinstance(correlation, str) else None,
            "correlation_error": correlation if isinstance(correlation, str) else None,
            "referenced": referenced,
            "hunt": job,
        },
    )
