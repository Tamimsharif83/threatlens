"""Analyst-facing HTML pages."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from threatlens import stats
from threatlens.alerts.store import counts_by_level, top_rules
from threatlens.storage.db import schema_version
from threatlens.timeutil import now_ms
from threatlens.web.deps import DbDep, SessionDep
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)


@router.get("/")
def overview(request: Request, session: SessionDep, db: DbDep) -> Response:
    return render(
        request,
        "overview.html",
        {
            "active": "overview",
            "schema_version": schema_version(db),
            "totals": stats.totals(db, now_ms()),
            "top_ips": stats.top_values(db, "source.ip", 10),
            "top_users": stats.top_values(db, "user.name", 10),
            "batches": stats.recent_batches(db, 8),
            "alert_counts": counts_by_level(db),
            "top_rules": top_rules(db, 8),
        },
    )
