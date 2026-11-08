"""Analyst-facing HTML pages."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from threatlens.storage.db import schema_version
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
        },
    )
