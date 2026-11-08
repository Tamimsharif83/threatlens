"""JSON REST API (v1). Uses the same session cookie as the UI; unsafe methods
need the ``X-CSRF-Token`` header."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from threatlens import __version__
from threatlens.web.deps import DbDep, SessionDep
from threatlens.web.templating import render

router = APIRouter()


class Health(BaseModel):
    status: Literal["ok"]
    version: str


class Me(BaseModel):
    username: str
    role: str


@router.get("/healthz", tags=["system"])
def healthz(db: DbDep) -> Health:
    """Liveness/readiness probe (no authentication; reveals nothing sensitive)."""
    db.execute("SELECT 1").fetchone()
    return Health(status="ok", version=__version__)


@router.get("/api/v1/me", tags=["auth"])
def me(session: SessionDep) -> Me:
    """The currently logged-in user."""
    return Me(username=session.user.username, role=session.user.role.value)


# ---- API documentation (requires login; assets are vendored, no CDN)

docs_router = APIRouter(include_in_schema=False)


@docs_router.get("/openapi.json")
def openapi_schema(request: Request, session: SessionDep) -> dict[str, object]:
    schema: dict[str, object] = request.app.openapi()
    return schema


@docs_router.get("/docs")
def swagger_ui(request: Request, session: SessionDep) -> HTMLResponse:
    return render(request, "docs.html")
