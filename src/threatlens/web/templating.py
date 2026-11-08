"""Jinja2 environment. Autoescaping is always on; log data is never marked safe."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from starlette.responses import HTMLResponse

from threatlens import __version__
from threatlens.timeutil import ms_to_iso

TEMPLATE_DIR = Path(__file__).parent / "templates"


def build_templates() -> Jinja2Templates:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,  # every template, every extension
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["app_version"] = __version__
    # Relative URLs (work behind any reverse proxy) with a version for cache busting.
    env.globals["static"] = lambda path: f"/static/{path}?v={__version__}"
    env.filters["iso"] = ms_to_iso
    env.filters["dt"] = format_dt
    env.filters["num"] = format_num
    env.filters["bytes"] = format_bytes
    return Jinja2Templates(env=env)


def format_dt(ms: int | None) -> str:
    """``2026-11-08 10:00:00 UTC`` (or an em dash for missing values)."""
    if ms is None:
        return "\u2014"
    return ms_to_iso(ms).replace("T", " ")[:19] + " UTC"


def format_num(n: int | float | None) -> str:
    return "\u2014" if n is None else f"{n:,}"


def format_bytes(n: int | float | None) -> str:
    if n is None:
        return "\u2014"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"  # pragma: no cover


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    templates: Jinja2Templates = request.app.state.templates
    session = getattr(request.state, "session", None)
    ctx: dict[str, Any] = {
        "session": session,
        "user": session.user if session else None,
        "csrf_token": session.csrf_token if session else "",
        "active": "",
    }
    ctx.update(context or {})
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)
