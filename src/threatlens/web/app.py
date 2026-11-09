"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from threatlens import __version__
from threatlens.auth.sessions import purge_expired
from threatlens.auth.throttle import LoginThrottle
from threatlens.auth.users import bootstrap_admin
from threatlens.config import Settings
from threatlens.services import Services
from threatlens.storage.db import connect, init_db, transaction
from threatlens.web.deps import NotAuthenticatedError, PasswordChangeRequiredError
from threatlens.web.limits import BodySizeLimitMiddleware
from threatlens.web.routes import api, auth, ingest, pages, rules
from threatlens.web.routes import settings as settings_routes
from threatlens.web.security import SecurityHeadersMiddleware
from threatlens.web.templating import build_templates, render

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"


def prepare_storage(settings: Settings) -> None:
    """Create directories, migrate the schema and bootstrap the first admin."""
    settings.ensure_dirs()
    init_db(settings.db_path)
    conn = connect(settings.db_path)
    try:
        with transaction(conn):
            bootstrap_admin(conn, settings)
            purge_expired(conn)
    finally:
        conn.close()


def _wants_html(request: Request) -> bool:
    """API paths get JSON errors; everything else is a page for a browser."""
    path = request.url.path
    return not (path.startswith("/api/") or path in {"/openapi.json", "/healthz"})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    services = Services(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        prepare_storage(settings)
        services.start()
        log.info("ThreatLens started", extra={"version": __version__, "port": settings.port})
        try:
            yield
        finally:
            services.stop()

    app = FastAPI(
        title="ThreatLens",
        version=__version__,
        description="Self-hosted detection & investigation platform. "
        "Authenticate by logging in through the web UI; state-changing calls need the "
        "`X-CSRF-Token` header.",
        lifespan=lifespan,
        # Served by our own authenticated routes with vendored assets (no CDN).
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.services = services
    app.state.templates = build_templates()
    app.state.throttle = LoginThrottle(
        settings.login_max_failures, settings.login_window_minutes * 60
    )

    # Order: the last added runs first, so security headers wrap everything (even 413s).
    app.add_middleware(
        BodySizeLimitMiddleware,
        upload_paths={"/ingest/upload": settings.max_upload_mb * 1024 * 1024},
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(auth.router)
    app.include_router(pages.router)
    app.include_router(ingest.router)
    app.include_router(rules.router)
    app.include_router(settings_routes.router)
    app.include_router(api.router)
    app.include_router(api.docs_router)

    @app.exception_handler(NotAuthenticatedError)
    async def _not_authenticated(request: Request, exc: NotAuthenticatedError) -> Response:
        if not _wants_html(request):
            return JSONResponse({"detail": "not authenticated"}, status.HTTP_401_UNAUTHORIZED)
        target = request.url.path
        if request.url.query:
            target += f"?{request.url.query}"
        login = f"/login?next={quote(target, safe='/')}" if target != "/" else "/login"
        if request.headers.get("hx-request"):
            # HTMX swaps would otherwise render the login page inside a fragment.
            return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"HX-Redirect": login})
        return RedirectResponse(login, status.HTTP_303_SEE_OTHER)

    @app.exception_handler(PasswordChangeRequiredError)
    async def _password_change(request: Request, exc: PasswordChangeRequiredError) -> Response:
        if not _wants_html(request):
            return JSONResponse({"detail": "password change required"}, status.HTTP_403_FORBIDDEN)
        if request.headers.get("hx-request"):
            return Response(
                status_code=status.HTTP_204_NO_CONTENT, headers={"HX-Redirect": "/account"}
            )
        return RedirectResponse("/account", status.HTTP_303_SEE_OTHER)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> Response:
        if not _wants_html(request):
            return JSONResponse(
                {"detail": exc.detail}, exc.status_code, headers=getattr(exc, "headers", None)
            )
        return render(
            request,
            "error.html",
            {"status_code": exc.status_code, "detail": str(exc.detail)},
            status_code=exc.status_code,
        )

    return app
