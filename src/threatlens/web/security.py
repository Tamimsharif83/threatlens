"""HTTP security controls: response headers, CSRF and cookie settings.

ThreatLens renders attacker-controlled text (log lines), so the browser is
told to run only our own static scripts (strict CSP, no inline code).
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import HTTPException, Request, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from threatlens.config import CookieSecure, Settings

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
# Swagger UI (API docs only, never renders log data) sets inline style attributes.
DOCS_CSP = CSP.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")
DOCS_PATH = "/docs"

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"


class SecurityHeadersMiddleware:
    """Pure-ASGI middleware adding security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        csp = DOCS_CSP if scope.get("path") == DOCS_PATH else CSP
        is_static = str(scope.get("path", "")).startswith("/static/")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                extra = {"Content-Security-Policy": csp, **SECURITY_HEADERS}
                if not is_static:
                    # Pages contain log data: never cache them on disk.
                    extra["Cache-Control"] = "no-store"
                for name, value in extra.items():
                    if name.lower().encode() not in present:
                        headers.append((name.lower().encode(), value.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


def cookie_secure(settings: Settings, request: Request) -> bool:
    if settings.cookie_secure is CookieSecure.ALWAYS:
        return True
    if settings.cookie_secure is CookieSecure.NEVER:
        return False
    return request.url.scheme == "https"


def cookie_name(base: str, secure: bool) -> str:
    """``__Host-`` prefixed names force Secure, Path=/ and no Domain in the browser."""
    return f"__Host-{base}" if secure else base


def cookie_options(secure: bool, max_age: int | None) -> dict[str, Any]:
    return {
        "httponly": True,
        "samesite": "strict",
        "secure": secure,
        "path": "/",
        "max_age": max_age,
    }


def new_token() -> str:
    return secrets.token_urlsafe(32)


def tokens_match(expected: str | None, supplied: str | None) -> bool:
    if not expected or not supplied:
        return False
    return secrets.compare_digest(expected.encode(), supplied.encode())


def check_same_origin(request: Request) -> None:
    """Reject state-changing requests that a browser marks as cross-site.

    Defence in depth on top of CSRF tokens and SameSite=Strict cookies.
    """
    if request.method in SAFE_METHODS:
        return
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site == "cross-site":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cross-site request refused")
    origin = request.headers.get("origin")
    if origin == "null":
        # Browsers send "Origin: null" for same-origin form posts when the page's
        # Referrer-Policy is no-referrer (ours is). It is also what a sandboxed
        # attacker frame sends, so only accept it when Fetch Metadata vouches for it.
        if fetch_site != "same-origin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "opaque-origin request refused")
        return
    if origin is not None:
        expected = f"{request.url.scheme}://{request.url.netloc}"
        if origin != expected:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "cross-origin request refused")


async def supplied_csrf_token(request: Request) -> str | None:
    """CSRF token from the ``X-CSRF-Token`` header (HTMX/API) or a form field."""
    header = request.headers.get(CSRF_HEADER)
    if header:
        return header
    content_type = request.headers.get("content-type", "")
    if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
        form = await request.form()
        value = form.get(CSRF_FORM_FIELD)
        return value if isinstance(value, str) else None
    return None
