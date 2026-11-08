"""Login and logout."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response

from threatlens import audit
from threatlens.auth.sessions import create_session, delete_session
from threatlens.auth.throttle import LoginThrottle
from threatlens.auth.users import authenticate
from threatlens.storage.db import transaction
from threatlens.web.deps import (
    DbDep,
    SessionDep,
    SettingsDep,
    client_ip,
    optional_session,
    session_cookie_name,
    session_token,
)
from threatlens.web.security import (
    check_same_origin,
    cookie_name,
    cookie_options,
    cookie_secure,
    new_token,
    tokens_match,
)
from threatlens.web.templating import render

log = logging.getLogger(__name__)
router = APIRouter(include_in_schema=False)

LOGIN_CSRF_COOKIE = "tl_login_csrf"
MAX_NEXT_LENGTH = 512


def safe_next(target: str | None) -> str:
    """Only allow redirects to a local path (no open redirect)."""
    if (
        not target
        or len(target) > MAX_NEXT_LENGTH
        or not target.startswith("/")
        or target.startswith(("//", "/\\"))
        or any(c in target for c in "\r\n\t\\")
    ):
        return "/"
    return target


def _login_page(
    request: Request,
    settings: SettingsDep,
    *,
    next_url: str,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    secure = cookie_secure(settings, request)
    token = new_token()
    response = render(
        request,
        "login.html",
        {"login_csrf": token, "next_url": next_url, "error": error},
        status_code=status_code,
    )
    response.set_cookie(
        cookie_name(LOGIN_CSRF_COOKIE, secure), token, **cookie_options(secure, max_age=3600)
    )
    return response


@router.get("/login")
def login_form(request: Request, settings: SettingsDep, db: DbDep, next: str = "/") -> Response:
    if optional_session(request, settings, db) is not None:
        return RedirectResponse(safe_next(next), status.HTTP_303_SEE_OTHER)
    return _login_page(request, settings, next_url=safe_next(next))


@router.post("/login")
def login_submit(
    request: Request,
    settings: SettingsDep,
    db: DbDep,
    username: Annotated[str, Form(max_length=64)] = "",
    password: Annotated[str, Form(max_length=1024)] = "",
    csrf_token: Annotated[str, Form(max_length=128)] = "",
    next: Annotated[str, Form(max_length=MAX_NEXT_LENGTH)] = "/",
) -> Response:
    check_same_origin(request)
    secure = cookie_secure(settings, request)
    if not tokens_match(request.cookies.get(cookie_name(LOGIN_CSRF_COOKIE, secure)), csrf_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid or missing CSRF token")

    ip = client_ip(request)
    throttle: LoginThrottle = request.app.state.throttle
    next_url = safe_next(next)
    wait = throttle.retry_after(ip, username)
    if wait:
        with transaction(db):
            audit.record(db, "auth.login.throttled", target=username[:64], ip=ip)
        response = _login_page(
            request,
            settings,
            next_url=next_url,
            error=f"Too many failed attempts. Try again in {wait} seconds.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
        response.headers["Retry-After"] = str(wait)
        return response

    with transaction(db):
        user = authenticate(db, username, password)
        if user is None:
            audit.record(db, "auth.login.failure", target=username[:64], ip=ip)
        else:
            token = create_session(
                db,
                user,
                ttl_hours=settings.session_hours,
                ip=ip,
                user_agent=request.headers.get("user-agent"),
            )
            audit.record(db, "auth.login.success", actor=user.username, ip=ip)

    if user is None:
        throttle.failure(ip, username)
        log.info("login failed", extra={"client_ip": ip})
        return _login_page(
            request,
            settings,
            next_url=next_url,
            error="Invalid username or password.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    throttle.success(ip, username)
    response = RedirectResponse(next_url, status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        session_cookie_name(settings, request),
        token,
        **cookie_options(secure, max_age=settings.session_hours * 3600),
    )
    response.delete_cookie(cookie_name(LOGIN_CSRF_COOKIE, secure), path="/", secure=secure)
    return response


@router.post("/logout")
def logout(request: Request, settings: SettingsDep, db: DbDep, session: SessionDep) -> Response:
    with transaction(db):
        delete_session(db, session_token(request, settings))
        audit.record(db, "auth.logout", actor=session.user.username, ip=client_ip(request))
    secure = cookie_secure(settings, request)
    response = RedirectResponse("/login", status.HTTP_303_SEE_OTHER)
    response.delete_cookie(
        session_cookie_name(settings, request),
        path="/",
        secure=secure,
        httponly=True,
        samesite="strict",
    )
    return response
