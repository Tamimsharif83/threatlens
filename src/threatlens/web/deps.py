"""FastAPI dependencies: settings, database connection, current user, CSRF."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from threatlens.auth.sessions import Session, load_session
from threatlens.auth.users import Role
from threatlens.config import Settings
from threatlens.storage.db import connect
from threatlens.web.security import (
    check_same_origin,
    cookie_name,
    cookie_secure,
    supplied_csrf_token,
    tokens_match,
)

SESSION_COOKIE = "tl_session"


class NotAuthenticatedError(Exception):
    """Raised by `require_session`; turned into a redirect to /login (or a 401)."""


class PasswordChangeRequiredError(Exception):
    """The user logged in with a generated password; only /account is reachable."""


PASSWORD_CHANGE_ALLOWED = frozenset({"/account", "/logout"})


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


SettingsDep = Annotated[Settings, Depends(get_settings)]


def get_db(settings: SettingsDep) -> Iterator[sqlite3.Connection]:
    """One SQLite connection per request (cheap for SQLite, avoids cross-thread sharing)."""
    conn = connect(settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


DbDep = Annotated[sqlite3.Connection, Depends(get_db)]


def session_cookie_name(settings: Settings, request: Request) -> str:
    return cookie_name(SESSION_COOKIE, cookie_secure(settings, request))


def session_token(request: Request, settings: Settings) -> str | None:
    return request.cookies.get(session_cookie_name(settings, request))


def optional_session(request: Request, settings: SettingsDep, db: DbDep) -> Session | None:
    return load_session(db, session_token(request, settings))


async def require_session(
    request: Request,
    session: Annotated[Session | None, Depends(optional_session)],
) -> Session:
    """Require a logged-in user; for unsafe methods also enforce origin + CSRF token."""
    if session is None:
        raise NotAuthenticatedError
    check_same_origin(request)
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not tokens_match(
        session.csrf_token, await supplied_csrf_token(request)
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid or missing CSRF token")
    request.state.session = session
    if session.user.must_change_password and request.url.path not in PASSWORD_CHANGE_ALLOWED:
        raise PasswordChangeRequiredError
    return session


SessionDep = Annotated[Session, Depends(require_session)]


def require_admin(session: SessionDep) -> Session:
    if session.user.role is not Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    return session


AdminDep = Annotated[Session, Depends(require_admin)]


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None
