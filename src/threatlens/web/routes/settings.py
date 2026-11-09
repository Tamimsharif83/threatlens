"""Settings (admin): retention, timezone, storage usage, users, maintenance.
Account (everyone): change your own password."""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse, Response
from starlette.datastructures import FormData

from threatlens import audit, runtime_settings
from threatlens.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    generate_password,
    hash_password,
)
from threatlens.auth.sessions import token_hash
from threatlens.auth.throttle import LoginThrottle
from threatlens.auth.users import (
    Role,
    check_password,
    count_active_admins,
    create_user,
    get_user,
    list_users,
    set_disabled,
    set_password,
    validate_username,
)
from threatlens.config import Settings
from threatlens.storage.db import transaction
from threatlens.storage.maintenance import compact, purge, storage_stats
from threatlens.web.deps import (
    AdminDep,
    DbDep,
    SessionDep,
    SettingsDep,
    client_ip,
    session_token,
)
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)


def _settings_page(
    request: Request,
    db: sqlite3.Connection,
    settings: Settings,
    *,
    message: str | None = None,
    error: str | None = None,
    new_password: tuple[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    ctx: dict[str, Any] = {
        "active": "settings",
        "retention_days": runtime_settings.retention_days(db, settings),
        "default_timezone": runtime_settings.default_timezone(db, settings),
        "env_retention_days": settings.retention_days,
        "env_timezone": settings.default_timezone,
        "storage": storage_stats(db, settings.db_path),
        "users": list_users(db),
        "message": message,
        "error": error,
        "new_password": new_password,
        "store_raw": settings.store_raw,
        "watch_enabled": settings.watch_enabled,
    }
    return render(request, "settings.html", ctx, status_code=status_code)


@router.get("/settings")
def settings_page(
    request: Request, session: AdminDep, db: DbDep, settings: SettingsDep
) -> Response:
    return _settings_page(request, db, settings)


async def _form(request: Request) -> FormData:
    return await request.form(max_files=0, max_fields=20)


@router.post("/settings/general")
async def save_general(
    request: Request, session: AdminDep, db: DbDep, settings: SettingsDep
) -> Response:
    form = await _form(request)
    try:
        days = int(str(form.get("retention_days", "")).strip())
        tz = str(form.get("default_timezone", "")).strip()
        with transaction(db):
            runtime_settings.set_retention_days(db, days, session.user.username)
            runtime_settings.set_default_timezone(db, tz, session.user.username)
            audit.record(
                db,
                "settings.update",
                actor=session.user.username,
                details={"retention_days": days, "default_timezone": tz},
                ip=client_ip(request),
            )
    except ValueError as exc:
        return _settings_page(request, db, settings, error=str(exc), status_code=400)
    return _settings_page(request, db, settings, message="Settings saved.")


@router.post("/settings/users")
async def add_user(
    request: Request, session: AdminDep, db: DbDep, settings: SettingsDep
) -> Response:
    form = await _form(request)
    username = str(form.get("username", "")).strip()
    role_value = str(form.get("role", "analyst"))
    try:
        validate_username(username)
        role = Role(role_value)
    except ValueError as exc:
        return _settings_page(request, db, settings, error=str(exc), status_code=400)
    password = generate_password()
    try:
        with transaction(db):
            create_user(db, username, password, role, must_change_password=True)
            audit.record(
                db,
                "user.create",
                actor=session.user.username,
                target=username,
                details={"role": role.value},
                ip=client_ip(request),
            )
    except sqlite3.IntegrityError:
        return _settings_page(
            request, db, settings, error=f"User {username!r} already exists.", status_code=409
        )
    return _settings_page(
        request,
        db,
        settings,
        message=f"User {username} created.",
        new_password=(username, password),
    )


@router.post("/settings/users/{user_id}/{action}")
def user_action(
    request: Request,
    user_id: int,
    action: str,
    session: AdminDep,
    db: DbDep,
    settings: SettingsDep,
) -> Response:
    target = get_user(db, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    actor = session.user.username
    if action in ("disable", "reset-password") and target.id == session.user.id:
        return _settings_page(
            request,
            db,
            settings,
            status_code=400,
            error="You cannot disable or reset your own account here; use Account.",
        )
    if action == "disable":
        if target.role is Role.ADMIN and count_active_admins(db) <= 1:
            return _settings_page(
                request,
                db,
                settings,
                status_code=400,
                error="Cannot disable the last active admin.",
            )
        with transaction(db):
            set_disabled(db, target.id, True)
            audit.record(
                db, "user.disable", actor=actor, target=target.username, ip=client_ip(request)
            )
        return _settings_page(request, db, settings, message=f"{target.username} disabled.")
    if action == "enable":
        with transaction(db):
            set_disabled(db, target.id, False)
            audit.record(
                db, "user.enable", actor=actor, target=target.username, ip=client_ip(request)
            )
        return _settings_page(request, db, settings, message=f"{target.username} enabled.")
    if action == "reset-password":
        password = generate_password()
        with transaction(db):
            set_password(db, target.id, password, must_change=True)
            audit.record(
                db,
                "user.password_reset",
                actor=actor,
                target=target.username,
                ip=client_ip(request),
            )
        return _settings_page(
            request,
            db,
            settings,
            message=f"Password reset for {target.username}.",
            new_password=(target.username, password),
        )
    raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown action")


@router.post("/settings/maintenance/{action}")
def maintenance(
    request: Request, action: str, session: AdminDep, db: DbDep, settings: SettingsDep
) -> Response:
    if action == "purge":
        result = purge(db, runtime_settings.retention_days(db, settings))
        message = (
            f"Retention purge: {result.total} events and {result.batches_deleted} batch "
            f"records deleted."
        )
        details: dict[str, Any] = {"events": result.total, "batches": result.batches_deleted}
    elif action == "compact":
        compact(db, full=False)
        message, details = "Database compacted.", {}
    else:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown action")
    with transaction(db):
        audit.record(
            db,
            f"maintenance.{action}",
            actor=session.user.username,
            details=details,
            ip=client_ip(request),
        )
    return _settings_page(request, db, settings, message=message)


# ---------------------------------------------------------------- account


@router.get("/account")
def account_page(request: Request, session: SessionDep) -> Response:
    return render(
        request,
        "account.html",
        {"active": "account", "error": None, "message": None, "min_length": MIN_PASSWORD_LENGTH},
    )


@router.post("/account")
async def change_password(
    request: Request, session: SessionDep, db: DbDep, settings: SettingsDep
) -> Response:
    form = await request.form(max_files=0, max_fields=10)
    current = str(form.get("current_password", ""))
    new = str(form.get("new_password", ""))
    confirm = str(form.get("confirm_password", ""))
    error = None
    # The same throttle as the login form: a stolen session must not be a way to
    # guess the current password. argon2 runs in a worker thread.
    throttle: LoginThrottle = request.app.state.throttle
    ip = client_ip(request)
    wait = throttle.retry_after(ip, session.user.username)
    if wait:
        error = f"Too many wrong passwords. Try again in {wait} seconds."
    elif not await run_in_threadpool(check_password, db, session.user.id, current):
        throttle.failure(ip, session.user.username)
        with transaction(db):
            audit.record(db, "user.password_change.failure", actor=session.user.username, ip=ip)
        error = "Current password is wrong."
    elif new != confirm:
        error = "The new passwords do not match."
    elif new == current:
        error = "Choose a password different from the current one."
    elif len(new) < MIN_PASSWORD_LENGTH:
        error = f"Use at least {MIN_PASSWORD_LENGTH} characters."
    elif len(new) > MAX_PASSWORD_LENGTH:
        error = f"Use at most {MAX_PASSWORD_LENGTH} characters."
    if error:
        return render(
            request,
            "account.html",
            {
                "active": "account",
                "error": error,
                "message": None,
                "min_length": MIN_PASSWORD_LENGTH,
            },
            status_code=400,
        )
    throttle.success(ip, session.user.username)
    token = session_token(request, settings)
    new_hash = await run_in_threadpool(hash_password, new)
    with transaction(db):
        set_password(
            db,
            session.user.id,
            new,
            keep_session_hash=token_hash(token) if token else None,
            password_hash=new_hash,
        )
        audit.record(db, "user.password_change", actor=session.user.username, ip=client_ip(request))
    return RedirectResponse("/", status.HTTP_303_SEE_OTHER)
