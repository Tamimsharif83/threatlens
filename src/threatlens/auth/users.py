"""User accounts. Roles: ``admin`` (everything) and ``analyst`` (no user/system admin)."""

from __future__ import annotations

import logging
import re
import sqlite3
import sys
from dataclasses import dataclass
from enum import StrEnum

from threatlens import audit
from threatlens.auth.passwords import (
    generate_password,
    hash_password,
    needs_rehash,
    verify_password,
)
from threatlens.config import Settings
from threatlens.timeutil import now_ms

log = logging.getLogger(__name__)


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"


@dataclass(frozen=True, slots=True)
class User:
    id: int
    username: str
    role: Role
    disabled: bool
    must_change_password: bool = False

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN


def row_to_user(row: sqlite3.Row) -> User:
    keys = row.keys()
    return User(
        id=row["id"],
        username=row["username"],
        role=Role(row["role"]),
        disabled=bool(row["disabled"]),
        must_change_password=bool(row["must_change_password"])
        if "must_change_password" in keys
        else False,
    )


@dataclass(frozen=True, slots=True)
class UserListing:
    user: User
    created_at: int
    last_login_at: int | None


def list_users(conn: sqlite3.Connection) -> list[UserListing]:
    rows = conn.execute(
        "SELECT id, username, role, disabled, must_change_password, created_at, last_login_at "
        "FROM users ORDER BY username"
    ).fetchall()
    return [UserListing(row_to_user(r), r["created_at"], r["last_login_at"]) for r in rows]


def count_active_admins(conn: sqlite3.Connection) -> int:
    n: int = conn.execute(
        "SELECT count(*) FROM users WHERE role = 'admin' AND disabled = 0"
    ).fetchone()[0]
    return n


def set_disabled(conn: sqlite3.Connection, user_id: int, disabled: bool) -> None:
    conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
    if disabled:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def get_user(conn: sqlite3.Connection, user_id: int) -> User | None:
    row = conn.execute(
        "SELECT id, username, role, disabled, must_change_password FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    return row_to_user(row) if row else None


def count_users(conn: sqlite3.Connection) -> int:
    n: int = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return n


USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")


def validate_username(username: str) -> str:
    if not USERNAME_RE.match(username):
        raise ValueError("username must be 1-64 characters: letters, digits, '.', '_', '@' or '-'")
    return username


def create_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    role: Role,
    *,
    must_change_password: bool = False,
) -> User:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, must_change_password) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, hash_password(password), role.value, now_ms(), int(must_change_password)),
    )
    user_id = cur.lastrowid
    if user_id is None:  # pragma: no cover - sqlite always sets it after INSERT
        raise RuntimeError("user insert returned no row id")
    return User(
        id=user_id,
        username=username,
        role=role,
        disabled=False,
        must_change_password=must_change_password,
    )


def set_password(
    conn: sqlite3.Connection,
    user_id: int,
    password: str,
    *,
    must_change: bool = False,
    keep_session_hash: str | None = None,
    password_hash: str | None = None,
) -> None:
    """Set a password. Signs the user out everywhere (except, optionally, the session
    that made the change). ``password_hash`` is the already computed hash, for callers
    that hash outside a transaction (argon2 takes a while)."""
    conn.execute(
        "UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
        (password_hash or hash_password(password), int(must_change), user_id),
    )
    conn.execute(
        "DELETE FROM sessions WHERE user_id = ? AND token_hash IS NOT ?",
        (user_id, keep_session_hash),
    )


def check_password(conn: sqlite3.Connection, user_id: int, password: str) -> bool:
    row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    return verify_password(row["password_hash"] if row else None, password)


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> User | None:
    """Return the user if the credentials are valid and the account is enabled."""
    row = conn.execute(
        "SELECT id, username, role, disabled, must_change_password, password_hash FROM users "
        "WHERE username = ?",
        (username,),
    ).fetchone()
    ok = verify_password(row["password_hash"] if row else None, password)
    if not ok or row is None or row["disabled"]:
        return None
    if needs_rehash(row["password_hash"]):
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(password), row["id"]),
        )
    conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_ms(), row["id"]))
    return row_to_user(row)


def bootstrap_admin(conn: sqlite3.Connection, settings: Settings) -> None:
    """On first run (no users at all), create the admin account.

    The password comes from ``TL_ADMIN_PASSWORD``; if that is unset a random
    password is generated and printed exactly once to the container log.
    """
    if count_users(conn) > 0:
        return
    generated = settings.admin_password is None
    password = (
        generate_password()
        if settings.admin_password is None
        else (settings.admin_password.get_secret_value())
    )
    # A generated password must be replaced at first login.
    create_user(conn, settings.admin_username, password, Role.ADMIN, must_change_password=generated)
    audit.record(
        conn,
        "user.bootstrap_admin",
        target=settings.admin_username,
        details={"password_source": "generated" if generated else "TL_ADMIN_PASSWORD"},
    )
    log.info("created initial admin account", extra={"username": settings.admin_username})
    if generated:
        # Deliberately a plain banner on stderr (not a JSON log field) and never stored.
        banner = (
            "\n" + "=" * 64 + "\n"
            "  ThreatLens first run: initial admin account created\n"
            f"  username: {settings.admin_username}\n"
            f"  password: {password}\n"
            "  This password is shown ONCE. Change it after logging in.\n" + "=" * 64 + "\n"
        )
        print(banner, file=sys.stderr, flush=True)
