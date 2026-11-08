"""User accounts. Roles: ``admin`` (everything) and ``analyst`` (no user/system admin)."""

from __future__ import annotations

import logging
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

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN


def row_to_user(row: sqlite3.Row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        role=Role(row["role"]),
        disabled=bool(row["disabled"]),
    )


def get_user(conn: sqlite3.Connection, user_id: int) -> User | None:
    row = conn.execute(
        "SELECT id, username, role, disabled FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return row_to_user(row) if row else None


def count_users(conn: sqlite3.Connection) -> int:
    n: int = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return n


def create_user(conn: sqlite3.Connection, username: str, password: str, role: Role) -> User:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, hash_password(password), role.value, now_ms()),
    )
    user_id = cur.lastrowid
    if user_id is None:  # pragma: no cover - sqlite always sets it after INSERT
        raise RuntimeError("user insert returned no row id")
    return User(id=user_id, username=username, role=role, disabled=False)


def set_password(conn: sqlite3.Connection, user_id: int, password: str) -> None:
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id)
    )
    # Changing a password signs the user out everywhere.
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> User | None:
    """Return the user if the credentials are valid and the account is enabled."""
    row = conn.execute(
        "SELECT id, username, role, disabled, password_hash FROM users WHERE username = ?",
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
    create_user(conn, settings.admin_username, password, Role.ADMIN)
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
