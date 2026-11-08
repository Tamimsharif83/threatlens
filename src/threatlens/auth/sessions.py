"""Server-side sessions.

The browser holds a random 256-bit token in an HttpOnly cookie; the database
holds only its SHA-256. Each session also carries its own CSRF token.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from dataclasses import dataclass

from threatlens.auth.users import User, row_to_user
from threatlens.timeutil import now_ms


@dataclass(frozen=True, slots=True)
class Session:
    user: User
    csrf_token: str
    expires_at: int


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(
    conn: sqlite3.Connection,
    user: User,
    *,
    ttl_hours: int,
    ip: str | None,
    user_agent: str | None,
) -> str:
    """Create a session and return the raw token for the cookie."""
    token = secrets.token_urlsafe(32)
    now = now_ms()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at, ip, "
        "user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            token_hash(token),
            user.id,
            secrets.token_urlsafe(32),
            now,
            now + ttl_hours * 3_600_000,
            ip,
            (user_agent or "")[:512],
        ),
    )
    return token


def load_session(conn: sqlite3.Connection, token: str | None) -> Session | None:
    if not token or len(token) > 128:
        return None
    row = conn.execute(
        "SELECT s.csrf_token, s.expires_at, u.id, u.username, u.role, u.disabled, "
        "u.must_change_password "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (token_hash(token),),
    ).fetchone()
    if row is None or row["expires_at"] <= now_ms() or row["disabled"]:
        return None
    return Session(
        user=row_to_user(row), csrf_token=row["csrf_token"], expires_at=row["expires_at"]
    )


def delete_session(conn: sqlite3.Connection, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))


def purge_expired(conn: sqlite3.Connection) -> int:
    return conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_ms(),)).rowcount
