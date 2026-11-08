"""Settings an admin can change from the UI (stored in ``app_settings``).

The ``TL_*`` environment variables are the defaults; a value saved from the
Settings page overrides them until it is reset.
"""

from __future__ import annotations

import sqlite3
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from threatlens.config import Settings
from threatlens.timeutil import now_ms

RETENTION_DAYS = "retention_days"
DEFAULT_TIMEZONE = "default_timezone"


def _get(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def _set(conn: sqlite3.Connection, key: str, value: str, actor: str | None) -> None:
    conn.execute(
        "INSERT INTO app_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (key) DO UPDATE SET value = excluded.value, "
        "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        (key, value, now_ms(), actor),
    )


def retention_days(conn: sqlite3.Connection, settings: Settings) -> int:
    value = _get(conn, RETENTION_DAYS)
    return int(value) if value and value.isdigit() else settings.retention_days


def default_timezone(conn: sqlite3.Connection, settings: Settings) -> str:
    return _get(conn, DEFAULT_TIMEZONE) or settings.default_timezone


def set_retention_days(conn: sqlite3.Connection, days: int, actor: str | None) -> None:
    if not 1 <= days <= 3650:
        raise ValueError("retention must be between 1 and 3650 days")
    _set(conn, RETENTION_DAYS, str(days), actor)


def set_default_timezone(conn: sqlite3.Connection, tz: str, actor: str | None) -> None:
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown timezone: {tz}") from exc
    _set(conn, DEFAULT_TIMEZONE, tz, actor)
