"""Read-only SQL hunt console.

Hunting queries are analyst-written SQL, so the console runs them in a sandbox:

* a separate connection opened with ``mode=ro`` (the database file itself
  refuses writes);
* an authorizer that allows only reading: no INSERT/UPDATE/DELETE/DDL, no
  ``ATTACH`` (no other files), no ``PRAGMA`` (no settings), and no reading the
  ``users`` or ``sessions`` tables (password hashes, session hashes);
* one statement per run, a row limit, and a time limit enforced by a progress
  handler that aborts the query.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from threatlens.detection.compiler import sql_regexp

DENIED_TABLES = frozenset({"users", "sessions"})
_ALLOWED_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    getattr(sqlite3, "SQLITE_RECURSIVE", 33),  # WITH RECURSIVE
}
MAX_CELL = 4000  # characters shown per cell


@dataclass(slots=True)
class HuntResult:
    columns: list[str] = field(default_factory=list)
    rows: list[list[object]] = field(default_factory=list)
    truncated: bool = False
    elapsed_ms: int = 0
    error: str | None = None


def _authorizer(
    action: int, arg1: str | None, arg2: str | None, _db: str | None, _trigger: str | None
) -> int:
    if action not in _ALLOWED_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_READ and arg1 is not None and arg1.lower() in DENIED_TABLES:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def open_readonly(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5, check_same_thread=False)
    conn.create_function("regexp", 2, sql_regexp, deterministic=True)
    conn.set_authorizer(_authorizer)
    return conn


def _cell(value: object) -> object:
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, str) and len(value) > MAX_CELL:
        return value[:MAX_CELL] + "…"
    return value


def run_hunt(db_path: Path, sql: str, *, row_limit: int, timeout_s: float) -> HuntResult:
    result = HuntResult()
    text = sql.strip().rstrip(";").strip()
    if not text:
        result.error = "Enter a query."
        return result
    conn = open_readonly(db_path)
    deadline = time.monotonic() + timeout_s
    conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10_000)
    started = time.monotonic()
    try:
        cursor = conn.execute(text)
        result.columns = [d[0] for d in cursor.description or []]
        rows = cursor.fetchmany(row_limit + 1)
        result.truncated = len(rows) > row_limit
        result.rows = [[_cell(v) for v in row] for row in rows[:row_limit]]
    except sqlite3.DatabaseError as exc:
        message = str(exc)
        if "interrupted" in message:
            message = f"query stopped after the {timeout_s:g} s time limit"
        elif "not authorized" in message or "prohibited" in message:
            message = (
                "not allowed: the hunt console is read-only and cannot read users or "
                "sessions, attach files or run PRAGMA"
            )
        result.error = message
    except (sqlite3.ProgrammingError, sqlite3.Warning) as exc:
        result.error = str(exc)
    finally:
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        conn.close()
    return result
