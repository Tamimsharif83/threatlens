"""SQLite connection handling and schema migrations.

ThreatLens keeps all state in one SQLite database in WAL mode (see ADR-0002).
Migrations are numbered ``NNNN_name.sql`` files shipped inside the package;
the applied version is tracked with ``PRAGMA user_version``.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

from threatlens.storage.events import upgrade_pivot_indexes

log = logging.getLogger(__name__)

_MIGRATION_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")
BUSY_TIMEOUT_MS = 5000


def connect(path: Path) -> sqlite3.Connection:
    """Open a read-write connection with ThreatLens' standard pragmas."""
    conn = sqlite3.connect(
        path,
        timeout=BUSY_TIMEOUT_MS / 1000,
        isolation_level=None,  # explicit transactions via `transaction()`
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous = NORMAL")  # safe with WAL, much faster
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """``BEGIN IMMEDIATE`` ... ``COMMIT`` (or ``ROLLBACK`` on error)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        # SQLite may already have rolled back by itself (SQLITE_FULL, SQLITE_IOERR); a
        # second ROLLBACK would raise and hide the real error.
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _migrations() -> list[tuple[int, str, str]]:
    found: list[tuple[int, str, str]] = []
    for entry in resources.files("threatlens.storage.migrations").iterdir():
        match = _MIGRATION_NAME.match(entry.name)
        if match:
            found.append((int(match.group(1)), entry.name, entry.read_text(encoding="utf-8")))
    found.sort()
    versions = [v for v, _, _ in found]
    if versions != list(range(1, len(versions) + 1)):
        raise RuntimeError(f"migration numbers must be contiguous from 0001, got {versions}")
    return found


def init_db(path: Path, *, quiet: bool = False) -> None:
    """Create the database if needed, enable WAL and apply pending migrations.

    ``quiet``: for throwaway databases (rule tests), log migrations at DEBUG."""
    conn = connect(path)
    try:
        # auto_vacuum only takes effect on an empty database, so it must come
        # before anything (including the WAL switch) writes the file header.
        conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        conn.execute("PRAGMA journal_mode = WAL")
        current: int = conn.execute("PRAGMA user_version").fetchone()[0]
        for version, name, sql in _migrations():
            if version <= current:
                continue
            log.log(
                logging.DEBUG if quiet else logging.INFO,
                "applying migration",
                extra={"migration": name},
            )
            # executescript() commits implicitly, so wrap the script itself.
            conn.executescript(
                f"BEGIN IMMEDIATE;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;"
            )
        with transaction(conn):
            rebuilt = upgrade_pivot_indexes(conn)
        if rebuilt:
            log.info("rebuilt pivot indexes as (field, time)", extra={"indexes": len(rebuilt)})
    finally:
        conn.close()
    path.chmod(0o600)


def schema_version(conn: sqlite3.Connection) -> int:
    value: int = conn.execute("PRAGMA user_version").fetchone()[0]
    return value
