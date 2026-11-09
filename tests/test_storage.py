from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from threatlens import audit
from threatlens.storage import db as dbmod
from threatlens.storage.db import connect, init_db, schema_version, transaction


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "t.db"
    init_db(path)
    with closing(connect(path)) as c:
        yield c


def test_init_db_creates_schema(tmp_path: Path, conn: sqlite3.Connection) -> None:
    path = tmp_path / "t.db"
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # incremental
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "sessions", "audit_log"} <= tables
    assert schema_version(conn) == len(dbmod._migrations())
    assert (path.stat().st_mode & 0o777) == 0o600


def test_init_db_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "t.db"
    init_db(path)
    init_db(path)
    with closing(connect(path)) as c:
        assert schema_version(c) == len(dbmod._migrations())


def test_migration_numbers_must_be_contiguous(monkeypatch: pytest.MonkeyPatch) -> None:
    class Entry:
        def __init__(self, name: str) -> None:
            self.name = name

        def read_text(self, encoding: str) -> str:
            return ""

    class Dir:
        def iterdir(self) -> list[Entry]:
            return [Entry("0001_a.sql"), Entry("0003_c.sql"), Entry("README.txt")]

    monkeypatch.setattr(dbmod.resources, "files", lambda _pkg: Dir())
    with pytest.raises(RuntimeError, match="contiguous"):
        dbmod._migrations()


def test_transaction_rolls_back(conn: sqlite3.Connection) -> None:
    def write_then_fail() -> None:
        with transaction(conn):
            audit.record(conn, "test.action")
            raise ZeroDivisionError

    with pytest.raises(ZeroDivisionError):
        write_then_fail()
    assert audit.recent(conn) == []


def test_audit_roundtrip(conn: sqlite3.Connection) -> None:
    with transaction(conn):
        audit.record(conn, "a.one", actor="alice", target="x", details={"k": 1}, ip="10.0.0.1")
        audit.record(conn, "a.two")
    entries = audit.recent(conn)
    assert [e.action for e in entries] == ["a.two", "a.one"]
    assert entries[1].details == {"k": 1}
    assert entries[1].actor == "alice"


def test_pivot_indexes_include_time_and_old_ones_are_upgraded(tmp_path: Path) -> None:
    from threatlens.normalize.schema import WEBSERVER  # noqa: PLC0415
    from threatlens.storage.events import EventStore, upgrade_pivot_indexes  # noqa: PLC0415

    path = tmp_path / "t.db"
    init_db(path)
    conn = connect(path)
    with transaction(conn):
        store = EventStore(conn)
        table = store.ensure_table(WEBSERVER)
        store._add_column(table, "source.ip", "TEXT")
    cols = [r[2] for r in conn.execute(f'PRAGMA index_info("{table}__source.ip")')]
    assert cols == ["source.ip", "tl_ts"]
    # a pre-1.0 database: single-column pivot index
    with transaction(conn):
        conn.execute(f'DROP INDEX "{table}__source.ip"')
        conn.execute(f'CREATE INDEX "{table}__source.ip" ON {table} ("source.ip")')
        assert upgrade_pivot_indexes(conn) == [f"{table}__source.ip"]
        assert upgrade_pivot_indexes(conn) == []
    cols = [r[2] for r in conn.execute(f'PRAGMA index_info("{table}__source.ip")')]
    assert cols == ["source.ip", "tl_ts"]
    conn.close()
    init_db(path)  # startup runs the upgrade; idempotent
