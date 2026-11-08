from __future__ import annotations

import gzip
import os
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest

from threatlens import runtime_settings
from threatlens.config import Settings
from threatlens.ingest.files import ingest_path
from threatlens.ingest.pipeline import IngestOptions
from threatlens.ingest.watch import InboxWatcher
from threatlens.storage.db import connect, init_db, transaction
from threatlens.storage.maintenance import compact, purge, storage_stats
from threatlens.synth import auth_lines, web_lines

DAY = 86_400_000


@pytest.fixture
def wsettings(tmp_path: Path) -> Settings:
    s = Settings(data_dir=tmp_path / "data", watch_enabled=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    (s.data_dir / "inbox").mkdir()
    init_db(s.db_path)
    return s


@pytest.fixture
def watcher(wsettings: Settings) -> InboxWatcher:
    return InboxWatcher(wsettings, lambda: "UTC")


def count(settings: Settings, table: str = "ev_webserver") -> int:
    with closing(connect(settings.db_path)) as c:
        try:
            return int(c.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
        except sqlite3.OperationalError:
            return 0


def append(path: Path, lines: list[str], newline: bool = True) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if newline else ""))


WEB = list(web_lines(400, seed=21))


def test_tail_appends_and_partial_lines(watcher: InboxWatcher, wsettings: Settings) -> None:
    log = watcher.inbox / "access.log"
    append(log, WEB[:100])
    watcher.scan_once()
    assert count(wsettings) == 100
    append(log, WEB[100:150])
    append(log, [WEB[150][:30]], newline=False)  # half-written line
    watcher.scan_once()
    assert count(wsettings) == 150  # the partial line waits for its newline
    append(log, [WEB[150][30:]])
    watcher.scan_once()
    assert count(wsettings) == 151
    watcher.scan_once()  # nothing new
    assert count(wsettings) == 151
    with closing(connect(wsettings.db_path)) as c:
        batches = c.execute("SELECT count(*), sum(events_inserted) FROM ingest_batches").fetchone()
        assert tuple(batches) == (1, 151)  # one batch per file per day
        src = c.execute("SELECT name, parser FROM sources").fetchone()
        assert tuple(src) == ("access.log", "apache")


def test_resume_after_restart(watcher: InboxWatcher, wsettings: Settings) -> None:
    log = watcher.inbox / "access.log"
    append(log, WEB[:50])
    watcher.scan_once()
    append(log, WEB[50:80])
    fresh = InboxWatcher(wsettings, lambda: "UTC")  # e.g. after a container restart
    fresh.scan_once()
    assert count(wsettings) == 80
    with closing(connect(wsettings.db_path)) as c:
        assert c.execute("SELECT sum(duplicates) FROM ingest_batches").fetchone()[0] == 0


def test_rotation_by_rename_and_truncation(watcher: InboxWatcher, wsettings: Settings) -> None:
    log = watcher.inbox / "access.log"
    append(log, WEB[:60])
    watcher.scan_once()
    log.rename(watcher.inbox / "access.log.1")  # logrotate: rename, then new file
    append(log, WEB[60:70])
    watcher.scan_once()
    # rotated copy is a "new" file to the watcher, but its lines dedup away
    assert count(wsettings) == 70
    log.write_text("")  # copytruncate
    append(log, WEB[70:75])
    watcher.scan_once()
    assert count(wsettings) == 75


def test_subfolder_is_source_name_and_auth_logs(watcher: InboxWatcher, wsettings: Settings) -> None:
    folder = watcher.inbox / "bastion"
    folder.mkdir()
    append(folder / "auth.log", list(auth_lines(40, seed=3)))
    watcher.scan_once()
    assert count(wsettings, "ev_linux_auth") == 40
    with closing(connect(wsettings.db_path)) as c:
        assert c.execute("SELECT name FROM sources").fetchone()[0] == "bastion"


def test_archives_wait_until_stable(watcher: InboxWatcher, wsettings: Settings) -> None:
    gz = watcher.inbox / "old.log.gz"
    gz.write_bytes(gzip.compress(("\n".join(WEB[:30]) + "\n").encode()))
    assert watcher.scan_once() == []  # first sighting: wait one poll
    reports = watcher.scan_once()
    assert [r.inserted for r in reports] == [30]
    assert watcher.scan_once() == []  # done; never re-ingested
    assert count(wsettings) == 30


def test_skips_hidden_temp_symlinks_and_unknown(
    watcher: InboxWatcher, wsettings: Settings, tmp_path: Path
) -> None:
    append(watcher.inbox / ".hidden.log", WEB[:5])
    append(watcher.inbox / "copying.log.part", WEB[:5])
    outside = tmp_path / "outside.log"
    append(outside, WEB[:5])
    os.symlink(outside, watcher.inbox / "link.log")
    append(watcher.inbox / "few.log", ["what is this"] * 2)
    watcher.scan_once()
    assert count(wsettings) == 0
    # an unrecognised file with enough lines is skipped without killing the scan
    append(watcher.inbox / "few.log", ["what is this"] * 10)
    append(watcher.inbox / "real.log", WEB[:3])
    watcher.scan_once()
    assert count(wsettings) == 3


def test_watcher_thread_start_stop(wsettings: Settings) -> None:
    w = InboxWatcher(wsettings, lambda: "UTC")
    w.start()
    w.stop()
    assert not w._thread or not w._thread.is_alive()


# ---------------------------------------------------------------- retention & storage


@pytest.fixture
def filled(wsettings: Settings, tmp_path: Path) -> Iterator[sqlite3.Connection]:
    path = tmp_path / "access.log"
    path.write_text("\n".join(WEB) + "\n")
    with closing(connect(wsettings.db_path)) as conn:
        ingest_path(conn, path, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
        yield conn


def test_purge_by_ingestion_time(filled: sqlite3.Connection, wsettings: Settings) -> None:
    # Old events ingested today are kept: retention counts from ingestion.
    result = purge(filled, 1)
    assert result.total == 0
    assert filled.execute("SELECT count(*) FROM ev_webserver").fetchone()[0] == len(WEB)
    # A second batch, then age only the first one past the retention period.
    with transaction(filled):
        filled.execute("UPDATE ingest_batches SET finished_at = finished_at - 3 * ?", (DAY,))
    extra = wsettings.data_dir / "more.log"
    extra.write_text("\n".join(web_lines(40, seed=99)) + "\n")
    ingest_path(filled, extra, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
    result = purge(filled, 2)
    assert result.total == len(WEB)
    assert result.batches_deleted == 1
    assert filled.execute("SELECT count(*) FROM ev_webserver").fetchone()[0] == 40
    assert filled.execute("PRAGMA freelist_count").fetchone()[0] == 0  # space reclaimed
    assert [r[0] for r in filled.execute("SELECT name FROM sources")] == ["more.log"]


def test_storage_stats_and_compact(filled: sqlite3.Connection, wsettings: Settings) -> None:
    st = storage_stats(filled, wsettings.db_path)
    assert st.total_events == len(WEB)
    assert st.tables[0].table == "ev_webserver" and st.tables[0].bytes > 0
    [src] = st.sources
    assert (src.name, src.events, src.batches) == ("access.log", len(WEB), 1)
    assert src.approx_bytes > 0
    compact(filled, full=True)


def test_runtime_settings_override_env(wsettings: Settings) -> None:
    with closing(connect(wsettings.db_path)) as conn:
        assert runtime_settings.retention_days(conn, wsettings) == 30
        assert runtime_settings.default_timezone(conn, wsettings) == "UTC"
        with transaction(conn):
            runtime_settings.set_retention_days(conn, 7, "admin")
            runtime_settings.set_default_timezone(conn, "Asia/Dhaka", "admin")
        assert runtime_settings.retention_days(conn, wsettings) == 7
        assert runtime_settings.default_timezone(conn, wsettings) == "Asia/Dhaka"
        with pytest.raises(ValueError, match="between"):
            runtime_settings.set_retention_days(conn, 0, "admin")
        with pytest.raises(ValueError, match="unknown timezone"):
            runtime_settings.set_default_timezone(conn, "Mars/Base", "admin")
