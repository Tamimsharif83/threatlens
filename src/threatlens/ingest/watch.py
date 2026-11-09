"""Watch folder: ingest files dropped into ``/data/inbox`` and follow appends.

* Plain text files are tailed: new complete lines are ingested as they appear;
  a partial last line waits until its newline arrives.
* Rotation is detected by a new inode, a shrinking size (truncation) or a
  changed first-bytes fingerprint (inode reuse); the file is then read from 0.
  Lines already ingested are recognised by the dedup hash anyway.
* ``.gz``/``.zip`` files are ingested once, when they stop changing.
* The offset is saved after each read; a crash before that re-reads the region
  and the dedup hash absorbs the overlap. The inbox may be mounted read-only:
  ThreatLens never modifies, moves or deletes files there.

Source names: files in a sub-folder use the folder name (``inbox/web-prod/access.log``
-> ``web-prod``); files at the top level use the file name without rotation suffix.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import chain, islice
from pathlib import Path
from typing import BinaryIO
from zoneinfo import ZoneInfo

from threatlens.config import Settings
from threatlens.ingest.files import ingest_path, source_name_for
from threatlens.ingest.pipeline import (
    SNIFF_LINES,
    BatchReport,
    BatchWriter,
    IngestOptions,
    OccurrenceCounter,
    get_or_create_source,
    run_chunks,
    set_source_parser,
)
from threatlens.ingest.readers import (
    EVTX_MAGIC,
    GZIP_MAGIC,
    READ_ERRORS,
    ZIP_MAGIC,
    UnsafeInputError,
    check_text,
    iter_lines,
)
from threatlens.parsers import ParseContext, UnknownFormatError, detect_parser, make_parser
from threatlens.storage.db import connect, transaction
from threatlens.timeutil import now_ms

log = logging.getLogger(__name__)
HEAD_BYTES = 256
MAX_DEPTH = 3
SKIP_SUFFIXES = (".tmp", ".swp", ".part", ".partial", "~")
MIN_SNIFF_LINES = 5
DAY_MS = 86_400_000


@dataclass(slots=True)
class WatchState:
    path: str
    dev: int
    inode: int
    head_hash: str
    offset: int
    size: int
    mtime_ns: int
    parser: str | None
    source_id: int | None
    done: bool


def _head_hash(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.sha256(fh.read(HEAD_BYTES)).hexdigest()


def _complete_end(fh: BinaryIO, start: int, size: int) -> int:
    """Offset just after the last newline in [start, size): never consume a partial line."""
    pos = size
    block = 64 * 1024
    while pos > start:
        read_from = max(start, pos - block)
        fh.seek(read_from)
        idx = fh.read(pos - read_from).rfind(b"\n")
        if idx != -1:
            return read_from + idx + 1
        pos = read_from
    return start


class _Region:
    """At most ``length`` bytes from the current position of ``fh``."""

    def __init__(self, fh: BinaryIO, length: int) -> None:
        self.fh = fh
        self.remaining = length

    def readline(self, size: int = -1, /) -> bytes:
        if self.remaining <= 0:
            return b""
        n = self.remaining if size < 0 else min(size, self.remaining)
        data = self.fh.readline(n)
        self.remaining -= len(data)
        return data


class InboxWatcher:
    def __init__(
        self,
        settings: Settings,
        default_timezone: Callable[[], str],
        on_batch: Callable[[BatchReport], None] | None = None,
    ) -> None:
        self.settings = settings
        self.inbox = settings.data_dir / "inbox"
        self.default_timezone = default_timezone
        self.on_batch = on_batch
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Per-file duplicate counters survive between polls (see OccurrenceCounter).
        self._counters: dict[str, OccurrenceCounter] = {}

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="inbox-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception:  # the watcher must survive anything
                log.exception("inbox scan failed")
            self._stop.wait(self.settings.watch_interval_seconds)

    # ---------------------------------------------------------------- scanning

    def candidates(self) -> list[Path]:
        if not self.inbox.is_dir():
            return []
        found: list[Path] = []
        base_depth = len(self.inbox.parts)
        for root, dirs, files in os.walk(self.inbox, followlinks=False):
            depth = len(Path(root).parts) - base_depth
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and depth < MAX_DEPTH)
            for name in sorted(files):
                if name.startswith(".") or name.endswith(SKIP_SUFFIXES):
                    continue
                p = Path(root) / name
                if p.is_symlink() or not p.is_file():
                    continue  # never follow links out of the inbox
                found.append(p)
        return found

    def source_for(self, path: Path) -> str:
        rel = path.relative_to(self.inbox)
        return rel.parts[0] if len(rel.parts) > 1 else source_name_for(path.name)

    def scan_once(self) -> list[BatchReport]:
        reports: list[BatchReport] = []
        conn = connect(self.settings.db_path)
        try:
            for path in self.candidates():
                try:
                    reports.extend(self._process(conn, path))
                except READ_ERRORS as exc:
                    log.warning("inbox file skipped", extra={"file": str(path), "error": str(exc)})
        finally:
            conn.close()
        for rep in reports:
            if self.on_batch and rep.inserted:
                self.on_batch(rep)
        return reports

    def _load(self, conn: sqlite3.Connection, key: str) -> WatchState | None:
        row = conn.execute("SELECT * FROM watch_files WHERE path = ?", (key,)).fetchone()
        if row is None:
            return None
        return WatchState(
            row["path"],
            row["dev"],
            row["inode"],
            row["head_hash"],
            row["offset"],
            row["size"],
            row["mtime_ns"],
            row["parser"],
            row["source_id"],
            bool(row["done"]),
        )

    @staticmethod
    def _save(conn: sqlite3.Connection, st: WatchState) -> None:
        conn.execute(
            "INSERT INTO watch_files (path, dev, inode, head_hash, offset, size, mtime_ns, parser, "
            "source_id, done, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (path) DO UPDATE SET dev = excluded.dev, inode = excluded.inode, "
            "head_hash = excluded.head_hash, offset = excluded.offset, size = excluded.size, "
            "mtime_ns = excluded.mtime_ns, parser = excluded.parser, "
            "source_id = excluded.source_id, done = excluded.done, "
            "updated_at = excluded.updated_at",
            (
                st.path,
                st.dev,
                st.inode,
                st.head_hash,
                st.offset,
                st.size,
                st.mtime_ns,
                st.parser,
                st.source_id,
                int(st.done),
                now_ms(),
            ),
        )

    def _process(self, conn: sqlite3.Connection, path: Path) -> list[BatchReport]:
        info = path.stat()
        if info.st_size == 0:
            return []
        key = str(path.relative_to(self.inbox))
        st = self._load(conn, key)
        head = _head_hash(path)
        rotated = st is not None and (
            st.inode != info.st_ino
            or st.dev != info.st_dev
            or info.st_size < st.offset
            or (st.head_hash != head and st.offset >= HEAD_BYTES)
        )
        if st is None or rotated:
            self._counters.pop(key, None)
            st = WatchState(
                key,
                info.st_dev,
                info.st_ino,
                head,
                0,
                -1,  # unknown size: archives wait one poll to see they stopped growing
                info.st_mtime_ns,
                st.parser if st else None,
                st.source_id if st else None,
                False,
            )
        if st.done:
            return []
        with path.open("rb") as fh:
            magic = fh.read(8)
        if magic.startswith((GZIP_MAGIC, *ZIP_MAGIC, EVTX_MAGIC)):
            # Read whole once the file stops changing. A grown EVTX file changes its
            # header, counts as rotated and is read again; dedup skips known records.
            return self._ingest_archive(conn, path, st, info)
        if st.offset >= info.st_size:
            return []
        return self._tail(conn, path, st, info)

    def _ingest_archive(
        self, conn: sqlite3.Connection, path: Path, st: WatchState, info: os.stat_result
    ) -> list[BatchReport]:
        if st.size != info.st_size or st.mtime_ns != info.st_mtime_ns:
            # Still being copied in (or first sighting): check again next poll.
            st.size, st.mtime_ns = info.st_size, info.st_mtime_ns
            with transaction(conn):
                self._save(conn, st)
            return []
        opts = IngestOptions(
            source_name=self.source_for(path),
            origin="watch",
            store_raw=self.settings.store_raw,
        )
        reports = ingest_path(
            conn,
            path,
            opts,
            default_timezone=self.default_timezone(),
            max_bytes=self.settings.max_decompressed_mb * 1024 * 1024,
            display_name=st.path,
        )
        st.done, st.offset = True, info.st_size
        with transaction(conn):
            self._save(conn, st)
        return reports

    def _tail(
        self, conn: sqlite3.Connection, path: Path, st: WatchState, info: os.stat_result
    ) -> list[BatchReport]:
        source = self.source_for(path)
        with path.open("rb") as fh:
            if st.offset == 0:
                check_text(fh.read(8192), st.path)
            data_end = _complete_end(fh, st.offset, info.st_size)
            if data_end <= st.offset:
                return []  # only a partial line so far
            fh.seek(st.offset)
            lines = iter_lines(_Region(fh, data_end - st.offset))
            first = list(islice(lines, SNIFF_LINES))

            with transaction(conn):
                source_id, source_tz = get_or_create_source(conn, source, st.parser or "auto")
            ctx = ParseContext(
                tz=ZoneInfo(source_tz or self.default_timezone()),
                reference_time=datetime.now(UTC),
            )
            if st.parser:
                parser = make_parser(st.parser)
            else:
                try:
                    parser = detect_parser([ln for _, ln in first], ctx)
                except UnknownFormatError:
                    if len(first) < MIN_SNIFF_LINES:
                        return []  # too few lines to recognise the format yet; retry later
                    raise UnsafeInputError(f"{st.path}: log format not recognised") from None
            if st.parser != parser.name:
                set_source_parser(conn, source_id, parser.name)
            st.parser, st.source_id = parser.name, source_id
            writer = BatchWriter(
                conn,
                source_id,
                source,
                st.path,
                parser.name,
                IngestOptions(
                    source_name=source, origin="watch", store_raw=self.settings.store_raw
                ),
                batch_id=self._open_batch(conn, source_id, st.path),
            )
            counter = self._counters.setdefault(st.path, OccurrenceCounter())
            run_chunks(writer, chain(first, lines), parser, ctx, counter=counter)

        st.offset, st.size, st.mtime_ns = data_end, info.st_size, info.st_mtime_ns
        st.head_hash, st.dev, st.inode = _head_hash(path), info.st_dev, info.st_ino
        with transaction(conn):
            self._save(conn, st)
        return [writer.finish()]

    @staticmethod
    def _open_batch(conn: sqlite3.Connection, source_id: int, file_name: str) -> int | None:
        """Reuse today's batch for this file so a busy log doesn't create a batch per poll."""
        now = now_ms()
        row = conn.execute(
            "SELECT id FROM ingest_batches WHERE origin = 'watch' AND source_id = ? AND "
            "file_name = ? AND started_at >= ? ORDER BY id DESC LIMIT 1",
            (source_id, file_name, now - now % DAY_MS),
        ).fetchone()
        if row is None:
            return None
        with transaction(conn):
            conn.execute("UPDATE ingest_batches SET status = 'running' WHERE id = ?", (row[0],))
        return int(row[0])
