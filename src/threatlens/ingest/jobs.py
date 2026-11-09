"""Background ingest worker for web uploads.

Uploads are saved to ``/data/uploads`` and queued; one worker thread ingests
them in order (one writer keeps SQLite happy and the UI responsive). Job
status lives in memory for the progress display; the durable record is the
``ingest_batches`` table.
"""

from __future__ import annotations

import logging
import queue
import secrets
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threatlens.config import Settings
from threatlens.ingest.files import ingest_path
from threatlens.ingest.pipeline import BatchReport, IngestOptions
from threatlens.storage.db import connect, transaction
from threatlens.timeutil import now_ms

log = logging.getLogger(__name__)
MAX_JOBS_KEPT = 200


@dataclass(slots=True)
class Job:
    id: str
    file_name: str
    path: Path
    opts: IngestOptions
    size: int
    state: str = "queued"  # queued | running | done | failed
    created_at: int = field(default_factory=now_ms)
    lines: int = 0
    inserted: int = 0
    duplicates: int = 0
    malformed: int = 0
    batch_ids: list[int] = field(default_factory=list)
    error: str | None = None
    task: Callable[[], str] | None = None  # non-ingest work (retro-hunt)
    result: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "file_name": self.file_name,
            "state": self.state,
            "size": self.size,
            "lines": self.lines,
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "malformed": self.malformed,
            "batch_ids": self.batch_ids,
            "error": self.error,
        }


class IngestWorker:
    def __init__(
        self,
        settings: Settings,
        default_timezone: Callable[[], str],
        on_batch: Callable[[BatchReport], None] | None = None,
    ) -> None:
        self.settings = settings
        self.default_timezone = default_timezone
        self.on_batch = on_batch
        self.jobs: dict[str, Job] = {}
        self._unsaved: dict[int, str] = {}  # batch id -> error, for failures not yet saved
        self._queue: queue.Queue[Job | None] = queue.Queue()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def upload_dir(self) -> Path:
        return self.settings.data_dir / "uploads"

    def start(self) -> None:
        self.upload_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Uploads left over from a crash or restart were never ingested: remove them.
        for leftover in self.upload_dir.glob("*.upload"):
            leftover.unlink(missing_ok=True)
        self._thread = threading.Thread(target=self._run, name="ingest-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread:
            self._queue.put(None)
            self._thread.join(timeout=10)

    def new_upload_path(self) -> Path:
        # Random server-side name, outside any served directory; the original name is
        # kept only as display text.
        return self.upload_dir / f"{secrets.token_hex(16)}.upload"

    def submit(self, path: Path, file_name: str, opts: IngestOptions) -> Job:
        job = Job(
            id=secrets.token_urlsafe(12),
            file_name=file_name,
            path=path,
            opts=opts,
            size=path.stat().st_size,
        )
        with self._lock:
            self.jobs[job.id] = job
            while len(self.jobs) > MAX_JOBS_KEPT:
                oldest = next(iter(self.jobs))
                if self.jobs[oldest].state in ("queued", "running"):
                    break
                del self.jobs[oldest]
        self._queue.put(job)
        return job

    def recent(self, limit: int = 20) -> list[Job]:
        with self._lock:
            return list(reversed(list(self.jobs.values())))[:limit]

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def idle(self) -> bool:
        return all(j.state in ("done", "failed") for j in list(self.jobs.values()))

    def submit_task(self, name: str, fn: Callable[[], str]) -> Job:
        """Queue a non-ingest task (e.g. a retro-hunt) on the same single writer."""
        job = Job(
            id=secrets.token_urlsafe(12),
            file_name=name,
            path=Path(),
            opts=IngestOptions(),
            size=0,
            task=fn,
        )
        with self._lock:
            self.jobs[job.id] = job
        self._queue.put(job)
        return job

    def _run(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                return
            if job.task is not None:
                self._run_task(job)
            else:
                self._process(job)

    @staticmethod
    def _run_task(job: Job) -> None:
        job.state = "running"
        try:
            assert job.task is not None  # noqa: S101
            job.error = None
            job.result = job.task()
            job.state = "done"
        except Exception as exc:
            log.exception("task failed", extra={"job": job.id})
            job.state, job.error = "failed", f"internal error: {type(exc).__name__}"

    def _save_failures(self, conn: sqlite3.Connection) -> None:
        """Write batch failures that could not be saved when they happened (full disk)."""
        for batch_id, error in list(self._unsaved.items()):
            try:
                with transaction(conn):
                    conn.execute(
                        "UPDATE ingest_batches SET status = 'failed', finished_at = ?, "
                        "error = ? WHERE id = ? AND status = 'running'",
                        (now_ms(), error, batch_id),
                    )
            except sqlite3.Error:
                return  # still no room; try again with the next job
            del self._unsaved[batch_id]

    def _process(self, job: Job) -> None:
        job.state = "running"
        conn = connect(self.settings.db_path)
        self._save_failures(conn)
        base = {"lines": 0, "inserted": 0, "duplicates": 0, "malformed": 0}

        def progress(rep: BatchReport) -> None:
            job.lines = base["lines"] + rep.lines
            job.inserted = base["inserted"] + rep.inserted
            job.duplicates = base["duplicates"] + rep.duplicates
            job.malformed = base["malformed"] + rep.malformed

        try:
            reports = ingest_path(
                conn,
                job.path,
                job.opts,
                default_timezone=self.default_timezone(),
                max_bytes=self.settings.max_decompressed_mb * 1024 * 1024,
                display_name=job.file_name,
                progress=progress,
            )
            for rep in reports:
                if rep.status == "failed":
                    self._unsaved[rep.batch_id] = rep.error or "failed"
                job.batch_ids.append(rep.batch_id)
                for key in base:
                    base[key] += getattr(rep, key)
                if self.on_batch and rep.chunks:  # also the stored part of a failed batch
                    self.on_batch(rep)
            job.lines, job.inserted = base["lines"], base["inserted"]
            job.duplicates, job.malformed = base["duplicates"], base["malformed"]
            failed = [r for r in reports if r.status == "failed"]
            job.state = "failed" if failed and len(failed) == len(reports) else "done"
            job.error = "; ".join(r.error or "" for r in failed) or None
        except Exception as exc:
            log.exception("ingest job failed", extra={"job": job.id})
            job.state, job.error = "failed", f"internal error: {type(exc).__name__}"
        finally:
            self._save_failures(conn)  # a no-op unless a failure was not saved yet
            conn.close()
            if self.settings.delete_uploads:
                job.path.unlink(missing_ok=True)
            else:  # TL_DELETE_UPLOADS=false: keep a copy outside the startup cleanup
                kept = self.upload_dir / "kept"
                kept.mkdir(mode=0o700, exist_ok=True)
                job.path.rename(kept / job.path.name)
