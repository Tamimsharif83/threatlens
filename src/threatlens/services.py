"""Background services started with the web app: ingest worker, inbox watcher
and the maintenance scheduler (retention purge, expired sessions)."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from threatlens import runtime_settings
from threatlens.auth.sessions import purge_expired
from threatlens.config import Settings
from threatlens.detection.engine import DetectionEngine
from threatlens.ingest.jobs import IngestWorker
from threatlens.ingest.pipeline import BatchReport, mark_detection, pending_detection
from threatlens.ingest.watch import InboxWatcher
from threatlens.storage.db import connect, transaction
from threatlens.storage.maintenance import purge

log = logging.getLogger(__name__)
MAINTENANCE_INTERVAL_S = 6 * 3600

BatchHook = Callable[[BatchReport], None]


class Services:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._batch_hooks: list[BatchHook] = []
        self.detection = DetectionEngine(settings)
        self._batch_hooks.append(self._detect)
        self.worker = IngestWorker(settings, self.default_timezone, self._on_batch)
        self.watcher = InboxWatcher(settings, self.default_timezone, self._on_batch)
        self._stop = threading.Event()
        self._maintenance: threading.Thread | None = None

    def add_batch_hook(self, hook: BatchHook) -> None:
        """Called after every successfully ingested batch (detection hooks in here)."""
        self._batch_hooks.append(hook)

    def _on_batch(self, report: BatchReport) -> None:
        for hook in self._batch_hooks:
            try:
                hook(report)
            except Exception:
                log.exception("batch hook failed", extra={"batch": report.batch_id})

    def _detect(self, report: BatchReport) -> None:
        """Detection on every newly ingested batch."""
        if not report.chunks:
            return
        conn = connect(self.settings.db_path)
        try:
            run = self.detection.run_ranges(conn, report.chunks)
            with transaction(conn):
                mark_detection(conn, report.batch_id, "done")
        finally:
            conn.close()
        if run.result.new_alerts or run.errors:
            log.info(
                "detection",
                extra={
                    "batch": report.batch_id,
                    "new_alerts": len(run.result.new_alerts),
                    "events": run.result.events,
                    "errors": run.errors,
                },
            )

    def _catch_up(self) -> str:
        """Run the rules on batches stored but never checked (crash, restart, old failure)."""
        conn = connect(self.settings.db_path)
        try:
            pending = pending_detection(conn)
            events = 0
            for batch_id, chunks in pending:
                if chunks:
                    events += self.detection.run_ranges(conn, chunks).result.events
                with transaction(conn):
                    mark_detection(conn, batch_id, "done")
        finally:
            conn.close()
        if pending:
            log.info(
                "detection catch-up",
                extra={"batches": len(pending), "matching_events": events},
            )
        return f"{len(pending)} batch(es) checked, {events} matching event(s)"

    def load_rules(self) -> None:
        conn = connect(self.settings.db_path)
        try:
            self.detection.reload(conn)
            self.detection.run_tests(conn)
        finally:
            conn.close()

    def default_timezone(self) -> str:
        conn = connect(self.settings.db_path)
        try:
            return runtime_settings.default_timezone(conn, self.settings)
        finally:
            conn.close()

    def start(self) -> None:
        self.settings.rules_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.load_rules()
        except Exception:  # a broken rule set must not stop the app from starting
            log.exception("loading rules failed")
        self.worker.start()
        conn = connect(self.settings.db_path)
        try:
            behind = bool(pending_detection(conn, limit=1))
        finally:
            conn.close()
        if behind:  # on the worker: it is the single writer
            self.worker.submit_task("detection catch-up", self._catch_up)
        if self.settings.watch_enabled:
            (self.settings.data_dir / "inbox").mkdir(mode=0o700, exist_ok=True)
            self.watcher.start()
        self._maintenance = threading.Thread(
            target=self._maintenance_loop, name="maintenance", daemon=True
        )
        self._maintenance.start()

    def stop(self) -> None:
        self._stop.set()
        self.watcher.stop()
        self.worker.stop()
        if self._maintenance:
            self._maintenance.join(timeout=10)

    def run_maintenance(self) -> None:
        conn = connect(self.settings.db_path)
        try:
            purge(conn, runtime_settings.retention_days(conn, self.settings))
            with transaction(conn):
                purge_expired(conn)
        finally:
            conn.close()

    def _maintenance_loop(self) -> None:
        # First run shortly after start-up, then every few hours.
        if self._stop.wait(30):
            return
        while True:
            try:
                self.run_maintenance()
            except Exception:
                log.exception("maintenance failed")
            if self._stop.wait(MAINTENANCE_INTERVAL_S):
                return
