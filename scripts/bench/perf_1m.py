"""End-to-end performance run: ingest 1M log lines with detection, then time the UI.

Run from a checkout (dev dependencies installed):

    uv run python scripts/bench/perf_1m.py                 # 1,000,000 web lines
    uv run python scripts/bench/perf_1m.py --lines 200000  # quicker
    uv run python scripts/bench/perf_1m.py --keep /tmp/tl  # keep the data dir

What it measures (results are printed as a Markdown table; see docs/performance.md):

1. ingest: lines/s, rejected lines, peak memory (RSS), database size; the shipped
   example rules run on every chunk, as in production;
2. pages: the web UI over that database, through the real FastAPI app (login,
   CSRF, templates): overview, alert queue, an alert, field search, hunt console,
   coverage, metrics, the events-over-time API;
3. a retro-hunt of every enabled rule over all events.

The data is synthetic (`threatlens.synth.web_lines`, seeded): ~0.5 % attack
traffic mixed into normal requests, so the rules have something to find.
"""

from __future__ import annotations

import argparse
import gzip
import re
import resource
import shutil
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from threatlens.config import Settings
from threatlens.detection.engine import DetectionEngine
from threatlens.ingest.files import ingest_path
from threatlens.ingest.pipeline import IngestOptions
from threatlens.storage.db import connect, init_db
from threatlens.synth import web_lines
from threatlens.web.app import create_app

PASSWORD = "benchmark-password-123"
CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


def rss_mb() -> float:
    """Current resident memory of this process, MiB."""
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024
    return 0.0


def peak_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


@contextmanager
def timed() -> Iterator[list[float]]:
    out: list[float] = []
    start = time.perf_counter()
    yield out
    out.append(time.perf_counter() - start)


def write_log(path: Path, lines: int, seed: int) -> None:
    opener: Callable[..., Any] = gzip.open if path.suffix == ".gz" else open
    with opener(path, "wt", encoding="utf-8") as fh:
        for line in web_lines(lines, seed=seed):
            fh.write(line + "\n")


def page_times(settings: Settings, rows: list[tuple[str, str]]) -> None:
    with TestClient(create_app(settings)) as client:
        token = CSRF.search(client.get("/login").text)
        assert token
        resp = client.post(
            "/login",
            data={"username": "admin", "password": PASSWORD, "csrf_token": token.group(1)},
            follow_redirects=False,
        )
        assert resp.status_code == 303, resp.text[:300]
        with closing(connect(settings.db_path)) as conn:
            alert = conn.execute(
                "SELECT id FROM alerts ORDER BY event_count DESC LIMIT 1"
            ).fetchone()
            ip = conn.execute(
                'SELECT "source.ip" FROM ev_webserver WHERE tl_id = 500000 OR tl_id = 1 '
                "ORDER BY tl_id DESC LIMIT 1"
            ).fetchone()[0]
        meta = re.search(r'<meta name="csrf-token" content="([^"]*)">', client.get("/").text)
        assert meta
        hunt_sql = (
            'SELECT "source.ip", count(*) AS n FROM ev_webserver '
            'WHERE "http.response.status_code" >= 400 GROUP BY 1 ORDER BY n DESC LIMIT 20'
        )
        pages: list[tuple[str, Callable[[], Any]]] = [
            ("Overview `/`", lambda: client.get("/")),
            ("Alert queue `/alerts`", lambda: client.get("/alerts")),
            (
                "Alert detail (largest alert)",
                lambda: client.get(f"/alerts/{alert[0]}") if alert else None,
            ),
            (
                "Field search, `source.ip = …` (indexed pivot field)",
                lambda: client.get(
                    "/search",
                    params={
                        "run": 1,
                        "table": "ev_webserver",
                        "f1": "source.ip",
                        "op1": "eq",
                        "v1": ip,
                    },
                ),
            ),
            (
                "Field search, `url.original contains …` (full scan)",
                lambda: client.get(
                    "/search",
                    params={
                        "run": 1,
                        "table": "ev_webserver",
                        "f1": "url.original",
                        "op1": "contains",
                        "v1": "passwd",
                    },
                ),
            ),
            (
                "Hunt console, GROUP BY over all events",
                lambda: client.post("/hunt", data={"csrf_token": meta.group(1), "sql": hunt_sql}),
            ),
            ("ATT&CK coverage `/coverage`", lambda: client.get("/coverage")),
            ("Rule metrics `/metrics`", lambda: client.get("/metrics")),
            ("Events-over-time API", lambda: client.get("/api/v1/stats/events-over-time")),
        ]
        for label, call in pages:
            call()  # warm the page cache once, as a browser session would
            with timed() as t:
                resp = call()
            if resp is not None:
                assert resp.status_code < 400, (label, resp.status_code, resp.text[:300])
            rows.append((label, f"{t[0] * 1000:,.0f} ms"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--lines", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--gzip", action="store_true", help="ingest a .log.gz instead of .log")
    ap.add_argument("--keep", type=Path, help="data directory to keep (default: temporary)")
    args = ap.parse_args()

    work = args.keep or Path(tempfile.mkdtemp(prefix="tl-perf-"))
    if work.exists() and args.keep:
        shutil.rmtree(work)
    settings = Settings(  # type: ignore[call-arg]
        data_dir=work / "data", admin_password=PASSWORD, watch_enabled=False
    )
    settings.ensure_dirs()
    init_db(settings.db_path)
    log = work / ("access.log.gz" if args.gzip else "access.log")
    rows: list[tuple[str, str]] = []

    with timed() as t:
        write_log(log, args.lines, args.seed)
    print(
        f"generated {args.lines:,} lines ({log.stat().st_size / 2**20:,.0f} MiB) in {t[0]:.1f} s",
        file=sys.stderr,
    )

    base_rss = rss_mb()
    with closing(connect(settings.db_path)) as conn:
        engine = DetectionEngine(settings)
        engine.reload(conn, "bench")
        with timed() as t:
            reports = ingest_path(
                conn, log, IngestOptions(), default_timezone="UTC", max_bytes=2**40
            )
            for rep in reports:
                engine.run_ranges(conn, rep.chunks)
        rep = reports[0]
        alerts = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
        rows += [
            (
                "Events stored",
                f"{rep.inserted:,} ({rep.malformed:,} rejected, {rep.duplicates:,} duplicates)",
            ),
            ("Ingest + detection, wall time", f"{t[0]:.1f} s"),
            ("Throughput", f"{args.lines / t[0]:,.0f} lines/s"),
            ("Alerts raised", f"{alerts:,}"),
            (
                "Peak memory (RSS) of the process",
                f"{peak_mb():,.0f} MiB (baseline {base_rss:,.0f} MiB)",
            ),
        ]
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db_mb = settings.db_path.stat().st_size / 2**20
        rows.append(
            (
                "Database size",
                f"{db_mb:,.0f} MiB "
                f"({db_mb * 2**20 / args.lines:,.0f} bytes/event; "
                f"input {log.stat().st_size / 2**20:,.0f} MiB)",
            )
        )

        rule_ids = [
            r[0]
            for r in conn.execute("SELECT id FROM rules WHERE enabled = 1 AND kind = 'detection'")
        ]
        with timed() as t:
            for rule_id in rule_ids:
                engine.retro_hunt(conn, rule_id)
        rows.append(
            (f"Retro-hunt: {len(rule_ids)} detection rules over all events", f"{t[0]:.1f} s")
        )

    page_times(settings, rows)
    rows.append(("Peak memory (RSS), whole run", f"{peak_mb():,.0f} MiB"))

    print(f"\n| Measure ({args.lines:,} web log lines) | Result |\n|---|---|")
    for k, v in rows:
        print(f"| {k} | {v} |")
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
