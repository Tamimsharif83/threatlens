"""Phase 8: whole-app security checks.

Instead of testing routes one by one, these tests walk every registered route,
so a route added later without login, CSRF or the admin check fails here.
"""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from tests.conftest import ADMIN_PASSWORD, login, page_csrf
from tests.test_web_phase1 import XSS, analyst, assert_inert, text, upload, wait_idle
from threatlens.config import Settings
from threatlens.detection.compiler import catastrophic_regex
from threatlens.detection.loader import lint, load_rules
from threatlens.search.hunt import MAX_VALUE_BYTES, run_hunt
from threatlens.storage.db import init_db, transaction
from threatlens.synth import web_lines
from threatlens.web import deps
from threatlens.web.app import create_app

PUBLIC = {("GET", "/login"), ("POST", "/login"), ("GET", "/healthz")}
ADMIN = {
    ("GET", "/audit"),
    ("GET", "/settings"),
    ("POST", "/settings/general"),
    ("POST", "/settings/users"),
    ("POST", "/settings/users/{user_id}/{action}"),
    ("POST", "/settings/maintenance/{action}"),
}
# Values for path parameters: syntactically valid, pointing at nothing.
PATH_VALUES = {
    "batch_id": "999",
    "rule_id": "00000000-0000-0000-0000-000000000000",
    "action": "enable",
    "alert_id": "999",
    "table": "ev_webserver",
    "event_id": "999",
    "hunt_id": "999",
    "sid": "999",
    "case_id": "999",
    "fmt": "csv",
    "user_id": "999",
}


def _calls(dependant) -> set[object]:  # type: ignore[no-untyped-def]
    out: set[object] = set()
    for sub in dependant.dependencies:
        out.add(sub.call)
        out |= _calls(sub)
    return out


def _walk(routes) -> Iterator[APIRoute]:  # type: ignore[no-untyped-def]
    for r in routes:
        if isinstance(r, APIRoute):
            yield r
        elif hasattr(r, "original_router"):  # FastAPI's included-router wrapper
            yield from _walk(r.original_router.routes)


def _routes() -> list[tuple[str, str, str]]:
    """(method, path template, level) for every route of the app."""
    app = create_app(Settings(data_dir=Path("/nonexistent")))  # type: ignore[call-arg]
    out = []
    for route in _walk(app.routes):
        calls = _calls(route.dependant)
        level = (
            "admin"
            if deps.require_admin in calls
            else "session"
            if deps.require_session in calls
            else "public"
        )
        out.extend((m, route.path, level) for m in sorted(route.methods - {"HEAD"}))
    return out


ROUTES = _routes()


def _url(path: str) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: PATH_VALUES[m.group(1)], path)


def test_route_inventory() -> None:
    """Every route is public, logged-in or admin-only, as listed here, on purpose."""
    assert len(ROUTES) >= 45
    levels = {(m, p): lvl for m, p, lvl in ROUTES}
    assert {k for k, v in levels.items() if v == "public"} == PUBLIC
    assert {k for k, v in levels.items() if v == "admin"} == ADMIN
    assert set(PATH_VALUES) >= {name for _, p, _ in ROUTES for name in re.findall(r"\{(\w+)\}", p)}


@pytest.mark.parametrize(("method", "path"), [(m, p) for m, p, lvl in ROUTES if lvl != "public"])
def test_every_route_requires_login(client: TestClient, method: str, path: str) -> None:
    resp = client.request(method, _url(path), follow_redirects=False)
    if path.startswith("/api/") or path == "/openapi.json":
        assert resp.status_code == 401, (method, path)
    else:
        assert resp.status_code == 303, (method, path)
        assert resp.headers["location"].startswith("/login")


@pytest.mark.parametrize(
    ("method", "path"), [(m, p) for m, p, lvl in ROUTES if lvl != "public" and m != "GET"]
)
def test_every_write_requires_csrf(authed: TestClient, method: str, path: str) -> None:
    resp = authed.request(method, _url(path), data={"x": "1"}, follow_redirects=False)
    assert resp.status_code == 403, (method, path)
    wrong = authed.request(
        method, _url(path), headers={"X-CSRF-Token": "forged"}, follow_redirects=False
    )
    assert wrong.status_code == 403, (method, path)


def test_analyst_refused_on_every_admin_route(client: TestClient, db: sqlite3.Connection) -> None:
    analyst(client, db)
    csrf = page_csrf(client.get("/").text)
    for method, path in sorted(ADMIN):
        resp = client.request(
            method,
            _url(path),
            headers={"X-CSRF-Token": csrf},
            data={"username": "mallory", "role": "admin"},
            follow_redirects=False,
        )
        assert resp.status_code == 403, (method, path)
    assert db.execute("SELECT count(*) FROM users WHERE username = 'mallory'").fetchone()[0] == 0
    # extra form fields on the account form do not change the role
    client.post(
        "/account",
        data={
            "csrf_token": csrf,
            "current_password": "analyst-password-1",
            "new_password": "analyst-password-2",
            "confirm_password": "analyst-password-2",
            "role": "admin",
        },
    )
    assert client.get("/api/v1/me").json()["role"] == "analyst"


# ---------------------------------------------------------------- hostile input


EVIL = ["'", '" OR 1=1 --', "-1", "99999999999999999999", "%00", "\x00", "../../etc/passwd", XSS]
QUERY_PARAMS = [
    "q",
    "page",
    "sort",
    "status",
    "level",
    "table",
    "start",
    "end",
    "f1",
    "op1",
    "v1",
    "before",
    "saved",
    "covered",
    "run",
    "rule_id",
    "field",
    "value",
    "order",
    "limit",
    "interval",
]


def test_hostile_query_strings_never_crash(authed: TestClient) -> None:
    """No GET page answers 500 (or reflects markup) whatever the query string holds."""
    upload(authed, [("access.log", text(web_lines(500, seed=3)))])
    wait_idle(authed)
    gets = [_url(p) for m, p, lvl in ROUTES if m == "GET" and lvl != "public"]
    for url in gets:
        for value in EVIL:
            params = dict.fromkeys(QUERY_PARAMS, value)
            resp = authed.get(url, params=params, follow_redirects=False)
            assert resp.status_code < 500, (url, value, resp.text[:300])
            if resp.headers.get("content-type", "").startswith("text/html"):
                assert_inert(resp.text)


@pytest.mark.parametrize(
    "path",
    [
        "/events/users/1",
        "/events/sessions/1",
        "/events/sqlite_master/1",
        "/events/ev_webserver;DROP TABLE alerts/1",
        "/cases/1/iocs.exe",
        "/static/../threatlens.db",
        "/static/%2e%2e/%2e%2e/config.py",
        "/alerts/99999999999999999999",
        "/cases/99999999999999999999/report.md",
        "/ingest/batches/-99999999999999999999",
        "/events/ev_webserver/99999999999999999999",
    ],
)
def test_path_tricks_are_refused(authed: TestClient, path: str) -> None:
    resp = authed.get(path, follow_redirects=False)
    assert resp.status_code in {400, 404, 422}, (path, resp.status_code)
    assert "password_hash" not in resp.text


def test_upload_filename_cannot_escape(authed: TestClient, settings: Settings) -> None:
    for name in ["../../../../tmp/evil.log", "..\\..\\evil.log", "/etc/cron.d/x.log"]:
        upload(authed, [(name, b"Jan  1 00:00:00 h sshd[1]: hello\n")])
    wait_idle(authed)
    assert not Path("/tmp/evil.log").exists()  # noqa: S108 - the path the attack aims at
    data = settings.data_dir.resolve()
    for p in data.rglob("*"):
        assert p.resolve().is_relative_to(data)


def test_oversized_and_overlong_form_fields(authed: TestClient) -> None:
    csrf = page_csrf(authed.get("/account").text)
    resp = authed.post(
        "/account",
        data={
            "csrf_token": csrf,
            "current_password": ADMIN_PASSWORD,
            "new_password": "x" * 5000,
            "confirm_password": "x" * 5000,
        },
    )
    assert resp.status_code == 400 and "at most" in resp.text
    huge = authed.post("/hunt", data={"csrf_token": csrf, "sql": "SELECT 1 " + " " * 200_000})
    assert huge.status_code < 500


def test_password_change_is_throttled(authed: TestClient, settings: Settings) -> None:
    csrf = page_csrf(authed.get("/account").text)
    form = {"csrf_token": csrf, "new_password": "n" * 16, "confirm_password": "n" * 16}
    for i in range(settings.login_max_failures):
        resp = authed.post("/account", data={**form, "current_password": f"guess-{i}"})
        assert "Current password is wrong" in resp.text
    blocked = authed.post("/account", data={**form, "current_password": ADMIN_PASSWORD})
    assert blocked.status_code == 400 and "Too many wrong passwords" in blocked.text


# ---------------------------------------------------------------- hunt console


@pytest.fixture
def hunt_db(tmp_path: Path) -> Path:
    db = tmp_path / "h.db"
    init_db(db)
    return db


def test_hunt_audit_log_is_admin_only(hunt_db: Path) -> None:
    sql = "SELECT count(*) FROM audit_log"
    assert run_hunt(hunt_db, sql, row_limit=5, timeout_s=5).error
    assert run_hunt(hunt_db, sql, row_limit=5, timeout_s=5, admin=True).error is None
    for table in ("users", "sessions"):
        r = run_hunt(hunt_db, f"SELECT * FROM {table}", row_limit=5, timeout_s=5, admin=True)
        assert r.error, table


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT length(printf('%.*c', 900000000, 'x'))",
        "SELECT length(zeroblob(900000000))",
        "SELECT length(randomblob(900000000))",
        "SELECT length(replace(hex(zeroblob(100000000)), '0', '00'))",
    ],
)
def test_hunt_cannot_allocate_huge_values(hunt_db: Path, sql: str) -> None:
    r = run_hunt(hunt_db, sql, row_limit=5, timeout_s=5)
    # refused with an error, or (printf) a NULL instead of the value: never allocated
    assert (r.error and f"{MAX_VALUE_BYTES // 2**20} MiB" in r.error) or r.rows == [[None]]


def test_hunt_refuses_catastrophic_regex(hunt_db: Path) -> None:
    started = time.monotonic()
    r = run_hunt(
        hunt_db,
        "SELECT 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' REGEXP '(a+)+$'",
        row_limit=5,
        timeout_s=5,
    )
    assert r.error and "REGEXP pattern refused" in r.error
    assert time.monotonic() - started < 2
    fine = run_hunt(hunt_db, "SELECT 'GET /x' REGEXP '(?i)^get\\s+/'", row_limit=5, timeout_s=5)
    assert fine.error is None and fine.rows == [[1]]


def test_hunt_page_hides_audit_log_from_analysts(
    client: TestClient, db: sqlite3.Connection
) -> None:
    analyst(client, db)
    page = client.get("/hunt").text
    assert "audit_log (admins only)" in page
    csrf = page_csrf(page)
    resp = client.post("/hunt", data={"csrf_token": csrf, "sql": "SELECT * FROM audit_log"})
    assert resp.status_code == 400 and "not allowed" in resp.text


@pytest.mark.parametrize(
    ("pattern", "risky"),
    [
        (r"(a+)+$", True),
        (r"(\w+\s?)*x", True),
        (r"(?:a|b+)*", True),
        (r"((ab)*)*", True),
        (r"(?=(a+)+)b", True),
        (r"(?>(a+)+)", True),
        (r"(a+){1,30}", True),
        (r"(a|b)*c", False),
        (r"(?>a+)+", False),
        (r"(a++)+", False),
        (r"(a{2})+", False),
        (r"(a?){3}", False),
        (r"(?i)union.*select", False),
        (r"^\d{4}-\d{2}", False),
        (r"[", False),
    ],
)
def test_catastrophic_regex_detector(pattern: str, risky: bool) -> None:
    assert catastrophic_regex(pattern) is risky


def test_lint_warns_on_catastrophic_regex(tmp_path: Path) -> None:
    (tmp_path / "r.yml").write_text(
        "title: t\nid: 70000000-0000-0000-0000-000000000009\nlogsource: {category: webserver}\n"
        "detection:\n  sel:\n    cs-uri-query|re: '(a+)+b'\n  ok:\n    cs-method|re: '^GET$'\n"
        "  condition: sel or ok\ntags: [attack.t1190]\n"
    )
    messages = [i.message for i in lint(load_rules([(tmp_path, "user")]))]
    assert sum("nests repeats" in m for m in messages) == 1


# ---------------------------------------------------------------- alert page


def test_alert_events_are_paged_and_folded(authed: TestClient, db: sqlite3.Connection) -> None:
    upload(authed, [("access.log", text(web_lines(3000, seed=8)))])
    wait_idle(authed)
    aid, rule_id = db.execute("SELECT id, rule_id FROM alerts ORDER BY id LIMIT 1").fetchone()
    ids = [
        r[0] for r in db.execute("SELECT tl_id, tl_ts FROM ev_webserver ORDER BY tl_id LIMIT 80")
    ]
    with transaction(db):
        db.executemany(
            "INSERT OR IGNORE INTO alert_events (rule_id, table_name, event_id, alert_id, "
            "event_ts) SELECT ?, 'ev_webserver', tl_id, ?, tl_ts FROM ev_webserver "
            "WHERE tl_id = ?",
            [(rule_id, aid, i) for i in ids],
        )
    linked = db.execute("SELECT count(*) FROM alert_events WHERE alert_id = ?", (aid,)).fetchone()[
        0
    ]
    assert linked > 50
    pages = -(-linked // 25)
    first = authed.get(f"/alerts/{aid}").text
    assert first.count('class="event-card"') == 25
    assert f"Page 1 of {pages}" in first and "Later" in first and "Earlier" not in first
    assert "more fields" in first and "<details" in first
    last = authed.get(f"/alerts/{aid}?page={pages}").text
    assert last.count('class="event-card"') == linked - 25 * (pages - 1)
    assert "Earlier" in last and "Later &rarr;" not in last
    assert authed.get(f"/alerts/{aid}?page=999").text.count('class="event-card"') == (
        linked - 25 * (pages - 1)
    )
    assert authed.get(f"/alerts/{aid}?page=-5").text.count('class="event-card"') == 25


def test_logout_everywhere_on_password_change(client: TestClient, settings: Settings) -> None:
    """Changing the password ends the user's other sessions."""
    other = TestClient(create_app(settings))
    with other:
        login(client)
        login(other)
        assert other.get("/api/v1/me").status_code == 200
        csrf = page_csrf(client.get("/account").text)
        client.post(
            "/account",
            data={
                "csrf_token": csrf,
                "current_password": ADMIN_PASSWORD,
                "new_password": "another-long-password",
                "confirm_password": "another-long-password",
            },
        )
        assert client.get("/api/v1/me").status_code == 200
        assert other.get("/api/v1/me").status_code == 401


def test_xss_in_event_cards(authed: TestClient, db: sqlite3.Connection) -> None:
    line = f'203.0.113.9 - - [10/Oct/2025:13:55:36 +0000] "GET /x?id=1%27%20UNION%20SELECT%20{XSS} HTTP/1.1" 200 5 "-" "{XSS}"'
    upload(authed, [("access.log", text([line]))])
    wait_idle(authed)
    for (aid,) in db.execute("SELECT id FROM alerts").fetchall():
        assert_inert(authed.get(f"/alerts/{aid}").text)


@pytest.mark.parametrize("parser", ["ecs-json", "json", "evtx"])
def test_deep_or_wide_json_is_malformed_not_fatal(parser: str) -> None:
    from threatlens.parsers import make_parser  # noqa: PLC0415
    from threatlens.parsers.base import ParseContext, ParseError  # noqa: PLC0415

    ts = '"@timestamp":"2025-01-01T00:00:00Z"'
    deep = "{" + ts + ',"a":' + "[" * 100_000 + "]" * 100_000 + "}"
    with pytest.raises(ParseError):
        make_parser(parser).parse(deep, ParseContext())
    wide = "{" + ts + "," + ",".join(f'"k{i}":{i}' for i in range(20_000)) + "}"
    if parser != "evtx":
        assert len(make_parser(parser).parse(wide, ParseContext()).fields) <= 1000


# ---------------------------------------------------------------- crash recovery


def test_interrupted_batch_is_closed_and_its_events_detected(tmp_path: Path) -> None:
    """A crash mid-ingest leaves a 'running' batch whose stored events no rule has seen.
    The next start marks it failed (so retention can purge it) and runs the rules on it."""
    from threatlens.ingest.files import ingest_path  # noqa: PLC0415
    from threatlens.ingest.pipeline import INTERRUPTED, IngestOptions  # noqa: PLC0415
    from threatlens.storage.db import connect  # noqa: PLC0415

    s = Settings(  # type: ignore[call-arg]
        data_dir=tmp_path / "d", admin_password=ADMIN_PASSWORD, watch_enabled=False
    )
    s.ensure_dirs()
    init_db(s.db_path)
    log = tmp_path / "access.log"
    log.write_text("\n".join(web_lines(3000, seed=8)) + "\n")
    conn = connect(s.db_path)
    [rep] = ingest_path(conn, log, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
    with transaction(conn):  # what a kill -9 during the batch leaves behind
        conn.execute("UPDATE ingest_batches SET status = 'running' WHERE id = ?", (rep.batch_id,))
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0
    with TestClient(create_app(s)) as client:
        login(client)
        wait_idle(client)
        status, error, detection = conn.execute(
            "SELECT status, error, detection FROM ingest_batches WHERE id = ?", (rep.batch_id,)
        ).fetchone()
        assert (status, error, detection) == ("failed", INTERRUPTED, "done")
        assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] > 0
        assert "detection catch-up" in client.get("/ingest").text
    # nothing pending: the next start queues no catch-up job
    with TestClient(create_app(s)) as client:
        login(client)
        assert "detection catch-up" not in client.get("/ingest").text
    conn.close()


def test_failed_upload_still_detects_its_stored_events(
    authed: TestClient, db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch that fails half-way (here: a compression bomb after real lines) keeps the
    events stored before the failure; the rules must still see them."""
    import gzip  # noqa: PLC0415

    from threatlens.ingest import readers  # noqa: PLC0415

    monkeypatch.setattr(readers, "RATIO_GRACE", 2 * 1024 * 1024)
    head = "\n".join(web_lines(3000, seed=8)) + "\n"
    payload = gzip.compress((head + ("A" * 200 + "\n") * 200_000).encode())
    upload(authed, [("access.log.gz", payload)])
    wait_idle(authed)
    status, inserted, detection = db.execute(
        "SELECT status, events_inserted, detection FROM ingest_batches ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert status == "failed" and inserted > 0 and detection == "done"
    assert db.execute("SELECT count(*) FROM alerts").fetchone()[0] > 0


def test_full_disk_fails_the_batch_with_a_clear_message(tmp_path: Path) -> None:
    """A real SQLITE_FULL in the middle of an ingest (the database may not grow past
    ``max_page_count``): the batch ends 'failed' with the reason instead of staying
    'running', the chunks already written are kept, and the rollback does not replace
    the error with "cannot rollback - no transaction is active"."""
    from threatlens.ingest import pipeline  # noqa: PLC0415
    from threatlens.ingest.files import ingest_path  # noqa: PLC0415
    from threatlens.storage.db import connect  # noqa: PLC0415

    db_path = tmp_path / "t.db"
    init_db(db_path)
    conn = connect(db_path)
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    conn.execute(f"PRAGMA max_page_count = {pages + 400}")  # ~1.6 MB more
    log = tmp_path / "access.log"
    log.write_text("\n".join(web_lines(30_000, seed=8)) + "\n")
    [rep] = ingest_path(
        conn, log, pipeline.IngestOptions(), default_timezone="UTC", max_bytes=2**30
    )
    status, error = conn.execute(
        "SELECT status, error FROM ingest_batches WHERE id = ?", (rep.batch_id,)
    ).fetchone()
    assert status == "failed", (status, error)
    assert "full" in error and "free space" in error
    assert 0 < rep.inserted < 30_000  # what was committed before the disk filled stays
    conn.close()


# ---------------------------------------------------------------- scale


def test_top_values_merge_counts_across_tables(tmp_path: Path) -> None:
    """Grouping per table and then summing gives the same answer as counting all rows."""
    from collections import Counter  # noqa: PLC0415

    from threatlens import stats  # noqa: PLC0415
    from threatlens.ingest.files import ingest_path  # noqa: PLC0415
    from threatlens.ingest.pipeline import IngestOptions  # noqa: PLC0415
    from threatlens.storage.db import connect  # noqa: PLC0415
    from threatlens.synth import auth_lines  # noqa: PLC0415

    db_path = tmp_path / "t.db"
    init_db(db_path)
    conn = connect(db_path)
    for name, lines in (("access.log", web_lines(4000, seed=3)), ("auth.log", auth_lines(4000))):
        p = tmp_path / name
        p.write_text("\n".join(lines) + "\n")
        ingest_path(conn, p, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
    start = stats.data_window(conn)[0]  # type: ignore[index]
    expected: Counter[str] = Counter()
    for table in ("ev_webserver", "ev_linux_auth"):
        for (ip,) in conn.execute(
            f'SELECT "source.ip" FROM {table} WHERE tl_ts >= ? AND "source.ip" IS NOT NULL',
            (start,),
        ):
            expected[ip] += 1
    top = stats.top_values(conn, "source.ip", 5)
    assert [n for _, n in top] == [n for _, n in expected.most_common(5)]
    assert {v for v, _ in top} <= set(expected)
    shared = {r[0] for r in conn.execute('SELECT "source.ip" FROM ev_webserver')} & {
        r[0] for r in conn.execute('SELECT "source.ip" FROM ev_linux_auth')
    }
    assert shared  # the synthetic attackers appear in both logs, so sums really merge
    conn.close()
