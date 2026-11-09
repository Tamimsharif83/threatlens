"""Phase 3: triage, suppressions, search, the read-only hunt console and audit."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import login, page_csrf
from tests.test_web_phase1 import XSS, assert_inert, text, upload, wait_idle
from threatlens.alerts import suppress
from threatlens.alerts.triage import (
    TriageError,
    add_note,
    alert_events,
    assign,
    history,
    notes,
    set_status,
)
from threatlens.auth.users import Role, create_user
from threatlens.config import Settings
from threatlens.detection.engine import DetectionEngine
from threatlens.export import neutralize, to_csv
from threatlens.ingest.files import ingest_path
from threatlens.ingest.pipeline import IngestOptions
from threatlens.search.hunt import run_hunt
from threatlens.search.query import Condition, SearchError, SearchRequest, build, search
from threatlens.storage.db import connect, init_db, transaction
from threatlens.synth import web_lines

SQLI = "3815fe7c-7c88-4597-aa81-98ebaabeeb5f"


@pytest.fixture
def env(tmp_path: Path) -> Iterator[tuple[Settings, sqlite3.Connection]]:
    s = Settings(data_dir=tmp_path / "d", watch_enabled=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    init_db(s.db_path)
    with closing(connect(s.db_path)) as conn:
        with transaction(conn):
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES ('ana', 'x', 'analyst', 0), ('off', 'x', 'analyst', 0)"
            )
            conn.execute("UPDATE users SET disabled = 1 WHERE username = 'off'")
        engine = DetectionEngine(s)
        engine.reload(conn)
        p = tmp_path / "access.log"
        p.write_text("\n".join(web_lines(3000, seed=8)) + "\n")
        [rep] = ingest_path(conn, p, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
        engine.run_ranges(conn, rep.chunks)
        yield s, conn


def first_alert(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT min(id) FROM alerts").fetchone()[0])


# ---------------------------------------------------------------- triage


def test_status_resolution_assign_notes_history(env: tuple[Settings, sqlite3.Connection]) -> None:
    _, conn = env
    aid = first_alert(conn)
    with pytest.raises(TriageError, match="requires a resolution"):
        set_status(conn, [aid], "closed", None, "ana")
    with pytest.raises(TriageError, match="unknown status"):
        set_status(conn, [aid], "done", None, "ana")
    with transaction(conn):
        assert set_status(conn, [aid], "in_progress", "true_positive", "ana") == 1
    # resolution only applies when closing
    assert conn.execute("SELECT resolution FROM alerts WHERE id = ?", (aid,)).fetchone()[0] is None
    with transaction(conn):
        assert set_status(conn, [aid, 99999], "closed", "false_positive", "ana") == 1
        assert set_status(conn, [aid], "closed", "false_positive", "ana") == 0  # no-op
    with pytest.raises(TriageError, match="unknown or disabled"):
        assign(conn, [aid], "off", "ana")
    with transaction(conn):
        assert assign(conn, [aid], "ana", "ana") == 1
        assert assign(conn, [aid], None, "ana") == 1
        add_note(conn, aid, "ana", "  looked at it  ")
    with pytest.raises(TriageError, match="empty"):
        add_note(conn, aid, "ana", "   ")
    with pytest.raises(TriageError, match="longer"):
        add_note(conn, aid, "ana", "x" * 10_001)
    with pytest.raises(TriageError, match="not found"):
        add_note(conn, 99999, "ana", "x")
    assert [n.body for n in notes(conn, aid)] == ["looked at it"]
    actions = [h.action for h in history(conn, aid)]
    assert actions == ["alert.status", "alert.status", "alert.assign", "alert.assign", "alert.note"]


def test_alert_events_and_purged_events(env: tuple[Settings, sqlite3.Connection]) -> None:
    _, conn = env
    aid = first_alert(conn)
    events = alert_events(conn, aid)
    assert events and all(not e.purged for e in events)
    assert "url.query" in events[0].fields
    with transaction(conn):
        conn.execute("DELETE FROM ev_webserver WHERE tl_id = ?", (events[0].id,))
    assert alert_events(conn, aid)[0].purged


# ---------------------------------------------------------------- suppressions


def test_suppression_validation_and_matching(env: tuple[Settings, sqlite3.Connection]) -> None:
    _, conn = env
    bad = [
        {"field": "bad field!", "value": "x", "reason": "r"},
        {"field": "source.ip", "value": "", "reason": "r"},
        {"field": "source.ip", "value": "x", "reason": "  "},
        {"field": "source.ip", "value": "x", "reason": "r", "expires_at": 1},
        {"field": "source.ip", "value": "x", "reason": "r", "rule_id": "nope"},
    ]
    for kwargs in bad:
        with pytest.raises(suppress.SuppressionError):
            suppress.create(conn, actor="ana", **{"rule_id": None, **kwargs})  # type: ignore[arg-type]
    with transaction(conn):
        sid = suppress.create(
            conn,
            rule_id=SQLI,
            field="source.ip",
            value="203.0.113.66",
            reason="pentest",
            actor="ana",
        )
        suppress.create(
            conn,
            rule_id=None,
            field="user.name",
            value="svc",
            reason="r",
            actor="ana",
            expires_at=4_102_444_800_000,
        )
    active = suppress.active_for_rule(conn, SQLI)
    assert len(active) == 2
    assert active[0].matches({"source.ip": "203.0.113.66"}) or active[1].matches(
        {"source.ip": "203.0.113.66"}
    )
    assert not active[0].matches({})
    with transaction(conn):
        suppress.set_enabled(conn, sid, False, "ana")
    assert len(suppress.active_for_rule(conn, SQLI)) == 1
    assert suppress.active_for_rule(conn, "other-rule")[0].field == "user.name"
    assert suppress.active_for_rule(conn, SQLI, now=4_102_444_800_001) == []
    with pytest.raises(suppress.SuppressionError):
        suppress.set_enabled(conn, 999, True, "ana")
    with transaction(conn):
        suppress.delete(conn, sid, "ana")
    with pytest.raises(suppress.SuppressionError):
        suppress.delete(conn, sid, "ana")


def test_suppression_stops_alerts_and_counts(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path / "d", watch_enabled=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    init_db(s.db_path)
    with closing(connect(s.db_path)) as conn:
        engine = DetectionEngine(s)
        engine.reload(conn)
        with transaction(conn):
            suppress.create(
                conn,
                rule_id=SQLI,
                field="source.ip",
                value="203.0.113.66",
                reason="our scanner",
                actor="ana",
            )
        p = tmp_path / "a.log"
        p.write_text("\n".join(web_lines(3000, seed=8)) + "\n")
        [rep] = ingest_path(conn, p, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
        run = engine.run_ranges(conn, rep.chunks)
        assert run.suppressed > 0
        ents = [
            r[0] for r in conn.execute("SELECT entities FROM alerts WHERE rule_id = ?", (SQLI,))
        ]
        assert not any("203.0.113.66" in e for e in ents)
        hits = conn.execute("SELECT hits FROM suppressions").fetchone()[0]
        assert hits == run.suppressed
        assert (
            conn.execute("SELECT suppressed FROM rules WHERE id = ?", (SQLI,)).fetchone()[0] == hits
        )


def test_sigma_filter_applies_to_named_rule_only(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path / "d", watch_enabled=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    init_db(s.db_path)
    s.rules_path.mkdir(parents=True, exist_ok=True)
    (s.rules_path / "filter.yml").write_text(
        "title: allow office\nid: 40000000-0000-0000-0000-000000000001\n"
        "logsource: {category: webserver}\n"
        f"filter:\n  rules: [{SQLI}]\n  sel: {{c-ip: 203.0.113.77}}\n  condition: not sel\n"
    )
    (s.rules_path / "broken_filter.yml").write_text(
        "title: broken\nid: 40000000-0000-0000-0000-000000000002\n"
        "logsource: {category: webserver}\nfilter: {rules: any, condition: nothing}\n"
    )
    with closing(connect(s.db_path)) as conn:
        engine = DetectionEngine(s)
        assert engine.reload(conn).filters == 2
        errs = dict(conn.execute("SELECT id, load_error FROM sigma_filters").fetchall())
        assert errs["40000000-0000-0000-0000-000000000001"] is None
        assert errs["40000000-0000-0000-0000-000000000002"]
        p = tmp_path / "a.log"
        p.write_text("\n".join(web_lines(3000, seed=8)) + "\n")
        [rep] = ingest_path(conn, p, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
        engine.run_ranges(conn, rep.chunks)
        sqli = [
            r[0] for r in conn.execute("SELECT entities FROM alerts WHERE rule_id = ?", (SQLI,))
        ]
        assert sqli and not any("203.0.113.77" in e for e in sqli)
        scanner = [
            r[0] for r in conn.execute("SELECT entities FROM alerts WHERE rule_id LIKE '52aae84e%'")
        ]
        assert any("203.0.113.77" in e for e in scanner)  # other rules unaffected
        assert "203.0.113.77" in engine.compiled_for(conn, SQLI)[0].sql  # type: ignore[union-attr]
        # the rule's own fixtures still pass with the filter applied
        assert {r.status for r in engine.run_tests(conn)} == {"pass"}


# ---------------------------------------------------------------- hunt sandbox


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM ev_webserver",
        "UPDATE alerts SET status = 'closed'",
        "INSERT INTO saved_hunts (name, sql, created_by, created_at, updated_at) "
        "VALUES ('x', 'x', 'x', 0, 0)",
        "DROP TABLE alerts",
        "CREATE TABLE evil (x)",
        "ATTACH DATABASE '/tmp/x.db' AS x",
        "PRAGMA writable_schema = 1",
        "PRAGMA table_info(users)",
        "SELECT * FROM users",
        "SELECT password_hash FROM users",
        "SELECT * FROM sessions",
        "SELECT a.id FROM alerts a JOIN users u ON 1 = 1",
        "SELECT (SELECT password_hash FROM users LIMIT 1)",
        "WITH x AS (SELECT * FROM USERS) SELECT * FROM x",
        "SELECT 1; DELETE FROM alerts",
    ],
)
def test_hunt_console_denies_writes_and_secrets(
    env: tuple[Settings, sqlite3.Connection], sql: str
) -> None:
    s, conn = env
    before = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    result = run_hunt(s.db_path, sql, row_limit=10, timeout_s=5)
    assert result.error, sql
    assert result.rows == []
    assert conn.execute("SELECT count(*) FROM alerts").fetchone()[0] == before


def test_hunt_console_reads_limits_and_timeout(env: tuple[Settings, sqlite3.Connection]) -> None:
    s, _ = env
    ok = run_hunt(
        s.db_path,
        'SELECT "source.ip", count(*) n FROM ev_webserver GROUP BY 1 ORDER BY n DESC;',
        row_limit=5,
        timeout_s=5,
    )
    assert ok.error is None and ok.columns == ["source.ip", "n"] and len(ok.rows) == 5
    assert ok.truncated
    regex = run_hunt(
        s.db_path,
        "SELECT count(*) FROM ev_webserver WHERE \"url.query\" REGEXP '(?i)union'",
        row_limit=5,
        timeout_s=5,
    )
    assert regex.error is None and regex.rows[0][0] > 0
    slow = run_hunt(
        s.db_path,
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c",
        row_limit=5,
        timeout_s=0.5,
    )
    assert slow.error and "time limit" in slow.error
    assert run_hunt(s.db_path, "   ", row_limit=5, timeout_s=1).error == "Enter a query."
    blob = run_hunt(s.db_path, "SELECT x'00ff', '" + "a" * 5000 + "'", row_limit=5, timeout_s=1)
    assert blob.rows[0][0] == "<2 bytes>" and str(blob.rows[0][1]).endswith("…")


def test_csv_neutralizes_formulas() -> None:
    assert neutralize('=HYPERLINK("x")') == '\'=HYPERLINK("x")'
    for prefix in "+-@\t\r":
        assert neutralize(prefix + "1").startswith("'")
    assert neutralize(None) == "" and neutralize(5) == "5"
    out = to_csv(["=a", "b"], [["=1+1", 'x"y'], [None, "-2"]])
    assert out.splitlines() == ["'=a,b", '\'=1+1,"x""y"', ",'-2"]


# ---------------------------------------------------------------- field search


def test_search_builder(env: tuple[Settings, sqlite3.Connection]) -> None:
    _, conn = env
    req = SearchRequest(
        "ev_webserver",
        [
            Condition("source.ip", "eq", "203.0.113.66"),
            Condition("url.query", "contains", "100%_x"),
            Condition("http.response.status_code", "gt", "399"),
        ],
        start_ms=0,
        end_ms=2**60,
        limit=50,
    )
    sql, params = build(conn, req)
    assert (
        '"source.ip" = ?' in sql
        and "LIKE ? ESCAPE" in sql
        and '"http.response.status_code" > ?' in sql
    )
    assert params[3] == "%100\\%\\_x%" and params[4] == 399.0
    with pytest.raises(SearchError, match="unknown field"):
        build(conn, SearchRequest("ev_webserver", [Condition('x"; DROP TABLE users;--', "eq")]))
    with pytest.raises(SearchError, match="unknown event table"):
        build(conn, SearchRequest("users"))
    with pytest.raises(SearchError, match="unknown operator"):
        build(conn, SearchRequest("ev_webserver", [Condition("source.ip", "regex", "x")]))
    with pytest.raises(SearchError, match="at most"):
        build(conn, SearchRequest("ev_webserver", [Condition("source.ip", "exists")] * 9))
    res = search(
        conn,
        SearchRequest(
            "ev_webserver",
            [
                Condition("source.ip", "eq", "203.0.113.66"),
                Condition("user.name", "missing"),
                Condition("url.path", "startswith", "/"),
                Condition("url.path", "endswith", ""),
            ],
            limit=5,
        ),
    )
    assert len(res.events) == 5 and res.truncated
    assert res.columns[0] == "source.ip"
    ne = search(
        conn,
        SearchRequest(
            "ev_webserver",
            [
                Condition("source.ip", "ne", "x"),
                Condition("source.ip", "exists"),
                Condition("http.response.status_code", "lt", "abc"),
            ],
            newest_first=False,
        ),
    )
    assert ne.sql.endswith("LIMIT 201") or "ASC" in ne.sql


# ---------------------------------------------------------------- web


def _seed(authed: TestClient) -> None:
    upload(authed, [("access.log", text(web_lines(3000, seed=8)))])
    wait_idle(authed)


def test_alert_queue_filters_bulk_and_detail(authed: TestClient, db: sqlite3.Connection) -> None:
    _seed(authed)
    page = authed.get("/alerts")
    assert page.status_code == 200 and "Keyboard" in page.text
    for q in [
        "?status=all&sort=severity",
        "?status=closed&level=high",
        "?assignee=me&sort=events",
        "?assignee=none&q=203.0.113",
        f"?rule={SQLI}&sort=first_seen",
        "?assignee=admin",
    ]:
        assert authed.get("/alerts" + q).status_code == 200
    ids = [r[0] for r in db.execute("SELECT id FROM alerts ORDER BY id LIMIT 3")]
    csrf = page_csrf(page.text)
    resp = authed.post(
        "/alerts/bulk",
        data={
            "csrf_token": csrf,
            "ids": [str(i) for i in ids],
            "action": "status",
            "status": "closed",
        },
        follow_redirects=True,
    )
    assert "requires a resolution" in resp.text
    resp = authed.post(
        "/alerts/bulk",
        data={
            "csrf_token": csrf,
            "ids": [str(i) for i in ids],
            "action": "status",
            "status": "closed",
            "resolution": "false_positive",
            "back": "//evil",
        },
        follow_redirects=False,
    )
    assert resp.headers["location"].startswith("/alerts?msg=")
    assert db.execute("SELECT count(*) FROM alerts WHERE status = 'closed'").fetchone()[0] == 3
    resp = authed.post(
        "/alerts/bulk",
        data={"csrf_token": csrf, "ids": [str(ids[0])], "action": "assign", "assignee": "me"},
        follow_redirects=True,
    )
    assert "assigned to admin" in resp.text
    assert (
        "Select at least one"
        in authed.post(
            "/alerts/bulk", data={"csrf_token": csrf, "action": "assign"}, follow_redirects=True
        ).text
    )
    assert (
        "unknown action"
        in authed.post(
            "/alerts/bulk",
            data={"csrf_token": csrf, "ids": "1", "action": "nuke"},
            follow_redirects=True,
        ).text
    )

    sqli = db.execute("SELECT id FROM alerts WHERE rule_id = ? LIMIT 1", (SQLI,)).fetchone()[0]
    detail = authed.get(f"/alerts/{sqli}")
    assert detail.status_code == 200
    assert '<mark class="hl">url.query</mark>' in detail.text  # the field the rule tests
    assert "All webserver events ±1 h" in detail.text and "Suppress…" in detail.text
    csrf = page_csrf(detail.text)
    authed.post(f"/alerts/{sqli}/note", data={"csrf_token": csrf, "body": "checked"})
    authed.post(
        f"/alerts/{sqli}/status",
        data={"csrf_token": csrf, "action": "status", "status": "in_progress"},
    )
    bad = authed.post(
        f"/alerts/{sqli}/note", data={"csrf_token": csrf, "body": " "}, follow_redirects=True
    )
    assert "note is empty" in bad.text
    detail = authed.get(f"/alerts/{sqli}").text
    assert "checked" in detail and "status" in detail and "in progress" in detail
    assert authed.get("/alerts/99999").status_code == 404
    assert authed.post(f"/alerts/{sqli}/explode", data={"csrf_token": csrf}).status_code == 404

    # pivot link -> search results
    pivot = re.search(r'href="(/search\?run=1[^"]+)"', detail)
    assert pivot
    results = authed.get(pivot.group(1).replace("&amp;", "&"))
    assert results.status_code == 200 and "event(s)" in results.text
    ev = re.search(r'href="(/events/ev_webserver/\d+)"', results.text)
    assert ev
    page = authed.get(ev.group(1))
    assert page.status_code == 200 and "Fields" in page.text
    assert authed.get("/events/users/1").status_code == 404
    assert authed.get("/events/ev_webserver/999999").status_code == 404


def test_search_page_states(authed: TestClient) -> None:
    assert "Ingest some logs" in authed.get("/search").text
    _seed(authed)
    assert authed.get("/search").status_code == 200
    bad = authed.get("/search?run=1&table=ev_webserver&f1=nope&op1=eq&v1=x&limit=abc")
    assert "unknown field" in bad.text
    ok = authed.get(
        "/search?run=1&table=ev_webserver&f1=source.ip&op1=exists"
        "&start=2026-01-01T00:00:00&end=2027-01-01T00:00&order=asc"
    )
    assert "event(s)" in ok.text


def test_hunt_page_run_csv_save_load_delete(authed: TestClient, db: sqlite3.Connection) -> None:
    _seed(authed)
    page = authed.get("/hunt")
    assert "Hunt console" in page.text and "ev_webserver" in page.text
    csrf = page_csrf(page.text)
    run = authed.post(
        "/hunt", data={"csrf_token": csrf, "sql": 'SELECT "source.ip" FROM ev_webserver LIMIT 3'}
    )
    assert run.status_code == 200 and "3 row(s)" in run.text
    denied = authed.post("/hunt", data={"csrf_token": csrf, "sql": "SELECT * FROM users"})
    assert denied.status_code == 400 and "not allowed" in denied.text
    csv = authed.post(
        "/hunt", data={"csrf_token": csrf, "format": "csv", "sql": "SELECT '=1+1' AS f"}
    )
    assert csv.headers["content-type"].startswith("text/csv")
    assert csv.text.splitlines() == ["f", "'=1+1"]
    saved = authed.post(
        "/hunt/saved",
        data={
            "csrf_token": csrf,
            "name": "Top 4xx",
            "sql": "SELECT 1",
            "attack_tag": "attack.t1595",
            "description": "d",
        },
    )
    assert "Saved hunt" in saved.text
    assert (
        authed.post(
            "/hunt/saved",
            data={"csrf_token": csrf, "name": "x", "sql": "SELECT 1", "attack_tag": "nope"},
        ).status_code
        == 400
    )
    assert (
        authed.post("/hunt/saved", data={"csrf_token": csrf, "name": "", "sql": ""}).status_code
        == 400
    )
    hid = db.execute("SELECT id FROM saved_hunts").fetchone()[0]
    assert "SELECT 1" in authed.get(f"/hunt?saved={hid}").text
    assert authed.get("/hunt?saved=999").status_code == 404
    assert (
        authed.post(
            f"/hunt/saved/{hid}/delete", data={"csrf_token": csrf}, follow_redirects=False
        ).status_code
        == 303
    )
    assert authed.post(f"/hunt/saved/{hid}/delete", data={"csrf_token": csrf}).status_code == 404
    actions = {r[0] for r in db.execute("SELECT action FROM audit_log")}
    assert {"hunt.run", "hunt.save", "hunt.delete"} <= actions


def test_tuning_page(authed: TestClient, db: sqlite3.Connection) -> None:
    prefill = authed.get(f"/tuning?rule_id={SQLI}&field=source.ip&value=1.2.3.4")
    assert 'value="1.2.3.4"' in prefill.text
    csrf = page_csrf(prefill.text)
    bad = authed.post(
        "/tuning/suppressions",
        data={
            "csrf_token": csrf,
            "rule_id": SQLI,
            "field": "source.ip",
            "value": "1.2.3.4",
            "reason": "",
        },
    )
    assert bad.status_code == 400 and "reason is required" in bad.text
    bad_date = authed.post(
        "/tuning/suppressions",
        data={"csrf_token": csrf, "field": "a", "value": "b", "reason": "c", "expires": "tomorrow"},
    )
    assert bad_date.status_code == 400
    ok = authed.post(
        "/tuning/suppressions",
        data={
            "csrf_token": csrf,
            "rule_id": SQLI,
            "field": "source.ip",
            "value": "1.2.3.4",
            "reason": "office NAT",
            "expires": "2099-01-01T00:00",
        },
        follow_redirects=True,
    )
    assert "Suppression added" in ok.text and "office NAT" in ok.text
    sid = db.execute("SELECT id FROM suppressions").fetchone()[0]
    for action in ("disable", "enable", "delete"):
        assert (
            authed.post(
                f"/tuning/suppressions/{sid}/{action}",
                data={"csrf_token": csrf},
                follow_redirects=False,
            ).status_code
            == 303
        )
    assert (
        authed.post(f"/tuning/suppressions/{sid}/delete", data={"csrf_token": csrf}).status_code
        == 404
    )
    assert (
        authed.post("/tuning/suppressions/1/explode", data={"csrf_token": csrf}).status_code == 404
    )
    assert (
        "Reloaded"
        in authed.post("/tuning/reload", data={"csrf_token": csrf}, follow_redirects=True).text
    )


def test_audit_page_admin_only(
    authed: TestClient, client: TestClient, db: sqlite3.Connection, settings: Settings
) -> None:
    page = authed.get("/audit")
    assert page.status_code == 200 and "auth.login.success" in page.text
    assert "auth.login.success" in authed.get("/audit?action=auth.&actor=admin").text
    assert authed.get("/audit?before=1").status_code == 200

    with transaction(db):
        create_user(db, "ana2", "ana2-password-12", Role.ANALYST)
    authed.cookies.clear()
    login(authed, "ana2", "ana2-password-12")
    assert authed.get("/audit").status_code == 403


def test_xss_in_triage_pages(authed: TestClient, db: sqlite3.Connection) -> None:
    lines = [
        f'{XSS} - - [05/Jan/2026:10:00:00 +0000] "GET /x?id=1%20union%20select%201 HTTP/1.1" '
        f'200 1 "-" "{XSS}"',
        *web_lines(5, seed=1),
    ]
    upload(authed, [("x.log", text(lines))], parser="apache")
    wait_idle(authed)
    aid = db.execute("SELECT id FROM alerts WHERE entities LIKE '%script%'").fetchone()[0]
    csrf = page_csrf(authed.get(f"/alerts/{aid}").text)
    authed.post(f"/alerts/{aid}/note", data={"csrf_token": csrf, "body": XSS})
    authed.post(
        "/tuning/suppressions",
        data={"csrf_token": csrf, "field": "source.ip", "value": XSS, "reason": XSS},
    )
    authed.post(
        "/hunt/saved",
        data={"csrf_token": csrf, "name": XSS, "sql": f"SELECT '{XSS}'", "description": XSS},
    )
    hunt = authed.post("/hunt", data={"csrf_token": csrf, "sql": f"SELECT '{XSS}' AS x"})
    assert_inert(hunt.text)
    eid = db.execute('SELECT tl_id FROM ev_webserver WHERE "source.ip" = ?', (XSS,)).fetchone()[0]
    for path in [
        f"/alerts/{aid}",
        "/alerts",
        "/alerts?status=all&q=script",
        "/tuning",
        "/hunt",
        f"/events/ev_webserver/{eid}",
        "/audit",
        f"/search?run=1&table=ev_webserver&f1=source.ip&op1=eq&v1={XSS}",
    ]:
        assert_inert(authed.get(path).text)
