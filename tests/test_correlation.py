"""Phase 4: Sigma v2 correlation rules."""

from __future__ import annotations

import json
import sqlite3
import textwrap
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import page_csrf
from tests.test_web_phase1 import text, upload, wait_idle
from threatlens.config import Settings
from threatlens.detection.engine import DetectionEngine
from threatlens.detection.loader import LoadedRule
from threatlens.detection.testing import run_correlation_test
from threatlens.ingest.files import ingest_path
from threatlens.ingest.pipeline import IngestOptions
from threatlens.storage.db import connect, init_db

BRUTE = "90faa98e-828e-45c8-a4e2-c53f8e9d2b99"
FAILED_SSH = "d3b91716-cedd-4375-893e-31635e879920"

WEB_FAIL = """\
title: web login failed
id: 60000000-0000-0000-0000-000000000001
name: web_fail
logsource: {category: webserver}
detection: {sel: {cs-uri-stem: /login, sc-status: 401}, condition: sel}
level: low
"""
SSH_OK = """\
title: ssh login ok
id: 60000000-0000-0000-0000-000000000002
name: ssh_ok
logsource: {product: linux, service: auth}
detection: {sel: {event.action: ssh_login, event.outcome: success}, condition: sel}
level: low
"""


def corr(rule_id: str, body: str, title: str = "corr") -> str:
    return f"title: {title}\nid: {rule_id}\nlevel: high\ncorrelation:\n" + textwrap.indent(
        textwrap.dedent(body), "  "
    )


def web(
    ip: str,
    minute: int,
    second: int,
    status: int = 401,
    path: str = "/login",
    user: str = "-",
    size: int = 10,
) -> str:
    return (
        f"{ip} - {user} [05/Jan/2026:10:{minute:02d}:{second:02d} +0000] "
        f'"POST {path} HTTP/1.1" {status} {size} "-" "ua"'
    )


def ssh(ip: str, minute: int, second: int) -> str:
    return (
        f"Jan  5 10:{minute:02d}:{second:02d} host sshd[1]: Accepted password for alice "
        f"from {ip} port 2222 ssh2"
    )


@pytest.fixture
def setup(tmp_path: Path) -> Iterator[tuple[Settings, sqlite3.Connection, DetectionEngine]]:
    s = Settings(
        data_dir=tmp_path / "d",
        watch_enabled=False,  # type: ignore[call-arg]
        builtin_rules=False,
    )
    s.ensure_dirs()
    s.rules_path.mkdir(parents=True)
    init_db(s.db_path)
    with closing(connect(s.db_path)) as conn:
        yield s, conn, DetectionEngine(s)


def write_rules(s: Settings, *docs: str) -> None:
    (s.rules_path / "rules.yml").write_text("\n---\n".join(d.strip() for d in docs) + "\n")


def ingest(
    s: Settings, conn: sqlite3.Connection, engine: DetectionEngine, name: str, lines: list[str]
):  # type: ignore[no-untyped-def]
    path = s.data_dir / name
    path.write_text("\n".join(lines) + "\n")
    [rep] = ingest_path(conn, path, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
    return engine.run_ranges(conn, rep.chunks)


def alerts(conn: sqlite3.Connection, kind: str = "correlation") -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM alerts WHERE kind = ? ORDER BY id", (kind,)).fetchall()


def test_event_count_merges_windows_and_never_double_counts(setup) -> None:  # type: ignore[no-untyped-def]
    s, conn, engine = setup
    write_rules(
        s,
        WEB_FAIL,
        corr(
            "60000000-0000-0000-0000-000000000010",
            """\
        type: event_count
        rules: [web_fail]
        group-by: [c-ip]
        timespan: 5m
        condition: {gte: 5}
    """,
        ),
    )
    report = engine.reload(conn)
    assert report.errors == 0
    burst = [web("203.0.113.9", 0, i * 5) for i in range(8)]
    other = [web("198.51.100.1", 0, i * 5) for i in range(3)]  # below the threshold
    run = ingest(s, conn, engine, "a.log", burst + other)
    assert run.correlations_run == 1
    [a] = alerts(conn)
    assert json.loads(a["entities"]) == {"source.ip": "203.0.113.9"}
    assert a["event_count"] == 8  # every event of every window, once
    metric = json.loads(a["metric"])
    assert metric["type"] == "event_count" and metric["value"] >= 5
    # base rule is used by the correlation (generate: false) -> no alerts of its own
    assert alerts(conn, "detection") == []
    assert (
        conn.execute("SELECT correlation_only FROM rules WHERE name = 'web_fail'").fetchone()[0]
        == 1
    )
    # retro-hunt over the same data finds nothing new
    hunt = engine.retro_hunt(conn, "60000000-0000-0000-0000-000000000010")
    assert hunt.result.events == 0 and hunt.errors == {}


def test_burst_split_across_batches_and_throttle(setup) -> None:  # type: ignore[no-untyped-def]
    s, conn, engine = setup
    write_rules(
        s,
        WEB_FAIL,
        corr(
            "60000000-0000-0000-0000-000000000011",
            """\
        type: event_count
        rules: [web_fail]
        group-by: [c-ip]
        timespan: 5m
        condition: {gte: 6}
    """,
        ),
    )
    engine.reload(conn)
    ingest(s, conn, engine, "1.log", [web("203.0.113.9", 0, i * 5) for i in range(3)])
    assert alerts(conn) == []
    # the rest of the burst arrives in a later batch: the run looks back one timespan
    ingest(s, conn, engine, "2.log", [web("203.0.113.9", 0, 15 + i * 5) for i in range(3)])
    [a] = alerts(conn)
    assert a["event_count"] == 6
    # a new burst hours later (beyond the 60 min throttle) is a separate alert
    ingest(s, conn, engine, "3.log", [web("203.0.113.9", 50, i) for i in range(6)])
    assert len(alerts(conn)) == 1  # 50 min later: same alert (within throttle window)
    late = [line.replace("10:", "13:", 1) for line in (web("203.0.113.9", 0, i) for i in range(6))]
    ingest(s, conn, engine, "4.log", late)
    assert len(alerts(conn)) == 2


@pytest.mark.parametrize(
    ("body", "lines", "fires"),
    [
        (
            "type: value_count\nrules: [web_fail]\ngroup-by: [c-ip]\ntimespan: 5m\n"
            "condition: {field: cs-username, gte: 3}",
            [web("1.1.1.1", 0, i, user=f"u{i}") for i in range(3)],
            True,
        ),
        (
            "type: value_count\nrules: [web_fail]\ngroup-by: [c-ip]\ntimespan: 5m\n"
            "condition: {field: cs-username, gte: 3}",
            [web("1.1.1.1", 0, i, user="same") for i in range(6)],
            False,
        ),
        (
            "type: value_sum\nrules: [web_fail]\ngroup-by: [c-ip]\ntimespan: 5m\n"
            "condition: {field: sc-bytes, gte: 1000}",
            [web("1.1.1.1", 0, i, size=400) for i in range(3)],
            True,
        ),
        (
            "type: value_avg\nrules: [web_fail]\ngroup-by: [c-ip]\ntimespan: 5m\n"
            "condition: {field: sc-bytes, gt: 500}",
            [web("1.1.1.1", 0, i, size=400) for i in range(3)],
            False,
        ),
    ],
)
def test_value_correlations(setup, body: str, lines: list[str], fires: bool) -> None:  # type: ignore[no-untyped-def]
    s, conn, engine = setup
    write_rules(s, WEB_FAIL, corr("60000000-0000-0000-0000-000000000012", body))
    assert engine.reload(conn).errors == 0
    ingest(s, conn, engine, "a.log", lines)
    assert bool(alerts(conn)) is fires


@pytest.mark.parametrize("kind", ["temporal", "temporal_ordered"])
def test_cross_table_temporal_with_alias_and_children(setup, kind: str) -> None:  # type: ignore[no-untyped-def]
    s, conn, engine = setup
    write_rules(
        s,
        WEB_FAIL,
        SSH_OK,
        corr(
            "60000000-0000-0000-0000-000000000013",
            f"""\
        type: {kind}
        rules: [web_fail, ssh_ok]
        group-by: [ip]
        aliases:
          ip:
            web_fail: c-ip
            ssh_ok: source.ip
        timespan: 10m
        generate: true
    """,
            title="web fail then ssh ok",
        ),
    )
    assert engine.reload(conn).errors == 0
    # generate: true -> the base rules alert on their own as well
    assert conn.execute("SELECT sum(correlation_only) FROM rules").fetchone()[0] == 0
    ingest(s, conn, engine, "access.log", [web("203.0.113.5", 0, 0)])
    ingest(s, conn, engine, "auth.log", [ssh("203.0.113.5", 2, 0)])
    [a] = alerts(conn)
    assert json.loads(a["entities"]) == {"source.ip": "203.0.113.5"}  # alias -> stored field
    tables = {
        r[0]
        for r in conn.execute("SELECT table_name FROM alert_events WHERE alert_id = ?", (a["id"],))
    }
    assert tables == {"ev_webserver", "ev_linux_auth"}
    children = conn.execute(
        "SELECT count(*) FROM alert_links WHERE parent_id = ?", (a["id"],)
    ).fetchone()[0]
    assert children == 2  # the web_fail alert and the ssh_ok alert


def test_temporal_ordered_respects_order(setup) -> None:  # type: ignore[no-untyped-def]
    s, conn, engine = setup
    write_rules(
        s,
        WEB_FAIL,
        SSH_OK,
        corr(
            "60000000-0000-0000-0000-000000000014",
            """\
        type: temporal_ordered
        rules: [web_fail, ssh_ok]
        group-by: [ip]
        aliases: {ip: {web_fail: c-ip, ssh_ok: source.ip}}
        timespan: 10m
    """,
        ),
    )
    engine.reload(conn)
    ingest(s, conn, engine, "auth.log", [ssh("203.0.113.5", 0, 0)])  # success first
    ingest(s, conn, engine, "access.log", [web("203.0.113.5", 2, 0)])  # failure after
    assert alerts(conn) == []


def test_compile_errors_and_generate_toggle(setup) -> None:  # type: ignore[no-untyped-def]
    s, conn, engine = setup
    write_rules(
        s,
        WEB_FAIL,
        corr(
            "60000000-0000-0000-0000-000000000020",
            "type: event_count\nrules: [missing]\n"
            "group-by: [c-ip]\ntimespan: 5m\ncondition: {gte: 2}",
        ),
        corr(
            "60000000-0000-0000-0000-000000000021",
            "type: event_count\nrules: [web_fail]\n"
            "group-by: [c-ip]\ntimespan: 5m\ncondition: {gte: 2}",
        ),
        corr(
            "60000000-0000-0000-0000-000000000022",
            "type: event_count\n"
            "rules: [60000000-0000-0000-0000-000000000021]\n"
            "group-by: [c-ip]\ntimespan: 5m\ncondition: {gte: 2}",
        ),
    )
    report = engine.reload(conn)
    errors = dict(conn.execute("SELECT id, load_error FROM rules").fetchall())
    assert "not loaded" in errors["60000000-0000-0000-0000-000000000020"]
    assert errors["60000000-0000-0000-0000-000000000021"] is None
    assert "not a detection rule" in errors["60000000-0000-0000-0000-000000000022"]
    assert report.errors == 0  # these are compile problems, reported per rule
    assert isinstance(
        engine.compiled_correlation_for(conn, "60000000-0000-0000-0000-000000000020"), str
    )
    assert engine.compiled_correlation_for(conn, "60000000-0000-0000-0000-000000000001") is None
    # disabling the only correlation that uses web_fail lets it alert on its own again
    assert conn.execute("SELECT correlation_only FROM rules WHERE name='web_fail'").fetchone()[0]
    engine.set_enabled(conn, "60000000-0000-0000-0000-000000000021", False, "t")
    assert not conn.execute("SELECT correlation_only FROM rules WHERE name='web_fail'").fetchone()[
        0
    ]
    assert (
        "no data"
        in engine.retro_hunt(conn, "60000000-0000-0000-0000-000000000021").errors[
            "60000000-0000-0000-0000-000000000021"
        ]
    )


def test_correlation_fixture_failures(tmp_path: Path) -> None:
    fixtures = tmp_path / "fx"
    cid = "60000000-0000-0000-0000-000000000030"
    (fixtures / cid).mkdir(parents=True)
    base = LoadedRule(
        id="60000000-0000-0000-0000-000000000001",
        title="w",
        kind="detection",
        origin="user",
        path="p",
        yaml=WEB_FAIL,
        sha256="x",
        name="web_fail",
        logsource={"category": "webserver"},
    )
    rule = LoadedRule(
        id=cid,
        title="c",
        kind="correlation",
        origin="user",
        path="p",
        yaml=corr(
            cid,
            "type: event_count\nrules: [web_fail]\ngroup-by: [c-ip]\n"
            "timespan: 5m\ncondition: {gte: 3}",
        ),
        sha256="y",
    )
    assert run_correlation_test(rule, [base], [tmp_path / "none"]).status == "none"
    assert run_correlation_test(rule, [base], [fixtures]).status == "none"  # empty folder
    (fixtures / cid / "tp.log").write_text(web("1.1.1.1", 0, 0) + "\n")
    (fixtures / cid / "tn.log").write_text("\n".join(web("1.1.1.1", 0, i) for i in range(4)))
    res = run_correlation_test(rule, [base], [fixtures])
    assert res.status == "fail"
    assert any("did not make the correlation fire" in m for m in res.messages)
    assert any("true-negative events made" in m for m in res.messages)
    broken = LoadedRule(
        id=cid,
        title="c",
        kind="correlation",
        origin="user",
        path="p",
        yaml="x",
        sha256="z",
        load_error="bad",
    )
    assert run_correlation_test(broken, [base], [fixtures]).status == "fail"


# ---------------------------------------------------------------- web


def test_correlation_pages(authed: TestClient, db: sqlite3.Connection) -> None:
    rules = authed.get("/rules").text
    assert "correlation only" in rules  # the failed-login example feeds the brute force
    page = authed.get(f"/rules/{BRUTE}")
    assert "Compiled query" in page.text and "event_count" in page.text
    assert "[Example] Failed SSH Login" in page.text
    from threatlens.synth import auth_lines  # noqa: PLC0415

    upload(authed, [("auth.log", text(auth_lines(900, seed=3)))])
    wait_idle(authed)
    aid = db.execute("SELECT id FROM alerts WHERE kind = 'correlation' LIMIT 1").fetchone()[0]
    detail = authed.get(f"/alerts/{aid}")
    assert "Correlation" in detail.text and "event_count" in detail.text
    assert "generate: false" in detail.text
    queue = authed.get("/alerts").text
    assert "SSH Brute Force" in queue and ">correlation<" in queue
    csrf = page_csrf(page.text)
    hunt = authed.post(
        f"/rules/{BRUTE}/retro-hunt", headers={"X-CSRF-Token": csrf}, follow_redirects=False
    )
    assert hunt.status_code == 303
    assert authed.get(f"/rules/{FAILED_SSH}").status_code == 200
