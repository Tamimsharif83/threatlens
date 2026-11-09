from __future__ import annotations

import json
import socket
import sqlite3
import textwrap
import urllib.request
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
import sigma.data.mitre_attack as mitre
from click.testing import CliRunner

from threatlens.alerts.store import (
    Match,
    RuleInfo,
    counts_by_level,
    group_key,
    list_alerts,
    record_matches,
    top_rules,
)
from threatlens.cli.main import cli
from threatlens.config import Settings
from threatlens.detection.compiler import (
    CompileError,
    compile_detection,
    sql_regexp,
    tables_for,
)
from threatlens.detection.engine import BUILTIN_TABLES, DetectionEngine
from threatlens.detection.loader import lint, load_rules, split_documents
from threatlens.detection.sigmahq import import_sigmahq
from threatlens.detection.testing import run_rule_test
from threatlens.ingest.files import ingest_path
from threatlens.ingest.pipeline import IngestOptions
from threatlens.normalize.schema import LogSource
from threatlens.storage.db import connect, init_db, transaction
from threatlens.synth import auth_lines, ecs_lines, web_lines

REPO = Path(__file__).resolve().parents[1]
EXAMPLES = REPO / "rules" / "examples"
FIXTURES = REPO / "tests" / "rules"
SQLI = "3815fe7c-7c88-4597-aa81-98ebaabeeb5f"
SSH = "d3b91716-cedd-4375-893e-31635e879920"


def rule_yaml(rule_id: str, logsource: str, detection: str, **extra: str) -> str:
    meta = "\n".join(f"{k}: {v}" for k, v in extra.items())
    return (
        textwrap.dedent(f"""\
        title: Test rule {rule_id[-4:]}
        id: {rule_id}
        status: test
        description: a test rule
        author: tests
        date: 2026-01-01
        level: high
        tags: [attack.t1190, attack.initial-access]
        falsepositives: [none]
        references: [https://example.invalid]
        logsource: {logsource}
        detection:
        """)
        + textwrap.indent(textwrap.dedent(detection), "  ")
        + meta
        + "\n"
    )


# ---------------------------------------------------------------- compiler


CATALOG = [
    *BUILTIN_TABLES,
    ("ev_api_webserver", LogSource("webserver", "api")),
    ("ev_app_audit", LogSource(None, "app", "audit")),
]


@pytest.mark.parametrize(
    ("logsource", "tables"),
    [
        ({"category": "webserver"}, ["ev_api_webserver", "ev_webserver"]),
        ({"category": "webserver", "product": "apache"}, ["ev_webserver"]),
        ({"category": "webserver", "product": "api"}, ["ev_api_webserver", "ev_webserver"]),
        ({"product": "linux", "service": "auth"}, ["ev_linux_auth"]),
        ({"product": "linux", "category": "process_creation"}, []),
        ({"product": "ecs", "category": "file"}, ["ev_ecs"]),
        ({"product": "app", "service": "audit"}, ["ev_app_audit"]),
        ({"product": "app"}, ["ev_app_audit"]),
        ({"product": "windows", "service": "security"}, []),
        ({}, []),
    ],
)
def test_tables_for(logsource: dict[str, str], tables: list[str]) -> None:
    assert tables_for(logsource, CATALOG) == tables


def test_compile_webserver_maps_sigma_fields() -> None:
    c = compile_detection(
        rule_yaml(
            "10000000-0000-0000-0000-000000000001",
            "{category: webserver}",
            "sel: {cs-method: POST, c-ip: 1.2.3.4, cs-uri-stem|endswith: /login}\ncondition: sel\n",
        ),
        "ev_webserver",
    )
    assert "http.request.method" in c.sql and "url.path" in c.sql and "source.ip" in c.sql
    assert c.sql.startswith("SELECT * FROM ev_webserver WHERE")
    assert set(c.fields) == {"http.request.method", "source.ip", "url.path"}


def test_compile_ecs_adds_category_condition_and_keywords() -> None:
    c = compile_detection(
        rule_yaml(
            "10000000-0000-0000-0000-000000000002",
            "{product: ecs, category: web}",
            "sel: {url.path: /admin}\ncondition: sel\n",
        ),
        "ev_ecs",
    )
    assert "`event.category`='web'" in c.sql
    k = compile_detection(
        rule_yaml(
            "10000000-0000-0000-0000-000000000003",
            "{product: linux, service: auth}",
            "keywords: ['Failed password']\ncondition: keywords\n",
        ),
        "ev_linux_auth",
    )
    assert "message LIKE '%Failed password%'" in k.sql


def test_compile_rejects_correlation_and_garbage() -> None:
    corr = textwrap.dedent("""\
        title: c
        id: 10000000-0000-0000-0000-000000000004
        correlation: {type: event_count, rules: [x], group-by: [source.ip], timespan: 5m,
                      condition: {gte: 2}}
        """)
    with pytest.raises(CompileError, match="not a detection rule"):
        compile_detection(corr, "ev_webserver")


def test_sql_regexp() -> None:
    assert sql_regexp("(?i)union", "x UNION y")
    assert not sql_regexp("abc", None)
    assert not sql_regexp(None, "abc")
    assert not sql_regexp("(unclosed", "x")


# ---------------------------------------------------------------- loader & lint


def write_rule(directory: Path, name: str, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text)
    return path


def test_load_rules_errors_duplicates_and_tests_folder_skipped(tmp_path: Path) -> None:
    good = rule_yaml(
        "10000000-0000-0000-0000-000000000010",
        "{category: webserver}",
        "sel: {cs-method: POST}\ncondition: sel\n",
    )
    write_rule(tmp_path, "good.yml", good)
    write_rule(tmp_path, "dup.yml", good)
    write_rule(tmp_path, "noid.yml", "title: x\n")
    write_rule(tmp_path, "bad.yaml", "key: [unclosed\n")
    write_rule(tmp_path, "empty.yml", "\n")
    write_rule(tmp_path, "list.yml", "- a\n")
    write_rule(
        tmp_path,
        "sigma_err.yml",
        rule_yaml(
            "10000000-0000-0000-0000-000000000011",
            "{category: webserver}",
            "sel: {cs-method: POST}\ncondition: sel and missing\n",
        ),
    )
    write_rule(tmp_path / "tests", "ignored.yml", "not: [a rule\n")
    (tmp_path / "notes.txt").write_text("ignored")
    result = load_rules([(tmp_path, "user")])
    ids = {r.id: r for r in result.rules}
    assert set(ids) == {
        "10000000-0000-0000-0000-000000000010",
        "10000000-0000-0000-0000-000000000011",
    }
    assert ids["10000000-0000-0000-0000-000000000011"].load_error
    errors = result.file_errors
    assert "duplicate rule id" in errors["user:good.yml"] or "duplicate" in errors.get(
        "user:dup.yml", ""
    )
    assert "no 'id'" in errors["user:noid.yml"]
    assert "invalid YAML" in errors["user:bad.yaml"]
    assert "empty" in errors["user:empty.yml"]
    assert "mapping" in errors["user:list.yml"]
    assert not any("ignored" in k for k in errors)


def test_split_documents_and_multi_doc_file(tmp_path: Path) -> None:
    text = (
        rule_yaml(
            "10000000-0000-0000-0000-000000000020",
            "{category: webserver}",
            "sel: {cs-method: POST}\ncondition: sel\n",
        )
        + "---\n"
        + rule_yaml(
            "10000000-0000-0000-0000-000000000021",
            "{category: webserver}",
            "sel: {cs-method: GET}\ncondition: sel\n",
        )
    )
    assert len(split_documents(text)) == 2
    write_rule(tmp_path, "two.yml", text)
    assert len(load_rules([(tmp_path, "user")]).rules) == 2


def test_lint_requires_metadata(tmp_path: Path) -> None:
    write_rule(
        tmp_path,
        "thin.yml",
        textwrap.dedent("""\
        title: thin
        id: not-a-uuid
        logsource: {category: webserver}
        detection: {sel: {cs-method: POST}, condition: sel}
        level: extreme
        tags: [attack.initial-access]
        """),
    )
    messages = [i.message for i in lint(load_rules([(tmp_path, "user")]))]
    assert "id is not a UUID" in messages
    for key in ("description", "author", "date", "falsepositives", "references"):
        assert f"missing required field '{key}'" in messages
    assert any("ATT&CK technique" in m for m in messages)
    assert any("level must be" in m for m in messages)


def test_example_rules_lint_clean_and_tests_pass() -> None:
    result = load_rules([(EXAMPLES, "builtin")])
    assert len(result.rules) == 5
    assert lint(result) == []
    for rule in result.rules:
        res = run_rule_test(rule, [FIXTURES])
        assert res.status == "pass", (rule.title, res.messages)
        assert "[Example]" in rule.title


def test_rule_test_reports_failures(tmp_path: Path) -> None:
    rid = "10000000-0000-0000-0000-000000000030"
    rule_dir = tmp_path / "rules"
    write_rule(
        rule_dir,
        "r.yml",
        rule_yaml(rid, "{category: webserver}", "sel: {cs-method: DELETE}\ncondition: sel\n"),
    )
    [rule] = load_rules([(rule_dir, "user")]).rules
    fixtures = tmp_path / "fixtures"
    assert run_rule_test(rule, [fixtures]).status == "none"
    (fixtures / rid).mkdir(parents=True)
    assert run_rule_test(rule, [fixtures]).status == "none"  # empty folder
    line = '1.2.3.4 - - [05/Jan/2026:10:00:00 +0000] "{} / HTTP/1.1" 200 1 "-" "x"'
    (fixtures / rid / "tp.log").write_text(line.format("GET") + "\n")
    (fixtures / rid / "tn.log").write_text(line.format("DELETE") + "\n")
    res = run_rule_test(rule, [fixtures])
    assert res.status == "fail"
    assert any("did not match" in m for m in res.messages)
    assert any("true-negative event(s) matched" in m for m in res.messages)
    (fixtures / rid / "tp.jsonl").write_text("{not json\n")
    assert "invalid JSON" in run_rule_test(rule, [fixtures]).messages[0]
    (fixtures / rid / "tp.jsonl").unlink()
    (fixtures / rid / "tp.log").write_text(
        "Jan  5 10:00:00 h sshd[1]: Accepted x for y from 1.2.3.4 port 1\n"
    )
    res = run_rule_test(rule, [fixtures])
    assert any("does not read" in m for m in res.messages)


# ---------------------------------------------------------------- alerts store


@pytest.fixture
def db(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    init_db(tmp_path / "t.db")
    with closing(connect(tmp_path / "t.db")) as conn:
        yield conn


RULE = RuleInfo("r1", "Rule One", "high", ["attack.t1190"])


def m(event_id: int, ts: int, ip: str = "1.1.1.1", user: str | None = None) -> Match:
    entities = {"source.ip": ip}
    if user:
        entities["user.name"] = user
    return Match("ev_webserver", event_id, ts, entities)


def record(
    db: sqlite3.Connection, matches: list[Match], window: int = 60_000, rule: RuleInfo = RULE
):  # type: ignore[no-untyped-def]
    with transaction(db):
        db.execute(
            "INSERT OR IGNORE INTO rules (id, title, kind, origin, path, yaml, sha256, "
            "loaded_at) VALUES (?, ?, 'detection', 'user', 'p', 'y', 's', 0)",
            (rule.id, rule.title),
        )
        return record_matches(db, rule, matches, window, "ingest")


def test_grouping_by_primary_entity_and_window(db: sqlite3.Connection) -> None:
    res = record(
        db,
        [
            m(1, 0, user="a"),
            m(2, 10_000, user="b"),
            m(3, 30_000, user="b"),
            m(4, 0, ip="2.2.2.2"),
            m(5, 500_000),
        ],
    )
    assert len(res.new_alerts) == 3  # ip1 burst, ip2, ip1 again after the window
    alerts = {a.id: a for a in list_alerts(db)}
    first = alerts[res.new_alerts[0]]
    assert first.event_count == 3
    assert first.entities == {"source.ip": "1.1.1.1"}  # user differs -> dropped
    assert (first.first_seen, first.last_seen) == (0, 30_000)
    rule = db.execute("SELECT hits, alerts, last_fired_at FROM rules WHERE id = 'r1'").fetchone()
    assert rule[0] == 5 and rule[1] == 3 and rule[2] is not None


def test_same_event_never_counted_twice(db: sqlite3.Connection) -> None:
    record(db, [m(1, 0), m(2, 1000)])
    again = record(db, [m(1, 0), m(2, 1000), m(3, 2000)])
    assert again.events == 1
    assert list_alerts(db)[0].event_count == 3


def test_closed_alert_starts_a_new_one_and_window_zero(db: sqlite3.Connection) -> None:
    [aid] = record(db, [m(1, 0)]).new_alerts
    with transaction(db):
        db.execute("UPDATE alerts SET status = 'closed' WHERE id = ?", (aid,))
    assert len(record(db, [m(2, 10)]).new_alerts) == 1
    assert len(record(db, [m(3, 20), m(4, 21)], window=0).new_alerts) == 2


def test_alert_summaries(db: sqlite3.Connection) -> None:
    record(db, [m(1, 0)])
    record(db, [m(2, 0, ip="9.9.9.9")], rule=RuleInfo("r2", "Two", "weird", []))
    counts = counts_by_level(db)
    assert counts["high"] == 1 and counts["medium"] == 1  # unknown level -> medium
    assert list(counts) == ["critical", "high", "medium", "low", "informational"]
    assert [r[0] for r in top_rules(db)] == ["r1", "r2"] or [r[0] for r in top_rules(db)] == [
        "r2",
        "r1",
    ]
    assert group_key("r", {"user.name": "x", "host.name": "h"}) == 'r|{"user.name":"x"}'
    assert list_alerts(db, level="high", status="new", rule_id="r1")[0].rule_title == "Rule One"


# ---------------------------------------------------------------- engine


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings(data_dir=tmp_path / "data", watch_enabled=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    init_db(s.db_path)
    return s


def ingest(conn: sqlite3.Connection, tmp_path: Path, name: str, lines: list[str]):  # type: ignore[no-untyped-def]
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    [rep] = ingest_path(conn, p, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
    return rep


def test_engine_end_to_end(settings: Settings, tmp_path: Path) -> None:
    engine = DetectionEngine(settings)
    with closing(connect(settings.db_path)) as conn:
        report = engine.reload(conn, "tester")
        assert report.loaded == 5 and report.errors == 0
        results = engine.run_tests(conn)
        assert {r.status for r in results} == {"pass"}
        rep = ingest(conn, tmp_path, "access.log", list(web_lines(3000, seed=8)))
        run = engine.run_ranges(conn, rep.chunks)
        assert run.errors == {}
        assert run.result.events > 0
        titles = {a.rule_title for a in list_alerts(conn)}
        assert "[Example] SQL Injection Pattern in URL Query" in titles
        # retro-hunt over the same data finds nothing new
        hunt = engine.retro_hunt(conn, SQLI)
        assert hunt.result.events == 0 and hunt.errors == {}
        # disable -> not run on new data; retro-hunt still possible
        engine.set_enabled(conn, SQLI, False, "tester")
        engine.reload(conn)  # enabled flag survives a reload
        assert conn.execute("SELECT enabled FROM rules WHERE id = ?", (SQLI,)).fetchone()[0] == 0
        before = conn.execute("SELECT hits FROM rules WHERE id = ?", (SQLI,)).fetchone()[0]
        rep2 = ingest(conn, tmp_path, "more.log", list(web_lines(2000, seed=9)))
        engine.run_ranges(conn, rep2.chunks)
        after = conn.execute("SELECT hits FROM rules WHERE id = ?", (SQLI,)).fetchone()[0]
        assert before == after
        assert engine.retro_hunt(conn, SQLI).result.events > 0
        assert engine.retro_hunt(conn, "nope").errors
        assert engine.run_ranges(conn, []).rules_run == 0
        compiled = engine.compiled_for(conn, SQLI)
        assert compiled and not isinstance(compiled[0], str)
        assert engine.compiled_for(conn, "nope") == []


def test_engine_user_rules_missing_fields_and_errors(settings: Settings, tmp_path: Path) -> None:
    rules = settings.rules_path
    write_rule(
        rules,
        "custom.yml",
        rule_yaml(
            "10000000-0000-0000-0000-000000000040",
            "{category: webserver}",
            "sel: {cs-cookie|contains: admin=1}\nfilter: {cs-method: OPTIONS}\n"
            "condition: not filter and not sel\n",
        ),
    )
    write_rule(
        rules,
        "auth.yml",
        rule_yaml(
            "10000000-0000-0000-0000-000000000041",
            "{product: linux, service: auth}",
            "sel: {event.action: user_created}\ncondition: sel\n",
        ),
    )
    write_rule(
        rules,
        "broken.yml",
        "title: x\nid: 10000000-0000-0000-0000-000000000042\n"
        "logsource: {category: webserver}\ndetection: {condition: nothing}\n",
    )
    engine = DetectionEngine(settings)
    with closing(connect(settings.db_path)) as conn:
        report = engine.reload(conn)
        assert report.errors == 1
        broken = conn.execute("SELECT load_error FROM rules WHERE id LIKE '%42'").fetchone()[0]
        assert broken
        rep = ingest(conn, tmp_path, "access.log", list(web_lines(200, seed=3)))
        run = engine.run_ranges(conn, rep.chunks)
        assert run.errors == {}
        # The rule referenced a field the table never had: added as an empty column,
        # so "not sel" matches every non-OPTIONS request.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(ev_webserver)")}
        assert "http.request.headers.cookie" in cols
        hits = conn.execute("SELECT hits FROM rules WHERE id LIKE '%40'").fetchone()[0]
        assert hits == 200
        # auth rule waits for data: no table yet, nothing run, no error
        assert conn.execute("SELECT hits FROM rules WHERE id LIKE '%41'").fetchone()[0] == 0


def test_builtin_rules_can_be_turned_off(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path / "d", builtin_rules=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    init_db(s.db_path)
    with closing(connect(s.db_path)) as conn:
        assert DetectionEngine(s).reload(conn).loaded == 0


# ---------------------------------------------------------------- sigmahq import & CLI


def test_import_sigmahq(tmp_path: Path) -> None:
    clone = tmp_path / "sigma"
    write_rule(
        clone / "rules" / "web" / "webserver_generic",
        "web_a.yml",
        rule_yaml(
            "10000000-0000-0000-0000-000000000050",
            "{category: webserver}",
            "sel: {cs-method: TRACE}\ncondition: sel\n",
        ),
    )
    write_rule(
        clone / "rules" / "windows" / "process_creation",
        "proc.yml",
        rule_yaml(
            "10000000-0000-0000-0000-000000000051",
            "{product: windows, category: process_creation}",
            "sel: {Image|endswith: x.exe}\ncondition: sel\n",
        ),
    )
    write_rule(clone / "rules" / "linux" / "builtin", "bad.yml", "key: [unclosed\n")
    (clone / "LICENSE.Detection.Rules.md").write_text("DRL 1.1")
    target = tmp_path / "out"
    report = import_sigmahq(clone, target)
    assert report.imported == 1 and report.skipped == 1 and len(report.errors) == 1
    assert (target / "rules/web/webserver_generic/web_a.yml").exists()
    assert (target / "LICENSE.Detection.Rules.md").read_text() == "DRL 1.1"
    assert "Detection Rule License" in (target / "README.md").read_text()
    assert import_sigmahq(tmp_path / "empty", target).errors


def test_cli_rules_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path / "d"))
    runner = CliRunner()
    lint_out = runner.invoke(cli, ["rules", "lint", "--dir", str(EXAMPLES)])
    assert lint_out.exit_code == 0, lint_out.output
    test_out = runner.invoke(
        cli,
        ["rules", "test", "--dir", str(EXAMPLES), "--tests", str(FIXTURES), "--require-fixtures"],
    )
    assert test_out.exit_code == 0, test_out.output
    assert test_out.output.count("PASS") == 5
    # default sources: bundled examples (+ empty user folder)
    assert runner.invoke(cli, ["rules", "test"]).exit_code == 0
    logs = tmp_path / "auth.log"
    logs.write_text("\n".join(auth_lines(300, seed=2)) + "\n")
    ingest_out = runner.invoke(cli, ["ingest", str(logs)])
    assert "detection:" in ingest_out.output
    listing = runner.invoke(cli, ["rules", "list"])
    assert SSH in listing.output
    assert "0 new matching" in runner.invoke(cli, ["rules", "hunt", SSH]).output
    assert runner.invoke(cli, ["rules", "hunt", "missing-id"]).exit_code == 1
    # no fixtures + --require-fixtures fails; lint finds metadata problems
    bad = tmp_path / "bad_rules"
    write_rule(
        bad,
        "r.yml",
        "title: t\nid: x\nlogsource: {category: webserver}\n"
        "detection: {sel: {cs-method: POST}, condition: sel}\n",
    )
    assert runner.invoke(cli, ["rules", "lint", "--dir", str(bad)]).exit_code == 1
    assert (
        runner.invoke(cli, ["rules", "test", "--dir", str(bad), "--require-fixtures"]).exit_code
        == 1
    )
    clone = tmp_path / "clone"
    write_rule(
        clone / "rules",
        "a.yml",
        rule_yaml(
            "10000000-0000-0000-0000-000000000060",
            "{category: webserver}",
            "sel: {cs-method: X}\ncondition: sel\n",
        ),
    )
    imp = runner.invoke(cli, ["rules", "import-sigmahq", str(clone)])
    assert "imported 1 rule(s)" in imp.output


def test_ecs_rule_on_synthetic_app_events(settings: Settings, tmp_path: Path) -> None:
    engine = DetectionEngine(settings)
    with closing(connect(settings.db_path)) as conn:
        engine.reload(conn)
        rep = ingest(conn, tmp_path, "app.jsonl", list(ecs_lines(2000, seed=4)))
        engine.run_ranges(conn, rep.chunks)
        alerts = list_alerts(conn)
        assert alerts and all(a.level == "critical" for a in alerts)
        assert json.loads(conn.execute("SELECT tags FROM alerts LIMIT 1").fetchone()[0])


def test_rule_loading_never_touches_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ThreatLens is offline at runtime: no validator may download data (e.g. MITRE)."""

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access during rule loading")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setenv("HOME", str(tmp_path / "nohome"))  # no cache to fall back on
    monkeypatch.setattr(mitre, "_cache", None)
    result = load_rules([(EXAMPLES, "builtin")])
    assert all(not any("skipped" in w for w in r.warnings) for r in result.rules)
    assert all(r.warnings == [] for r in result.rules)
