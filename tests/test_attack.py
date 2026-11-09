"""Phase 6: ATT&CK catalogue, coverage matrix, Navigator export and rule metrics."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import page_csrf
from tests.test_web_phase1 import XSS, assert_inert, text, upload, wait_idle
from threatlens.alerts.triage import set_status
from threatlens.attack.catalog import load, techniques_in_tags
from threatlens.attack.coverage import compute, navigator_layer, rule_metrics
from threatlens.config import Settings
from threatlens.detection.engine import DetectionEngine
from threatlens.detection.loader import lint, load_rules
from threatlens.storage.db import connect, init_db, transaction
from threatlens.synth import web_lines

REPO = Path(__file__).resolve().parents[1]
SQLI = "3815fe7c-7c88-4597-aa81-98ebaabeeb5f"


def test_catalog() -> None:
    cat = load()
    assert cat.version == "20.0"
    assert len(cat.tactics) >= 14 and cat.tactics[0].shortname == "reconnaissance"
    assert cat.name("t1110.001") == "Password Guessing"
    assert cat.name("T9999") == "unknown technique"
    assert cat.techniques["T1110.001"].parent == "T1110"
    assert {s.id for s in cat.subtechniques("T1110")} >= {"T1110.001", "T1110.003"}
    assert "defense-evasion" in cat.tactic_names()  # legacy tag still readable
    assert techniques_in_tags(
        [
            "attack.t1190",
            "attack.initial-access",
            "attack.T1190",
            "attack.t1110.001",
            "cve.2021.44228",
        ]
    ) == ["T1190", "T1110.001"]


def test_generator_builds_compact_list(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("gen", REPO / "scripts/gen_attack_techniques.py")
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    sys.modules["gen"] = gen
    spec.loader.exec_module(gen)
    ref = [{"source_name": "mitre-attack", "external_id": "TA0001"}]
    bundle = {
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x--1",
                "name": "Initial Access",
                "x_mitre_shortname": "initial-access",
                "external_references": ref,
            },
            {"type": "x-mitre-matrix", "id": "m--1", "tactic_refs": ["x--1"]},
            {
                "type": "attack-pattern",
                "id": "a--1",
                "name": "Exploit",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "a--2",
                "name": "Old",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}],
            },
            {
                "type": "attack-pattern",
                "id": "a--3",
                "name": "Sub",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190.001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
        ]
    }
    src = tmp_path / "bundle.json"
    src.write_text(json.dumps(bundle))
    out = tmp_path / "out.json"
    sys.argv = ["gen", "--version", "1.0", "--input", str(src), "--out", str(out)]
    assert gen.main() == 0
    data = json.loads(out.read_text())
    assert [t["id"] for t in data["techniques"]] == ["T1190", "T1190.001"]
    assert data["techniques"][1]["parent"] == "T1190"
    assert data["tactics"] == [
        {"id": "TA0001", "shortname": "initial-access", "name": "Initial Access"}
    ]
    assert len(data["source_sha256"]) == 64


def test_lint_warns_on_unknown_techniques(tmp_path: Path) -> None:
    (tmp_path / "r.yml").write_text(
        "title: t\nid: 70000000-0000-0000-0000-000000000001\nlogsource: {category: webserver}\n"
        "detection: {sel: {cs-method: POST}, condition: sel}\ntags: [attack.t9999]\n"
    )
    messages = [i.message for i in lint(load_rules([(tmp_path, "user")]))]
    assert any("T9999 is not in ATT&CK" in m for m in messages)


@pytest.fixture
def env(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = Settings(data_dir=tmp_path / "d", watch_enabled=False)  # type: ignore[call-arg]
    s.ensure_dirs()
    init_db(s.db_path)
    s.rules_path.mkdir(parents=True)
    with closing(connect(s.db_path)) as conn:
        yield s, conn, DetectionEngine(s)


def cell(cov, technique: str):  # type: ignore[no-untyped-def]
    for _, _, cells in cov.columns:
        for c in cells:
            if c.technique == technique:
                return c
    raise AssertionError(technique)


def test_coverage_levels_subtechniques_and_unknown(env) -> None:  # type: ignore[no-untyped-def]
    s, conn, engine = env
    (s.rules_path / "x.yml").write_text(
        "title: Untested custom\nid: 70000000-0000-0000-0000-000000000002\n"
        "logsource: {category: webserver}\ndetection: {sel: {cs-method: TRACE}, condition: sel}\n"
        "tags: [attack.t1059, attack.t9999]\n"
    )
    engine.reload(conn)
    engine.run_tests(conn)
    cov = compute(conn)
    assert cell(cov, "T1190").level == 2  # example rule with passing tests, not fired yet
    assert cell(cov, "T1059").level == 1  # rule, no tests
    assert cell(cov, "T1110").enabled >= 1 and "T1110.001" in cell(cov, "T1110").sub_covered
    assert cell(cov, "T1003").level == 0
    assert cov.unknown_tags == {"T9999": ["Untested custom"]}
    assert 0 < cov.covered < cov.total
    # fire the SQLi rule -> level 3
    p = s.data_dir / "a.log"
    p.write_text("\n".join(web_lines(3000, seed=8)) + "\n")
    from threatlens.ingest.files import ingest_path  # noqa: PLC0415
    from threatlens.ingest.pipeline import IngestOptions  # noqa: PLC0415

    [rep] = ingest_path(conn, p, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
    engine.run_ranges(conn, rep.chunks)
    assert cell(compute(conn), "T1190").level == 3
    # disabled rules do not count
    engine.set_enabled(conn, SQLI, False, "t")
    assert cell(compute(conn), "T1190").enabled == 0

    layer = navigator_layer(compute(conn))
    assert layer["versions"]["attack"] == "20" and layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"]: t for t in layer["techniques"]}
    assert "T1110" in ids and "T1110.001" in ids and "T1059" in ids
    assert ids["T1110"]["score"] >= 1 and "rule(s)" in ids["T1110"]["comment"]
    assert layer["gradient"]["maxValue"] >= 1


def test_rule_metrics_precision(env) -> None:  # type: ignore[no-untyped-def]
    s, conn, engine = env
    engine.reload(conn)
    p = s.data_dir / "a.log"
    p.write_text("\n".join(web_lines(3000, seed=8)) + "\n")
    from threatlens.ingest.files import ingest_path  # noqa: PLC0415
    from threatlens.ingest.pipeline import IngestOptions  # noqa: PLC0415

    [rep] = ingest_path(conn, p, IngestOptions(), default_timezone="UTC", max_bytes=2**30)
    engine.run_ranges(conn, rep.chunks)
    ids = [
        r[0] for r in conn.execute("SELECT id FROM alerts WHERE rule_id = ? ORDER BY id", (SQLI,))
    ]
    assert len(ids) == 3
    with transaction(conn):
        set_status(conn, ids[:2], "closed", "true_positive", "t")
        set_status(conn, ids[2:], "closed", "false_positive", "t")
    m = {x.id: x for x in rule_metrics(conn)}[SQLI]
    assert (m.tp, m.fp, m.btp, m.open, m.closed) == (2, 1, 0, 0, 3)
    assert m.precision == pytest.approx(2 / 3)
    assert m.techniques == ["T1190"]
    by_id = {x.id: x for x in rule_metrics(conn)}
    assert by_id["d3b91716-cedd-4375-893e-31635e879920"].correlation_only  # generate: false
    assert not by_id[SQLI].correlation_only
    untouched = next(x for x in rule_metrics(conn) if x.alerts == 0)
    assert untouched.precision is None


# ---------------------------------------------------------------- web


def test_coverage_and_metrics_pages(authed: TestClient, db: sqlite3.Connection) -> None:
    page = authed.get("/coverage")
    assert page.status_code == 200
    assert "Exploit Public-Facing Application" in page.text and "v20.0" in page.text
    only = authed.get("/coverage?covered=1").text
    assert "Exploit Public-Facing Application" in only and "OS Credential Dumping" not in only
    nav = authed.get("/coverage/navigator.json")
    assert nav.headers["content-disposition"].startswith("attachment")
    assert json.loads(nav.text)["domain"] == "enterprise-attack"

    upload(authed, [("access.log", text(web_lines(3000, seed=8)))])
    wait_idle(authed)
    aid = db.execute("SELECT id FROM alerts WHERE rule_id = ? LIMIT 1", (SQLI,)).fetchone()[0]
    csrf = page_csrf(authed.get("/alerts").text)
    authed.post(
        "/alerts/bulk",
        data={
            "csrf_token": csrf,
            "ids": str(aid),
            "action": "status",
            "status": "closed",
            "resolution": "false_positive",
        },
    )
    metrics = authed.get("/metrics")
    assert "Noisiest rules" in metrics.text and "0%" in metrics.text
    for sort in ("alerts", "precision", "fp", "title", "bogus"):
        assert authed.get(f"/metrics?sort={sort}").status_code == 200
    # case findings now carry technique names
    resp = authed.post("/cases", data={"csrf_token": csrf, "ids": str(aid)}, follow_redirects=True)
    assert "Exploit Public-Facing Application" in resp.text


def test_xss_in_coverage_and_metrics(authed: TestClient, settings: Settings) -> None:
    (settings.rules_path / "xss.yml").write_text(
        f"title: '{XSS}'\nid: 70000000-0000-0000-0000-000000000003\nlevel: high\n"
        "logsource: {category: webserver}\ndetection: {sel: {cs-method: GET}, condition: sel}\n"
        "tags: [attack.t1190]\n"
    )
    csrf = page_csrf(authed.get("/rules").text)
    authed.post("/rules/reload", headers={"X-CSRF-Token": csrf})
    for path in ["/coverage", "/coverage?covered=1", "/metrics"]:
        assert_inert(authed.get(path).text)
    layer = authed.get("/coverage/navigator.json").text
    assert XSS in layer  # JSON for Navigator; it is data, served as an attachment
