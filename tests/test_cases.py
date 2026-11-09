"""Phase 5: cases, timeline, IOCs and report export."""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from tests.conftest import page_csrf
from tests.test_web_phase1 import XSS, assert_inert, text, upload, wait_idle
from threatlens.cases import store
from threatlens.reports.render import md_code, md_text, render_html, render_markdown
from threatlens.storage.db import transaction
from threatlens.synth import auth_lines, ecs_lines, web_lines

SQLI = "3815fe7c-7c88-4597-aa81-98ebaabeeb5f"


def seed(client: TestClient) -> None:
    upload(
        client,
        [
            ("access.log", text(web_lines(3000, seed=8))),
            ("auth.log", text(auth_lines(900, seed=3))),
            ("app.jsonl", text(ecs_lines(2000, seed=4))),
        ],
    )
    wait_idle(client)


def post(client: TestClient, path: str, **data: object):  # type: ignore[no-untyped-def]
    csrf = page_csrf(client.get("/cases").text)
    return client.post(path, data={"csrf_token": csrf, **data}, follow_redirects=False)


# ---------------------------------------------------------------- unit


def test_markdown_escaping() -> None:
    assert md_code("a|b") == "`a\\|b`"
    assert md_code("x`y") == "``x`y``"
    assert md_code("`edge`") == "`` `edge` ``"
    assert md_code("line1\nline2\x1b[31m") == "`line1 line2[31m`"
    assert md_code(None) == ""
    assert md_text("**bold** [link](javascript:x) <b>") == (
        "\\*\\*bold\\*\\* \\[link\\]\\(javascript:x\\) \\<b\\>"
    )


def test_case_store_rules(db: sqlite3.Connection, authed: TestClient) -> None:
    with pytest.raises(store.CaseError, match="title"):
        store.create(db, title="  ", severity="low", actor="admin")
    with pytest.raises(store.CaseError, match="severity"):
        store.create(db, title="x", severity="extreme", actor="admin")
    with transaction(db):
        cid = store.create(db, title="Case A", severity="high", actor="admin")
    with pytest.raises(store.CaseError, match="status"):
        store.update(db, cid, "admin", status="done")
    with pytest.raises(store.CaseError, match="user"):
        store.update(db, cid, "admin", assignee="ghost")
    with pytest.raises(store.CaseError, match="longer"):
        store.update(db, cid, "admin", summary="x" * 20_001)
    with pytest.raises(store.CaseError, match="not found"):
        store.update(db, 999, "admin", title="x")
    with transaction(db):
        store.update(db, cid, "admin", status="closed", assignee="admin")
        store.update(db, cid, "admin")  # nothing to change
    case = store.get(db, cid)
    assert case is not None and case.closed_at is not None and case.assignee == "admin"
    with transaction(db):
        store.update(db, cid, "admin", status="open")
    assert store.get(db, cid).closed_at is None  # type: ignore[union-attr]
    for bad in [("ip", ""), ("file_hash", "not-a-hash"), ("planet", "x")]:
        with pytest.raises(store.CaseError):
            store.add_ioc(db, cid, bad[0], bad[1], None, "admin")
    with pytest.raises(store.CaseError):
        store.add_note(db, cid, "admin", "   ")
    with pytest.raises(store.CaseError):
        store.add_annotation(db, cid, 0, "admin", "")
    with pytest.raises(store.CaseError):
        store.delete_annotation(db, cid, 999, "admin")
    with pytest.raises(store.CaseError):
        store.delete_ioc(db, cid, 999, "admin")
    with pytest.raises(store.CaseError, match="not found"):
        store.add_alerts(db, 999, [1], "admin")
    assert store.list_cases(db, "open")[0]["title"] == "Case A"
    assert store.list_cases(db, "closed") == []
    assert store.list_cases(db, "all")


# ---------------------------------------------------------------- end to end


def test_case_from_alerts_timeline_iocs_and_reports(
    authed: TestClient, db: sqlite3.Connection
) -> None:
    seed(authed)
    ids = [
        r[0]
        for r in db.execute(
            "SELECT id FROM alerts WHERE rule_id = ? OR kind = 'correlation' OR level = 'critical' "
            "ORDER BY id",
            (SQLI,),
        )
    ]
    assert len(ids) >= 3
    # bulk "Add to case" from the queue (new case, title from the first alert)
    resp = post(authed, "/cases", ids=[str(i) for i in ids])
    assert resp.status_code == 303
    cid = int(resp.headers["location"].rsplit("/", 1)[1])
    case = store.get(db, cid)
    assert case is not None and case.title.startswith("Investigation: ")
    page = authed.get(f"/cases/{cid}")
    assert page.status_code == 200
    assert "T1190" in page.text and "T1110.001" in page.text  # findings by technique

    # IOCs extracted from the case's events (+ a manual one)
    post(authed, f"/cases/{cid}/extract-iocs")
    kinds = {r[0] for r in db.execute("SELECT kind FROM case_iocs WHERE case_id = ?", (cid,))}
    assert {"ip", "url", "user_agent", "file_name"} <= kinds
    post(authed, f"/cases/{cid}/add-ioc", kind="file_hash", value="a" * 64, note="dropper")
    post(authed, f"/cases/{cid}/add-ioc", kind="ip", value="203.0.113.66", note="attacker")
    row = db.execute(
        "SELECT origin, note FROM case_iocs WHERE case_id = ? AND value = ?", (cid, "203.0.113.66")
    ).fetchone()
    assert tuple(row) == ("manual", "attacker")
    # re-extraction keeps manual entries
    post(authed, f"/cases/{cid}/extract-iocs")
    assert (
        db.execute(
            "SELECT count(*) FROM case_iocs WHERE case_id = ? AND origin = 'manual'", (cid,)
        ).fetchone()[0]
        == 2
    )

    # annotations, notes, report sections, status
    post(authed, f"/cases/{cid}/annotate", ts="2026-01-05T08:30:00", body="scanning starts")
    assert (
        post(authed, f"/cases/{cid}/annotate", ts="yesterday", body="x")
        .headers["location"]
        .startswith(f"/cases/{cid}?error=")
    )
    post(authed, f"/cases/{cid}/note", body="contained the host")
    post(
        authed,
        f"/cases/{cid}/report",
        summary="Attackers scanned and probed the shop.",
        recommendations="- Patch the search endpoint\n- Rate-limit SSH",
    )
    post(
        authed,
        f"/cases/{cid}/update",
        title="Shop compromise attempt",
        severity="high",
        status="contained",
        assignee="admin",
        description="d",
    )
    entries, _ = store.timeline(db, cid)
    assert {e.kind for e in entries} == {"alert", "event", "annotation"}
    assert entries == sorted(entries, key=lambda e: e.ts)

    md = authed.get(f"/cases/{cid}/report.md")
    assert md.headers["content-disposition"].startswith('attachment; filename="threatlens-case-')
    for heading in [
        "## 1. Executive summary",
        "## 2. Scope",
        "## 3. Timeline",
        "## 4. Findings mapped to MITRE ATT&CK",
        "## 5. Indicators of compromise",
        "## 6. Impact",
        "## 7. Root cause",
        "## 8. Recommendations",
        "## 9. Appendix",
    ]:
        assert heading in md.text
    assert "Attackers scanned and probed the shop." in md.text
    assert "- Patch the search endpoint" in md.text
    assert "scanning starts" in md.text and "contained the host" in md.text

    html = authed.get(f"/cases/{cid}/report.html")
    assert html.headers["content-type"].startswith("text/html")
    assert "default-src 'none'" in html.text and "<script" not in html.text
    assert "Shop compromise attempt" in html.text and "5. Indicators of compromise" in html.text

    csv_resp = authed.get(f"/cases/{cid}/iocs.csv")
    rows = list(csv.reader(io.StringIO(csv_resp.text)))
    assert rows[0][:2] == ["type", "value"] and len(rows) > 3
    data = json.loads(authed.get(f"/cases/{cid}/iocs.json").text)
    assert {"kind", "value", "occurrences"} <= set(data[0])
    assert authed.get(f"/cases/{cid}/iocs.xml").status_code == 404

    # remove an alert, delete an IOC and an annotation; alert page shows the case
    ann = db.execute("SELECT id FROM case_annotations WHERE case_id = ?", (cid,)).fetchone()[0]
    ioc = db.execute("SELECT id FROM case_iocs WHERE case_id = ? LIMIT 1", (cid,)).fetchone()[0]
    post(authed, f"/cases/{cid}/delete-annotation", annotation_id=str(ann))
    post(authed, f"/cases/{cid}/delete-ioc", ioc_id=str(ioc))
    post(authed, f"/cases/{cid}/remove-alert", alert_id=str(ids[0]))
    assert f"#{cid} Shop compromise attempt" in authed.get(f"/alerts/{ids[1]}").text
    # add to an existing case from an alert page
    assert post(authed, "/cases", ids=str(ids[0]), case_id=str(cid)).headers["location"] == (
        f"/cases/{cid}"
    )
    actions = {
        r[0] for r in db.execute("SELECT action FROM audit_log WHERE target = ?", (f"case:{cid}",))
    }
    assert {
        "case.create",
        "case.add_alerts",
        "case.extract_iocs",
        "case.add_ioc",
        "case.annotate",
        "case.note",
        "case.update",
        "case.remove_alert",
    } <= actions
    assert "Shop compromise attempt" in authed.get("/cases").text
    assert "Shop compromise attempt" in authed.get("/cases?status_filter=contained").text


def test_case_page_errors(authed: TestClient) -> None:
    assert authed.get("/cases/999").status_code == 404
    assert authed.get("/cases/999/report.md").status_code == 404
    resp = post(authed, "/cases", title="", severity="low")
    assert "msg=" in resp.headers["location"]
    created = post(authed, "/cases", title="manual", severity="low")
    cid = created.headers["location"].rsplit("/", 1)[1]
    assert post(authed, f"/cases/{cid}/explode").status_code == 404
    bad = post(authed, f"/cases/{cid}/update", severity="extreme")
    assert "error=" in bad.headers["location"]
    page = authed.get(bad.headers["location"])
    assert "unknown severity" in page.text


def test_xss_in_cases_and_reports(authed: TestClient, db: sqlite3.Connection) -> None:
    line = (
        f'{XSS} - - [05/Jan/2026:10:00:00 +0000] "GET /x?id=1%20union%20select%201 HTTP/1.1" '
        f'200 1 "-" "{XSS}"'
    )
    upload(authed, [("x.log", text([line, *web_lines(5, seed=1)]))], parser="apache")
    wait_idle(authed)
    aid = db.execute("SELECT id FROM alerts WHERE entities LIKE '%script%'").fetchone()[0]
    resp = post(authed, "/cases", ids=str(aid), title=XSS, severity="high", description=XSS)
    cid = int(resp.headers["location"].rsplit("/", 1)[1])
    post(authed, f"/cases/{cid}/extract-iocs")
    post(authed, f"/cases/{cid}/add-ioc", kind="other", value=XSS, note=XSS)
    post(authed, f"/cases/{cid}/annotate", ts="2026-01-05T10:00:00", body=XSS)
    post(authed, f"/cases/{cid}/note", body=XSS)
    post(authed, f"/cases/{cid}/report", summary=XSS)
    for path in [f"/cases/{cid}", "/cases", f"/alerts/{aid}"]:
        assert_inert(authed.get(path).text)
    html = render_html(db, cid)
    assert_inert(html)
    assert "&lt;script&gt;" in html
    md = render_markdown(db, cid)
    # log values are code spans; titles are escaped
    assert "`<script>alert(1)</script>`" in md
    assert re.search(r"Incident report: \\<script\\>", md)


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        (
            {
                "source.ip": "1.2.3.4",
                "http.request.method": "GET",
                "url.original": "GET /x HTTP/1.1",
            },
            "1.2.3.4 GET /x HTTP/1.1",
        ),
        (
            {"source.ip": "1.2.3.4", "http.request.method": "POST", "url.path": "/login"},
            "1.2.3.4 POST /login",
        ),
        ({"event.action": "file-upload", "file.name": "shell.php"}, "file-upload shell.php"),
        ({"event.action": "ssh_login", "user.name": "root"}, "ssh_login root"),
        ({"message": "hello"}, "hello"),
        ({"a": 1, "b": 2}, "a=1, b=2"),
    ],
)
def test_timeline_event_summaries(fields: dict[str, object], expected: str) -> None:
    from threatlens.alerts.triage import EventView  # noqa: PLC0415

    assert store._event_summary(EventView("ev_x", 1, 0, fields)) == expected
