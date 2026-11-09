from __future__ import annotations

import re
import sqlite3
import time

from fastapi.testclient import TestClient

from tests.conftest import page_csrf
from tests.test_web_phase1 import XSS, assert_inert, text, upload, wait_idle
from threatlens.config import Settings
from threatlens.synth import web_lines

SQLI = "3815fe7c-7c88-4597-aa81-98ebaabeeb5f"


def post(client: TestClient, path: str, htmx: bool = False):  # type: ignore[no-untyped-def]
    csrf = page_csrf(client.get("/rules").text)
    headers = {"X-CSRF-Token": csrf}
    if htmx:
        headers["HX-Request"] = "true"
    return client.post(path, headers=headers, follow_redirects=False)


def test_rules_page_lists_examples_with_test_status(authed: TestClient) -> None:
    page = authed.get("/rules")
    assert page.status_code == 200
    assert len(re.findall(r'<a href="/rules/[0-9a-f-]+">\[Example\]', page.text)) == 5
    assert page.text.count('class="badge status-done">pass</span>') == 5
    detail = authed.get(f"/rules/{SQLI}")
    assert "Compiled query" in detail.text
    assert "SELECT * FROM ev_webserver WHERE" in detail.text
    assert "attack.t1190" in detail.text
    assert authed.get("/rules/does-not-exist").status_code == 404


def test_toggle_reload_and_audit(authed: TestClient, db: sqlite3.Connection) -> None:
    resp = post(authed, f"/rules/{SQLI}/disable", htmx=True)
    assert resp.status_code == 200 and 'aria-checked="false"' in resp.text
    assert db.execute("SELECT enabled FROM rules WHERE id = ?", (SQLI,)).fetchone()[0] == 0
    assert post(authed, f"/rules/{SQLI}/enable").status_code == 303
    reload = post(authed, "/rules/reload")
    assert "Reloaded 5 rule(s)" in reload.text
    assert post(authed, f"/rules/{SQLI}/test").status_code == 303
    assert post(authed, f"/rules/{SQLI}/explode").status_code == 404
    actions = {r[0] for r in db.execute("SELECT action FROM audit_log")}
    assert {"rule.disable", "rule.enable", "rules.reload"} <= actions


def test_upload_creates_alerts_and_retro_hunt(authed: TestClient, db: sqlite3.Connection) -> None:
    upload(authed, [("access.log", text(web_lines(3000, seed=8)))])
    wait_idle(authed)
    alerts = authed.get("/alerts")
    assert "[Example] SQL Injection Pattern in URL Query" in alerts.text
    assert authed.get("/alerts?level=high&status_filter=new").status_code == 200
    assert authed.get("/alerts?level=bogus&status_filter=bogus").status_code == 200
    overview = authed.get("/").text
    assert "Top rules" in overview and "[Example]" in overview
    hunt = post(authed, f"/rules/{SQLI}/retro-hunt")
    assert hunt.status_code == 303
    location = hunt.headers["location"]
    deadline = time.monotonic() + 20
    while True:
        page = authed.get(location).text
        if "Retro-hunt done" in page:
            break
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert "0 new matching event(s)" in page
    assert (
        db.execute("SELECT count(*) FROM audit_log WHERE action = 'rule.retro_hunt'").fetchone()[0]
        == 1
    )


def test_user_rules_errors_shown(authed: TestClient, settings: Settings) -> None:
    rules = settings.rules_path
    (rules / "bad.yml").write_text("key: [unclosed\n")
    (rules / "broken.yml").write_text(
        "title: Broken\nid: 30000000-0000-0000-0000-000000000001\n"
        "logsource: {category: webserver}\ndetection: {condition: nothing}\n"
    )
    page = post(authed, "/rules/reload").text
    assert "Files that could not be loaded" in page and "user:bad.yml" in page
    assert re.search(r"Broken.*?status-failed", page, re.S)
    resp = post(authed, "/rules/30000000-0000-0000-0000-000000000001/retro-hunt")
    assert resp.status_code == 400


def test_xss_in_rules_and_alerts_is_inert(authed: TestClient, settings: Settings) -> None:
    (settings.rules_path / "xss.yml").write_text(
        f"title: '{XSS}'\nid: 30000000-0000-0000-0000-000000000002\n"
        f"description: '{XSS}'\nauthor: '{XSS}'\nstatus: test\nlevel: high\n"
        "tags: [attack.t1190]\nlogsource: {category: webserver}\n"
        "detection: {sel: {cs-method: GET}, condition: sel}\n"
    )
    reload = post(authed, "/rules/reload").text
    assert_inert(reload)
    assert "Reloaded 6 rule(s): 0 with errors" in reload
    line = f'{XSS} - - [05/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'
    upload(authed, [("x.log", text([line, *list(web_lines(5, seed=1))]))], parser="apache")
    wait_idle(authed)
    for path in ["/rules", "/rules/30000000-0000-0000-0000-000000000002", "/alerts", "/"]:
        html = authed.get(path).text
        assert_inert(html)
    assert "&lt;script&gt;" in authed.get("/alerts").text  # entity shown as text
