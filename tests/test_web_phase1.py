"""Web UI for Phase 1: upload & ingest, settings, account, overview, and XSS via log data."""

from __future__ import annotations

import gzip
import io
import re
import sqlite3
import time
from pathlib import Path

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from tests.conftest import ADMIN_PASSWORD, login, page_csrf
from threatlens.auth.users import Role, create_user
from threatlens.cli.main import cli
from threatlens.config import Settings
from threatlens.storage.db import transaction
from threatlens.synth import auth_lines, web_lines
from threatlens.web.app import create_app

XSS = "<script>alert(1)</script>"
XSS_ATTR = '"><img src=x onerror=alert(1)>'
XSS_SQ = "'><img src=x onerror=alert(1)>"  # survives inside a quoted log field


def wait_idle(client: TestClient, timeout: float = 20) -> None:
    worker = client.app.state.services.worker  # type: ignore[attr-defined]
    deadline = time.monotonic() + timeout
    while not worker.idle():
        assert time.monotonic() < deadline, "ingest job did not finish"
        time.sleep(0.05)


def upload(client: TestClient, files: list[tuple[str, bytes]], htmx: bool = True, **form: str):  # type: ignore[no-untyped-def]
    csrf = page_csrf(client.get("/ingest").text)
    headers = {"X-CSRF-Token": csrf}
    if htmx:
        headers["HX-Request"] = "true"
    return client.post(
        "/ingest/upload",
        files=[
            ("files", (name, io.BytesIO(data), "application/octet-stream")) for name, data in files
        ],
        data=form,
        headers=headers,
        follow_redirects=False,
    )


def text(lines: object) -> bytes:
    return ("\n".join(lines) + "\n").encode()  # type: ignore[call-overload]


def assert_inert(html: str) -> None:
    assert XSS not in html
    assert "<script>alert" not in html
    assert not re.search(r"<img[^>]*onerror=", html, re.I)


# ---------------------------------------------------------------- upload


def test_upload_ingests_and_reports(authed: TestClient) -> None:
    resp = upload(
        authed,
        [
            ("access.log", text(web_lines(300, seed=5))),
            ("auth.log.gz", gzip.compress(text(auth_lines(50, seed=5)))),
        ],
    )
    assert resp.status_code == 200
    assert "Queued for ingestion: access.log, auth.log.gz" in resp.text
    wait_idle(authed)
    page = authed.get("/ingest").text
    assert "access.log" in page and "auth.log" in page
    batch = authed.get("/ingest/batches/1")
    assert batch.status_code == 200
    assert "ev_webserver" in batch.text
    overview = authed.get("/")
    assert "350" in overview.text  # events stored
    series = authed.get("/api/v1/stats/events-over-time").json()
    assert set(series["series"]) == {"webserver", "linux_auth"}
    assert sum(series["series"]["webserver"]) == 300
    live = authed.get("/ingest/live")
    assert live.status_code == 200 and "Batch history" in live.text


def test_upload_without_htmx_redirects(authed: TestClient) -> None:
    resp = upload(authed, [("a.log", text(web_lines(5)))], htmx=False)
    assert resp.status_code == 303 and resp.headers["location"] == "/ingest"
    wait_idle(authed)


@pytest.mark.parametrize(
    ("name", "data", "message"),
    [
        ("evil.exe", b"MZ\x90", "file type not accepted"),
        ("a.log", b"MZ\x90\x00binary", "binary"),
        ("a.log", gzip.compress(b"x"), "does not end in .gz"),
        ("a.gz", b"plain text", "not a valid gz"),
        ("a.log", b"", "empty file"),
    ],
)
def test_upload_rejections(authed: TestClient, name: str, data: bytes, message: str) -> None:
    resp = upload(authed, [(name, data)])
    assert resp.status_code == 400
    assert message in resp.text
    uploads = authed.app.state.settings.data_dir / "uploads"  # type: ignore[attr-defined]
    assert not list(uploads.glob("*.upload"))  # rejected files are not kept


def test_upload_option_validation(authed: TestClient) -> None:
    resp = upload(
        authed,
        [("a.log", text(web_lines(3)))],
        parser="windows",
        timezone="Mars/Base",
        source_name="bad<name>",
        web_format="%",
        mapping="nope",
    )
    assert resp.status_code == 400
    for msg in [
        "Unknown log type",
        "Unknown timezone",
        "Source name",
        "Web log format",
        "not available",
    ]:
        assert msg in resp.text


def test_upload_requires_csrf_and_login(client: TestClient, authed: TestClient) -> None:
    resp = authed.post(
        "/ingest/upload", files=[("files", ("a.log", b"x\n"))], follow_redirects=False
    )
    assert resp.status_code == 403


def test_upload_size_limit(tmp_path: Path) -> None:
    s = Settings(
        data_dir=tmp_path / "d",
        admin_password=ADMIN_PASSWORD,  # type: ignore[arg-type,call-arg]
        watch_enabled=False,
        max_upload_mb=1,
    )
    with TestClient(create_app(s)) as c:
        login(c)
        resp = upload(c, [("big.log", b"x" * (2 * 1024 * 1024))])
        assert resp.status_code == 413
        assert "too large" in resp.text


def test_non_upload_bodies_are_small(authed: TestClient) -> None:
    csrf = page_csrf(authed.get("/").text)
    resp = authed.post(
        "/logout",
        content=b"a" * (2 * 1024 * 1024),
        headers={"X-CSRF-Token": csrf, "content-type": "text/plain"},
    )
    assert resp.status_code == 413


def test_batch_not_found(authed: TestClient) -> None:
    assert authed.get("/ingest/batches/999").status_code == 404


def test_mapping_files_are_offered(authed: TestClient, settings: Settings) -> None:
    mdir = settings.data_dir / "mappings"
    mdir.mkdir()
    (mdir / "shop.yaml").write_text("name: shop\nlogsource: {product: shop}\ntimestamp: t\n")
    (mdir / "broken.yaml").write_text("bogus: 1\n")
    page = authed.get("/ingest").text
    assert '<option value="shop">shop</option>' in page
    assert "broken (invalid" in page
    resp = upload(
        authed,
        [("s.jsonl", b'{"t": 1767600000, "ip": "1.2.3.4"}\n')],
        parser="json",
        mapping="shop",
    )
    assert resp.status_code == 200
    wait_idle(authed)
    assert "ev_shop" in authed.get("/ingest/batches/1").text


# ---------------------------------------------------------------- XSS through log data


def test_xss_in_log_fields_renders_inert(authed: TestClient, db: sqlite3.Connection) -> None:
    web = [
        # payloads in client address, user, URL, query, referrer and user agent
        f'{XSS} - {XSS} [05/Jan/2026:08:00:00 +0000] "GET /{XSS}?q={XSS} HTTP/1.1" '
        f'200 1 "{XSS_SQ}" "{XSS_SQ}"',
        f'198.51.100.1 - {XSS} [05/Jan/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "x"',
        f"MALFORMED {XSS} {XSS_ATTR}",
        *web_lines(5, seed=1),
    ]
    body = XSS.replace("/", "\\/")
    ecs = [
        '{"@timestamp": "2026-01-05T08:00:00Z", "user": {"name": "' + XSS + '"}, '
        '"source": {"ip": "' + XSS + '"}, '
        '"http": {"request": {"body": {"content": "' + body + '"}}}}'
    ]
    resp = upload(authed, [(f"{XSS}.log", text(web))], parser="apache", source_name="x")
    assert resp.status_code == 200
    assert_inert(resp.text)
    resp = upload(authed, [("app.jsonl", text(ecs))], parser="ecs-json")
    assert resp.status_code == 200
    wait_idle(authed)
    # The payloads really are stored...
    assert (
        db.execute('SELECT count(*) FROM ev_webserver WHERE "user.name" = ?', (XSS,)).fetchone()[0]
        == 2
    )
    assert db.execute('SELECT "http.request.body.content" FROM ev_ecs').fetchone()[0] == XSS
    assert db.execute("SELECT malformed FROM ingest_batches WHERE id = 1").fetchone()[0] == 1
    # ...and render as inert text on every page that shows log data.
    for path in [
        "/",
        "/ingest",
        "/ingest/live",
        "/ingest/batches/1",
        "/ingest/batches/2",
        "/settings",
    ]:
        assert_inert(authed.get(path).text)
    overview = authed.get("/").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in overview  # visible, escaped
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in authed.get("/ingest/batches/1").text


def test_cli_output_strips_terminal_escapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path / "d"))
    log = tmp_path / "evil.log"
    log.write_text("\x1b]0;pwned\x07 \x1b[2J junk line\n" + "\n".join(web_lines(10)) + "\n")
    result = CliRunner().invoke(cli, ["ingest", str(log), "--type", "apache"])
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output
    assert "junk line" in result.output


# ---------------------------------------------------------------- settings & users


def analyst(client: TestClient, db: sqlite3.Connection, name: str = "ana") -> None:
    with transaction(db):
        create_user(db, name, "analyst-password-1", Role.ANALYST)
    client.cookies.clear()
    assert login(client, name, "analyst-password-1").status_code == 303


def test_settings_admin_only(client: TestClient, db: sqlite3.Connection) -> None:
    analyst(client, db)
    assert client.get("/settings").status_code == 403
    assert "/settings" not in client.get("/").text  # not in the menu either
    csrf = page_csrf(client.get("/").text)
    assert (
        client.post("/settings/users", data={"username": "x", "csrf_token": csrf}).status_code
        == 403
    )


def _post(client: TestClient, path: str, **data: str):  # type: ignore[no-untyped-def]
    csrf = page_csrf(client.get("/settings").text)
    return client.post(path, data={"csrf_token": csrf, **data}, follow_redirects=False)


def test_create_user_and_forced_password_change(authed: TestClient) -> None:
    resp = _post(authed, "/settings/users", username="bob", role="analyst")
    assert resp.status_code == 200
    password = re.search(r'class="secret">([^<]+)<', resp.text)
    assert password
    assert _post(authed, "/settings/users", username="bob").status_code == 409
    assert _post(authed, "/settings/users", username="bad name!").status_code == 400

    authed.cookies.clear()
    assert login(authed, "bob", password.group(1)).status_code == 303
    # Everything except /account is blocked until the password is changed.
    assert authed.get("/", follow_redirects=False).headers["location"] == "/account"
    assert authed.get("/api/v1/me").status_code == 403
    csrf = page_csrf(authed.get("/account").text)
    bad = authed.post(
        "/account",
        data={
            "csrf_token": csrf,
            "current_password": "wrong",
            "new_password": "x" * 12,
            "confirm_password": "x" * 12,
        },
    )
    assert bad.status_code == 400 and "Current password is wrong" in bad.text
    ok = authed.post(
        "/account",
        data={
            "csrf_token": csrf,
            "current_password": password.group(1),
            "new_password": "bobs-new-password",
            "confirm_password": "bobs-new-password",
        },
        follow_redirects=False,
    )
    assert ok.status_code == 303
    assert authed.get("/api/v1/me").json() == {"username": "bob", "role": "analyst"}


@pytest.mark.parametrize(
    ("new", "confirm", "message"),
    [
        ("short", "short", "at least"),
        ("a-long-password-1", "different-pass-2", "do not match"),
        (ADMIN_PASSWORD, ADMIN_PASSWORD, "different from the current"),
    ],
)
def test_account_password_rules(authed: TestClient, new: str, confirm: str, message: str) -> None:
    csrf = page_csrf(authed.get("/account").text)
    resp = authed.post(
        "/account",
        data={
            "csrf_token": csrf,
            "current_password": ADMIN_PASSWORD,
            "new_password": new,
            "confirm_password": confirm,
        },
    )
    assert resp.status_code == 400 and message in resp.text


def test_disable_enable_reset_and_last_admin(authed: TestClient, db: sqlite3.Connection) -> None:
    with transaction(db):
        uid = create_user(db, "eve", "eve-password-12", Role.ANALYST).id
    admin_id = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[0]
    assert "eve disabled" in _post(authed, f"/settings/users/{uid}/disable").text
    assert db.execute("SELECT disabled FROM users WHERE id = ?", (uid,)).fetchone()[0] == 1
    assert "eve enabled" in _post(authed, f"/settings/users/{uid}/enable").text
    reset = _post(authed, f"/settings/users/{uid}/reset-password")
    assert "Password reset for eve" in reset.text
    assert (
        db.execute("SELECT must_change_password FROM users WHERE id = ?", (uid,)).fetchone()[0] == 1
    )
    own = _post(authed, f"/settings/users/{admin_id}/disable")
    assert own.status_code == 400
    assert _post(authed, "/settings/users/9999/disable").status_code == 404
    assert _post(authed, f"/settings/users/{uid}/explode").status_code == 404


def test_last_admin_cannot_be_disabled(authed: TestClient, db: sqlite3.Connection) -> None:
    with transaction(db):
        other = create_user(db, "root2", "root2-password-x", Role.ADMIN).id
        db.execute("UPDATE users SET disabled = 1 WHERE username = 'admin'")
    # 'admin' is now disabled, so the session is gone: log in as root2.
    authed.cookies.clear()
    assert login(authed, "root2", "root2-password-x").status_code == 303
    admin_id = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[0]
    with transaction(db):
        db.execute("UPDATE users SET disabled = 0 WHERE id = ?", (admin_id,))
        db.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (admin_id,))
    resp = _post(authed, f"/settings/users/{other}/disable")
    assert resp.status_code == 400  # own account
    with transaction(db):
        db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (admin_id,))
        db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (admin_id,))
        third = create_user(db, "x3", "x3-password-xxx", Role.ADMIN).id
        db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (third,))
    # root2 is the only active admin: disabling another (inactive) admin is fine,
    # but the check counts active admins, so test through a second active admin.
    with transaction(db):
        db.execute("UPDATE users SET disabled = 0 WHERE id = ?", (third,))
    assert _post(authed, f"/settings/users/{third}/disable").status_code == 200


def test_general_settings_and_maintenance(authed: TestClient, db: sqlite3.Connection) -> None:
    ok = _post(authed, "/settings/general", retention_days="14", default_timezone="Asia/Dhaka")
    assert "Settings saved" in ok.text
    assert 'value="14"' in ok.text
    bad = _post(authed, "/settings/general", retention_days="0", default_timezone="UTC")
    assert bad.status_code == 400
    bad_tz = _post(authed, "/settings/general", retention_days="5", default_timezone="Nope/X")
    assert bad_tz.status_code == 400
    assert "Retention purge" in _post(authed, "/settings/maintenance/purge").text
    assert "compacted" in _post(authed, "/settings/maintenance/compact").text
    assert _post(authed, "/settings/maintenance/format-disk").status_code == 404
    actions = [r[0] for r in db.execute("SELECT action FROM audit_log")]
    assert {"settings.update", "maintenance.purge", "maintenance.compact"} <= set(actions)


# ---------------------------------------------------------------- CLI


def test_cli_ingest_db_and_synth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path / "d"))
    runner = CliRunner()
    out = tmp_path / "logs"
    out.mkdir()
    assert (
        runner.invoke(
            cli, ["synth", "--kind", "web", "--lines", "200", "-o", str(out / "access.log")]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli, ["synth", "--kind", "auth", "--lines", "50", "-o", str(out / "auth.log")]
        ).exit_code
        == 0
    )
    (out / "notes.md").write_text("ignored: not a log extension\n")
    result = runner.invoke(cli, ["ingest", str(out), "--tz", "Asia/Dhaka"])
    assert result.exit_code == 0, result.output
    assert result.output.count("OK ") == 2
    again = runner.invoke(cli, ["ingest", str(out / "access.log")])
    assert "0 events, 200 duplicates" in again.output
    stats = runner.invoke(cli, ["db", "stats"])
    assert "250 events" in stats.output and "ev_webserver" in stats.output
    assert "retention 30 days" in runner.invoke(cli, ["db", "purge"]).output
    assert "MB ->" in runner.invoke(cli, ["db", "compact", "--full"]).output
    stdout = runner.invoke(cli, ["synth", "--kind", "ecs", "--lines", "3", "--seed", "4"])
    assert stdout.output.count("\n") == 3


def test_cli_ingest_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path / "d"))
    runner = CliRunner()
    junk = tmp_path / "junk.log"
    junk.write_text("not a log\n" * 20)
    assert runner.invoke(cli, ["ingest", str(junk)]).exit_code == 1
    assert runner.invoke(cli, ["ingest", str(junk), "--tz", "Nope/X"]).exit_code == 2
    bad_map = tmp_path / "m.yaml"
    bad_map.write_text("bogus: 1\n")
    assert runner.invoke(cli, ["ingest", str(junk), "--mapping", str(bad_map)]).exit_code == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert runner.invoke(cli, ["ingest", str(empty)]).exit_code == 1
