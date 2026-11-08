from __future__ import annotations

import sqlite3
from contextlib import closing

from fastapi.testclient import TestClient

from tests.conftest import ADMIN_PASSWORD, login, login_csrf, page_csrf
from threatlens import audit
from threatlens.auth.users import Role, create_user
from threatlens.config import Settings
from threatlens.storage.db import connect, transaction
from threatlens.web.app import create_app


def _actions(settings: Settings) -> list[str]:
    with closing(connect(settings.db_path)) as conn:
        return [e.action for e in audit.recent(conn)]


def test_unauthenticated_page_redirects_to_login(client: TestClient) -> None:
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_redirect_keeps_target(client: TestClient) -> None:
    resp = client.get("/docs?x=1", follow_redirects=False)
    assert resp.headers["location"] == "/login?next=/docs%3Fx%3D1"


def test_unauthenticated_api_gets_401_json(client: TestClient) -> None:
    resp = client.get("/api/v1/me")
    assert resp.status_code == 401
    assert resp.json() == {"detail": "not authenticated"}


def test_htmx_request_gets_hx_redirect(client: TestClient) -> None:
    resp = client.get("/", headers={"HX-Request": "true"}, follow_redirects=False)
    assert resp.status_code == 204
    assert resp.headers["HX-Redirect"] == "/login"


def test_login_success_sets_hardened_cookie(client: TestClient, settings: Settings) -> None:
    resp = login(client)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    cookie = next(
        h for h in resp.headers.get_list("set-cookie") if h.startswith("tl_session=")
    ).lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    page = client.get("/")
    assert page.status_code == 200
    assert "Overview" in page.text
    assert client.get("/api/v1/me").json() == {"username": "admin", "role": "admin"}
    assert "auth.login.success" in _actions(settings)


def test_session_token_not_stored_in_clear(client: TestClient, settings: Settings) -> None:
    login(client)
    token = client.cookies.get("tl_session")
    assert token
    with closing(connect(settings.db_path)) as conn:
        stored = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
    assert token not in stored
    assert len(stored[0]) == 64


def test_secure_cookie_over_https(settings: Settings) -> None:
    with TestClient(create_app(settings), base_url="https://testserver") as c:
        resp = login(c)
        cookies = resp.headers.get_list("set-cookie")
        session = next(h for h in cookies if h.startswith("__Host-tl_session="))
        assert "secure" in session.lower()


def test_wrong_password(client: TestClient, settings: Settings) -> None:
    resp = login(client, password="wrong-password-123")
    assert resp.status_code == 401
    assert "Invalid username or password." in resp.text
    assert client.get("/api/v1/me").status_code == 401
    assert "auth.login.failure" in _actions(settings)


def test_unknown_user_same_message(client: TestClient) -> None:
    resp = login(client, username="nobody", password="whatever-password")
    assert resp.status_code == 401
    assert "Invalid username or password." in resp.text


def test_login_requires_csrf(client: TestClient) -> None:
    client.get("/login")
    resp = client.post(
        "/login",
        data={"username": "admin", "password": ADMIN_PASSWORD, "csrf_token": "forged"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_login_rate_limited(client: TestClient, settings: Settings) -> None:
    for _ in range(settings.login_max_failures):
        assert login(client, password="bad-password-xx").status_code == 401
    resp = login(client)  # even the right password is refused while throttled
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) > 0
    assert "Too many failed attempts" in resp.text
    assert "auth.login.throttled" in _actions(settings)


def test_open_redirect_blocked(client: TestClient) -> None:
    for evil in ["//evil.example", "https://evil.example", "/\\evil.example", "javascript:x"]:
        resp = login(client, next=evil)
        assert resp.headers["location"] == "/", evil
        client.cookies.clear()


def test_local_next_honoured(client: TestClient) -> None:
    assert login(client, next="/docs").headers["location"] == "/docs"


def test_login_page_redirects_when_logged_in(authed: TestClient) -> None:
    resp = authed.get("/login", follow_redirects=False)
    assert resp.status_code == 303


def test_logout_requires_csrf(authed: TestClient) -> None:
    assert authed.post("/logout", follow_redirects=False).status_code == 403
    assert authed.get("/api/v1/me").status_code == 200


def test_logout_invalidates_session(authed: TestClient, settings: Settings) -> None:
    token = authed.cookies.get("tl_session")
    csrf = page_csrf(authed.get("/").text)
    resp = authed.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
    # Replaying the old cookie must not work.
    authed.cookies.set("tl_session", token or "")
    assert authed.get("/api/v1/me").status_code == 401
    assert "auth.logout" in _actions(settings)


def test_csrf_header_accepted(authed: TestClient) -> None:
    csrf = page_csrf(authed.get("/").text)
    resp = authed.post("/logout", headers={"X-CSRF-Token": csrf}, follow_redirects=False)
    assert resp.status_code == 303


def test_disabled_user_cannot_log_in(client: TestClient, db: sqlite3.Connection) -> None:
    conn = db
    with transaction(conn):
        create_user(conn, "eve", "eve-password-123", Role.ANALYST)
        conn.execute("UPDATE users SET disabled = 1 WHERE username = 'eve'")
    assert login(client, "eve", "eve-password-123").status_code == 401


def test_disabling_user_kills_session(client: TestClient, db: sqlite3.Connection) -> None:
    conn = db
    with transaction(conn):
        create_user(conn, "mallory", "mallory-password", Role.ANALYST)
    assert login(client, "mallory", "mallory-password").status_code == 303
    assert client.get("/api/v1/me").json()["role"] == "analyst"
    with transaction(conn):
        conn.execute("UPDATE users SET disabled = 1 WHERE username = 'mallory'")
    assert client.get("/api/v1/me").status_code == 401


def test_expired_session_rejected(authed: TestClient, db: sqlite3.Connection) -> None:
    conn = db
    with transaction(conn):
        conn.execute("UPDATE sessions SET expires_at = 0")
    assert authed.get("/api/v1/me").status_code == 401


def test_login_form_has_token(client: TestClient) -> None:
    assert len(login_csrf(client)) >= 32
