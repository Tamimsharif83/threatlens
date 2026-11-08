from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatlens.config import Settings
from threatlens.storage.db import connect
from threatlens.web.app import create_app

ADMIN_PASSWORD = "correct-horse-battery-staple"
_CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
_META_CSRF_RE = re.compile(r'<meta name="csrf-token" content="([^"]*)">')


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never let the developer's own TL_* environment leak into tests."""
    for key in list(os.environ):
        if key.startswith("TL_"):
            monkeypatch.delenv(key)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        admin_password=ADMIN_PASSWORD,  # type: ignore[arg-type]
        watch_enabled=False,  # tests drive the watcher explicitly
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as c:
        yield c


def login_csrf(client: TestClient) -> str:
    resp = client.get("/login")
    match = _CSRF_RE.search(resp.text)
    assert match, "login form has no CSRF token"
    return match.group(1)


def page_csrf(html: str) -> str:
    match = _META_CSRF_RE.search(html)
    assert match
    return match.group(1)


def login(
    client: TestClient, username: str = "admin", password: str = ADMIN_PASSWORD, **extra: str
):  # type: ignore[no-untyped-def]
    token = login_csrf(client)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token, **extra},
        follow_redirects=False,
    )


@pytest.fixture
def authed(client: TestClient) -> TestClient:
    resp = login(client)
    assert resp.status_code == 303
    return client


@pytest.fixture
def db(settings: Settings, client: TestClient) -> Iterator[sqlite3.Connection]:
    """A connection to the app's database (after startup), closed at teardown."""
    with closing(connect(settings.db_path)) as conn:
        yield conn
