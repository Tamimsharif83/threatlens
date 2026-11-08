"""Stored/reflected XSS: attacker-controlled text must always render inert.

Phase 0 covers the fields that exist so far (usernames, the `next` parameter).
Later phases extend this with log fields (URL, user agent, body, user name)
rendered on every page.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import login
from threatlens.auth.users import Role, create_user
from threatlens.storage.db import transaction

PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "<svg/onload=alert(1)>",
    "'><iframe srcdoc='<script>alert(1)</script>'>",
]
SRC = Path(__file__).resolve().parents[1] / "src" / "threatlens"


def _assert_inert(html: str, payload: str) -> None:
    assert payload not in html
    assert "<script>alert" not in html
    assert not re.search(r"<(img|svg|iframe)[^>]*on(error|load)=", html, re.I)


@pytest.mark.parametrize("payload", PAYLOADS)
def test_xss_username_rendered_inert(
    client: TestClient, db: sqlite3.Connection, payload: str
) -> None:
    conn = db
    with transaction(conn):
        create_user(conn, payload, "xss-test-password", Role.ANALYST)
    assert login(client, payload, "xss-test-password").status_code == 303
    html = client.get("/").text
    _assert_inert(html, payload)
    assert "&lt;" in html  # it is there, but escaped


@pytest.mark.parametrize("payload", PAYLOADS)
def test_xss_next_param_reflected_inert(client: TestClient, payload: str) -> None:
    html = client.get("/login", params={"next": "/" + payload}).text
    _assert_inert(html, payload)


def test_no_unsafe_template_constructs() -> None:
    """Guard rail: nothing in the code base may switch escaping off."""
    banned = [
        r"\|\s*safe\b",
        r"autoescape\s+false",
        r"\bMarkup\(",
        # DOM property writes (HTMX's hx-swap="innerHTML" swaps escaped server HTML: fine)
        r"\.innerHTML\b",
        r"\.outerHTML\b",
        r"insertAdjacentHTML",
        r"document\.write",
        r"hx-on",
    ]
    offenders = []
    for path in SRC.rglob("*"):
        if path.suffix not in {".html", ".py", ".js"} or "vendor" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in banned:
            # The JS comment that warns *against* innerHTML is allowed.
            for m in re.finditer(pattern, text):
                line = text[: m.start()].count("\n")
                if "Never assign" in text.splitlines()[line]:
                    continue
                offenders.append(f"{path.relative_to(SRC)}:{line + 1}: {pattern}")
    assert offenders == []
