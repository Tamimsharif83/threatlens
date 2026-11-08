from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import page_csrf

STRICT = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


@pytest.mark.parametrize("path", ["/login", "/healthz", "/does-not-exist"])
def test_headers_on_public_responses(client: TestClient, path: str) -> None:
    resp = client.get(path)
    for name, value in STRICT.items():
        assert resp.headers[name] == value
    csp = resp.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert resp.headers["cache-control"] == "no-store"
    assert "server" not in resp.headers


def test_headers_on_authenticated_page(authed: TestClient) -> None:
    resp = authed.get("/")
    assert "unsafe-inline" not in resp.headers["content-security-policy"]
    assert resp.headers["cache-control"] == "no-store"


def test_docs_csp_only_relaxes_styles(authed: TestClient) -> None:
    resp = authed.get("/docs")
    assert resp.status_code == 200
    csp = resp.headers["content-security-policy"]
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "script-src 'self';" in csp


def test_static_assets_cacheable(client: TestClient) -> None:
    resp = client.get("/static/css/app.css")
    assert resp.status_code == 200
    assert "cache-control" not in resp.headers or resp.headers["cache-control"] != "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_no_inline_scripts_in_pages(authed: TestClient) -> None:
    for path in ["/", "/docs", "/login"]:
        html = authed.get(path).text
        for chunk in html.split("<script")[1:]:
            assert chunk.split(">", 1)[0].strip().startswith("src="), path


def test_cross_origin_post_refused(authed: TestClient) -> None:
    csrf = page_csrf(authed.get("/").text)
    resp = authed.post(
        "/logout",
        data={"csrf_token": csrf},
        headers={"Origin": "https://evil.example"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_cross_site_fetch_refused(authed: TestClient) -> None:
    csrf = page_csrf(authed.get("/").text)
    resp = authed.post(
        "/logout",
        data={"csrf_token": csrf},
        headers={"Sec-Fetch-Site": "cross-site"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_same_origin_post_allowed(authed: TestClient) -> None:
    csrf = page_csrf(authed.get("/").text)
    resp = authed.post(
        "/logout",
        data={"csrf_token": csrf},
        headers={"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_null_origin_same_origin_form_allowed(authed: TestClient) -> None:
    """Real browsers send Origin: null on form posts under Referrer-Policy: no-referrer."""
    csrf = page_csrf(authed.get("/").text)
    resp = authed.post(
        "/logout",
        data={"csrf_token": csrf},
        headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


@pytest.mark.parametrize("fetch_site", [None, "cross-site", "same-site", "none"])
def test_null_origin_without_same_origin_metadata_refused(
    authed: TestClient, fetch_site: str | None
) -> None:
    csrf = page_csrf(authed.get("/").text)
    headers = {"Origin": "null"}
    if fetch_site:
        headers["Sec-Fetch-Site"] = fetch_site
    resp = authed.post(
        "/logout", data={"csrf_token": csrf}, headers=headers, follow_redirects=False
    )
    assert resp.status_code == 403


def test_openapi_requires_login(client: TestClient) -> None:
    assert client.get("/openapi.json").status_code == 401
    assert client.get("/docs", follow_redirects=False).status_code == 303


def test_openapi_available_when_logged_in(authed: TestClient) -> None:
    schema = authed.get("/openapi.json").json()
    assert schema["info"]["title"] == "ThreatLens"
    assert "/api/v1/me" in schema["paths"]
    assert "/login" not in schema["paths"]
