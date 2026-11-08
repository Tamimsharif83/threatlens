from __future__ import annotations

import json
import logging
from contextlib import closing
from pathlib import Path

import pytest
from click.testing import CliRunner

from threatlens import __version__
from threatlens.auth.users import authenticate, bootstrap_admin, count_users
from threatlens.cli.main import cli
from threatlens.cli.output import sanitize
from threatlens.config import Settings
from threatlens.logging_setup import JsonFormatter
from threatlens.storage.db import connect, transaction
from threatlens.web.app import prepare_storage


def _check(settings: Settings, username: str, password: str) -> bool:
    with closing(connect(settings.db_path)) as conn:
        return authenticate(conn, username, password) is not None


def _users(settings: Settings) -> int:
    with closing(connect(settings.db_path)) as conn:
        return count_users(conn)


def test_bootstrap_uses_env_password(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path, admin_password="from-the-environment")  # type: ignore[arg-type]
    prepare_storage(s)
    assert _users(s) == 1
    assert _check(s, "admin", "from-the-environment")


def test_bootstrap_generates_and_prints_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    s = Settings(data_dir=tmp_path)
    prepare_storage(s)
    err = capsys.readouterr().err
    assert "password: " in err
    password = err.split("password: ", 1)[1].split()[0]
    assert _check(s, "admin", password)
    prepare_storage(s)  # second start: no new admin, nothing printed
    assert "password" not in capsys.readouterr().err
    assert _users(s) == 1


def test_bootstrap_noop_when_users_exist(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path, admin_password="first-password-x")  # type: ignore[arg-type]
    prepare_storage(s)
    s2 = Settings(data_dir=tmp_path, admin_password="second-password")  # type: ignore[arg-type]
    with closing(connect(s2.db_path)) as conn, transaction(conn):
        bootstrap_admin(conn, s2)
    assert not _check(s2, "admin", "second-password")


def test_cli_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_reset_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TL_ADMIN_PASSWORD", "original-password")
    prepare_storage(Settings())
    result = CliRunner().invoke(cli, ["user", "reset-password", "admin"])
    assert result.exit_code == 0, result.output
    new = result.output.split("New password for admin: ", 1)[1].split()[0]
    s = Settings()
    assert _check(s, "admin", new)
    assert not _check(s, "admin", "original-password")


def test_cli_reset_password_unknown_user(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_DATA_DIR", str(tmp_path))
    result = CliRunner().invoke(cli, ["user", "reset-password", "ghost"])
    assert result.exit_code == 1


def test_cli_config_error_is_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_PORT", "not-a-port")
    result = CliRunner().invoke(cli, ["healthcheck"])
    assert result.exit_code == 2
    assert "TL_PORT" in result.output


def test_cli_healthcheck_fails_without_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_PORT", "1")  # nothing listens there
    assert CliRunner().invoke(cli, ["healthcheck"]).exit_code == 1


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("plain text", "plain text"),
        ("\x1b[31mred\x1b[0m", "red"),
        ("title\x1b]0;pwned\x07!", "title!"),
        ("osc st\x1b]8;;http://x\x1b\\link", "osc stlink"),
        ("bell\x07 and nul\x00", "bell and nul"),
        ("c1\x9b31mcsi", "c131mcsi"),
        ("keep\ttabs\nand newlines", "keep\ttabs\nand newlines"),
        ("cursor\x1b[2Jclear\x1b[H", "cursorclear"),
    ],
)
def test_sanitize_terminal_output(raw: str, clean: str) -> None:
    assert sanitize(raw) == clean


def test_json_log_formatter() -> None:
    record = logging.LogRecord("tl.test", logging.INFO, __file__, 1, "hello %s", ("x",), None)
    record.client_ip = "10.0.0.1"
    out = json.loads(JsonFormatter().format(record))
    assert out["msg"] == "hello x"
    assert out["level"] == "INFO"
    assert out["client_ip"] == "10.0.0.1"
    assert out["ts"].endswith("+00:00")


def test_healthz(client) -> None:  # type: ignore[no-untyped-def]
    resp = client.get("/healthz")
    assert resp.json() == {"status": "ok", "version": __version__}
