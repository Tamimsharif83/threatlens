from __future__ import annotations

import pytest
from pydantic import ValidationError

from threatlens.config import CookieSecure, Settings


def test_defaults() -> None:
    s = Settings()
    assert s.port == 8080
    assert s.retention_days == 30
    assert s.store_raw is False
    assert s.delete_uploads is True
    assert s.default_timezone == "UTC"
    assert s.cookie_secure is CookieSecure.AUTO
    assert s.admin_password is None


def test_env_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_PORT", "9001")
    monkeypatch.setenv("TL_RETENTION_DAYS", "7")
    monkeypatch.setenv("TL_DEFAULT_TIMEZONE", "Asia/Dhaka")
    s = Settings()
    assert (s.port, s.retention_days, s.default_timezone) == (9001, 7, "Asia/Dhaka")


def test_empty_admin_password_means_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_ADMIN_PASSWORD", "")
    assert Settings().admin_password is None


def test_short_admin_password_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_ADMIN_PASSWORD", "short")
    with pytest.raises(ValidationError, match="at least 12"):
        Settings()


def test_admin_password_is_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_ADMIN_PASSWORD", "a-very-long-password")
    assert "a-very-long-password" not in repr(Settings())


@pytest.mark.parametrize("tz", ["Mars/Olympus", "../../etc/passwd"])
def test_bad_timezone_rejected(monkeypatch: pytest.MonkeyPatch, tz: str) -> None:
    monkeypatch.setenv("TL_DEFAULT_TIMEZONE", tz)
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize(("var", "value"), [("TL_PORT", "0"), ("TL_RETENTION_DAYS", "0")])
def test_out_of_range(monkeypatch: pytest.MonkeyPatch, var: str, value: str) -> None:
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError):
        Settings()


def test_paths(tmp_path) -> None:  # type: ignore[no-untyped-def]
    s = Settings(data_dir=tmp_path / "d")
    s.ensure_dirs()
    assert s.db_path == tmp_path / "d" / "threatlens.db"
    assert s.tmp_dir.is_dir()
    assert (s.data_dir.stat().st_mode & 0o777) == 0o700
