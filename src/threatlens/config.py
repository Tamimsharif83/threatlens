"""Runtime configuration.

Every setting is read from an environment variable prefixed with ``TL_``
(for example ``TL_PORT=9000``). Defaults are chosen so that a plain
``docker run`` works without any configuration.
"""

from __future__ import annotations

from enum import StrEnum
from functools import cached_property
from pathlib import Path
from typing import Annotated
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_ADMIN_PASSWORD_LENGTH = 12


class CookieSecure(StrEnum):
    """Whether session cookies get the ``Secure`` flag."""

    AUTO = "auto"  # Secure when the request arrived over HTTPS
    ALWAYS = "always"
    NEVER = "never"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Settings(BaseSettings):
    """ThreatLens settings (environment variables with the ``TL_`` prefix)."""

    model_config = SettingsConfigDict(
        env_prefix="TL_",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    host: str = Field(default="127.0.0.1", description="Interface the web server binds to.")
    port: Annotated[int, Field(ge=1, le=65535)] = 8080
    data_dir: Path = Field(default=Path("./data"), description="All state lives here.")

    admin_username: Annotated[str, Field(min_length=1, max_length=64)] = "admin"
    admin_password: SecretStr | None = Field(
        default=None,
        description="First-run admin password. If unset, a random one is printed once to the log.",
    )

    retention_days: Annotated[int, Field(ge=1, le=3650)] = 30
    max_upload_mb: Annotated[int, Field(ge=1, le=10_240)] = 1024
    store_raw: bool = Field(default=False, description="Keep the raw log line (zstd-compressed).")
    delete_uploads: bool = Field(default=True, description="Delete uploaded files after ingest.")
    # Cap on data expanded from one .gz/.zip (zip-bomb protection).
    max_decompressed_mb: Annotated[int, Field(ge=1, le=102_400)] = 10_240
    watch_enabled: bool = Field(default=True, description="Ingest files placed in <data>/inbox.")
    watch_interval_seconds: Annotated[float, Field(ge=0.5, le=3600)] = 5.0
    rules_dir: Path | None = Field(
        default=None, description="Your Sigma rules (default <data>/rules)."
    )
    builtin_rules: bool = Field(default=True, description="Load the bundled example rules.")
    alert_throttle_minutes: Annotated[int, Field(ge=0, le=10_080)] = 60
    default_timezone: str = "UTC"
    log_level: LogLevel = LogLevel.INFO

    session_hours: Annotated[int, Field(ge=1, le=168)] = 12
    cookie_secure: CookieSecure = CookieSecure.AUTO
    forwarded_allow_ips: str = Field(
        default="",
        description="Comma-separated reverse-proxy IPs trusted for X-Forwarded-* headers.",
    )
    login_max_failures: Annotated[int, Field(ge=1, le=100)] = 5
    login_window_minutes: Annotated[int, Field(ge=1, le=1440)] = 15

    @field_validator("admin_password", mode="before")
    @classmethod
    def _empty_password_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and value == "":
            return None
        return value

    @field_validator("admin_password")
    @classmethod
    def _admin_password_strength(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < MIN_ADMIN_PASSWORD_LENGTH:
            raise ValueError(
                f"TL_ADMIN_PASSWORD must be at least {MIN_ADMIN_PASSWORD_LENGTH} characters"
            )
        return value

    @field_validator("default_timezone")
    @classmethod
    def _valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown timezone: {value!r}") from exc
        return value

    @cached_property
    def db_path(self) -> Path:
        return self.data_dir / "threatlens.db"

    @cached_property
    def rules_path(self) -> Path:
        return self.rules_dir or self.data_dir / "rules"

    @cached_property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"

    def ensure_dirs(self) -> None:
        """Create the data directory layout (owner-only permissions)."""
        for path in (self.data_dir, self.tmp_dir, self.data_dir / "uploads"):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
