"""``threatlens`` command-line interface."""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

import click
from pydantic import ValidationError

from threatlens import __version__
from threatlens.cli.output import echo
from threatlens.config import Settings

HEALTHCHECK_TIMEOUT_S = 3


def _load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as exc:
        for err in exc.errors():
            field = ".".join(str(p) for p in err["loc"]) or "?"
            echo(f"configuration error: TL_{field.upper()}: {err['msg']}", err=True)
        sys.exit(2)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="threatlens")
def cli() -> None:
    """ThreatLens — self-hosted detection & investigation platform."""


@cli.command()
def serve() -> None:
    """Run the web server."""
    import uvicorn  # noqa: PLC0415 - keep other commands fast to start

    from threatlens.logging_setup import configure_logging, logging_config  # noqa: PLC0415
    from threatlens.web.app import create_app  # noqa: PLC0415

    settings = _load_settings()
    configure_logging(settings.log_level.value)
    settings.ensure_dirs()
    trusted_proxies = settings.forwarded_allow_ips.strip()
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_config=logging_config(settings.log_level.value),
        server_header=False,
        proxy_headers=bool(trusted_proxies),
        forwarded_allow_ips=trusted_proxies or None,
    )


@cli.command()
def healthcheck() -> None:
    """Exit 0 if the local server answers /healthz (used by Docker HEALTHCHECK)."""
    settings = _load_settings()
    url = f"http://127.0.0.1:{settings.port}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=HEALTHCHECK_TIMEOUT_S) as resp:
            sys.exit(0 if resp.status == 200 else 1)
    except (urllib.error.URLError, OSError):
        sys.exit(1)


@cli.group()
def user() -> None:
    """Manage user accounts."""


@user.command("reset-password")
@click.argument("username")
def reset_password(username: str) -> None:
    """Set a new random password for USERNAME and print it once.

    Use this if the admin password is lost:
    docker exec -it threatlens threatlens user reset-password admin
    """
    from threatlens import audit  # noqa: PLC0415
    from threatlens.auth.passwords import generate_password  # noqa: PLC0415
    from threatlens.auth.users import set_password  # noqa: PLC0415
    from threatlens.storage.db import connect, init_db, transaction  # noqa: PLC0415

    settings = _load_settings()
    settings.ensure_dirs()
    init_db(settings.db_path)
    conn = connect(settings.db_path)
    try:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            echo(f"no such user: {username}", err=True)
            sys.exit(1)
        password = generate_password()
        with transaction(conn):
            set_password(conn, row["id"], password)
            audit.record(conn, "user.password_reset_cli", target=username)
    finally:
        conn.close()
    echo(f"New password for {username}: {password}")
    echo("All existing sessions for this user were signed out.")


if __name__ == "__main__":  # pragma: no cover
    cli()
