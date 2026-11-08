"""``threatlens`` command-line interface."""

from __future__ import annotations

import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path

import click
from pydantic import ValidationError

from threatlens import __version__
from threatlens.cli.output import echo
from threatlens.config import Settings
from threatlens.parsers import PARSER_TYPES

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


# ---------------------------------------------------------------- ingest


@cli.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option(
    "--type",
    "parser_type",
    type=click.Choice(PARSER_TYPES),
    default="auto",
    show_default=True,
    help="Log format.",
)
@click.option("--tz", "timezone", help="Timezone for timestamps without one (e.g. Asia/Dhaka).")
@click.option("--source-name", help="Source name (default: derived from the file name).")
@click.option("--format", "web_format", help="Web log format: preset or Apache/Nginx string.")
@click.option(
    "--mapping",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Field-mapping YAML for --type json.",
)
@click.option("--recursive/--no-recursive", default=True, show_default=True)
def ingest(  # noqa: PLR0912 - CLI option handling
    paths: tuple[Path, ...],
    parser_type: str,
    timezone: str | None,
    source_name: str | None,
    web_format: str | None,
    mapping: Path | None,
    recursive: bool,
) -> None:
    """Ingest log files, archives (.gz, .zip) or directories."""
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415

    from threatlens import runtime_settings  # noqa: PLC0415
    from threatlens.ingest.files import ingest_path  # noqa: PLC0415
    from threatlens.ingest.pipeline import IngestOptions  # noqa: PLC0415
    from threatlens.ingest.readers import allowed_filename  # noqa: PLC0415
    from threatlens.parsers import FieldMapping  # noqa: PLC0415
    from threatlens.storage.db import connect, init_db  # noqa: PLC0415

    settings = _load_settings()
    if timezone:
        try:
            ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError):
            echo(f"unknown timezone: {timezone}", err=True)
            sys.exit(2)
    field_mapping = None
    if mapping:
        try:
            field_mapping = FieldMapping.from_file(mapping)
        except ValueError as exc:
            echo(f"invalid mapping {mapping}: {exc}", err=True)
            sys.exit(2)
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            pattern = "**/*" if recursive else "*"
            files.extend(
                f for f in sorted(p.glob(pattern)) if f.is_file() and allowed_filename(f.name)
            )
        else:
            files.append(p)
    if not files:
        echo("no log files found", err=True)
        sys.exit(1)

    settings.ensure_dirs()
    init_db(settings.db_path)
    conn = connect(settings.db_path)
    failed = 0
    try:
        default_tz = runtime_settings.default_timezone(conn, settings)
        opts = IngestOptions(
            parser_type=parser_type,
            source_name=source_name,
            timezone=timezone,
            web_format=web_format,
            mapping=field_mapping,
            store_raw=settings.store_raw,
            origin="cli",
            created_by="cli",
        )
        for f in files:
            for rep in ingest_path(
                conn,
                f,
                opts,
                default_timezone=default_tz,
                max_bytes=settings.max_decompressed_mb * 1024 * 1024,
            ):
                status = "OK  " if rep.status == "done" else "FAIL"
                echo(
                    f"{status} batch #{rep.batch_id} {rep.file_name} [{rep.parser}] "
                    f"source={rep.source}: {rep.inserted} events, {rep.duplicates} duplicates, "
                    f"{rep.malformed} malformed of {rep.lines} lines"
                )
                if rep.error:
                    echo(f"     error: {rep.error}")
                for sample in rep.samples[:3]:
                    echo(
                        f"     line {sample['record']}: {sample['reason']}: {sample['line'][:120]}"
                    )
                failed += rep.status != "done"
    finally:
        conn.close()
    sys.exit(1 if failed else 0)


# ---------------------------------------------------------------- database


@cli.group()
def db() -> None:
    """Database maintenance."""


def _open_db() -> tuple[Settings, sqlite3.Connection]:
    from threatlens.storage.db import connect, init_db  # noqa: PLC0415

    settings = _load_settings()
    settings.ensure_dirs()
    init_db(settings.db_path)
    return settings, connect(settings.db_path)


@db.command("stats")
def db_stats() -> None:
    """Show storage usage per source and per event table."""
    from threatlens.storage.maintenance import storage_stats  # noqa: PLC0415

    settings, conn = _open_db()
    try:
        st = storage_stats(conn, settings.db_path)
    finally:
        conn.close()
    echo(f"database {_mb(st.db_bytes)}, WAL {_mb(st.wal_bytes)}, free {_mb(st.free_bytes)}")
    echo(f"{st.total_events} events")
    for t in st.tables:
        echo(f"  table  {t.table:<28} {t.events:>12} events  {_mb(t.bytes):>10}")
    for s in st.sources:
        echo(f"  source {s.name:<28} {s.events:>12} events ~{_mb(s.approx_bytes):>9}  [{s.parser}]")


@db.command("purge")
def db_purge() -> None:
    """Delete events older than the retention period now."""
    from threatlens import runtime_settings  # noqa: PLC0415
    from threatlens.storage.maintenance import purge  # noqa: PLC0415

    settings, conn = _open_db()
    try:
        days = runtime_settings.retention_days(conn, settings)
        result = purge(conn, days)
    finally:
        conn.close()
    echo(
        f"retention {days} days: deleted {result.total} events and "
        f"{result.batches_deleted} batch records; freed {result.pages_freed} pages"
    )


@db.command("compact")
@click.option(
    "--full", is_flag=True, help="Rewrite the whole file (VACUUM). Needs free disk space."
)
def db_compact(full: bool) -> None:
    """Reclaim free space in the database file."""
    from threatlens.storage.maintenance import compact  # noqa: PLC0415

    settings, conn = _open_db()
    before = settings.db_path.stat().st_size
    try:
        compact(conn, full=full)
    finally:
        conn.close()
    after = settings.db_path.stat().st_size
    echo(f"database {_mb(before)} -> {_mb(after)}")


def _mb(n: int | float) -> str:
    return f"{n / (1024 * 1024):.1f} MB"


# ---------------------------------------------------------------- synthetic data


@cli.command()
@click.option("--kind", type=click.Choice(["web", "auth", "ecs"]), default="web", show_default=True)
@click.option(
    "--lines", "count", type=click.IntRange(1, 50_000_000), default=1000, show_default=True
)
@click.option("--seed", type=int, default=1, show_default=True)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="File (default: stdout).",
)
def synth(kind: str, count: int, seed: int, output: Path | None) -> None:
    """Generate synthetic, seeded log lines (for demos and tests)."""
    from threatlens.synth import GENERATORS  # noqa: PLC0415

    lines = GENERATORS[kind](count, seed)
    if output is None:
        for line in lines:
            click.echo(line)
        return
    with output.open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(line + "\n")
    echo(f"wrote {count} {kind} lines to {output}")


if __name__ == "__main__":  # pragma: no cover
    cli()
