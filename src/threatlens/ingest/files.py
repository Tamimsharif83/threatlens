"""Ingest a file (plain, .gz or .zip) as one batch per log stream."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from threatlens.ingest.pipeline import (
    BatchReport,
    BatchWriter,
    IngestOptions,
    get_or_create_source,
    ingest_stream,
)
from threatlens.ingest.readers import READ_ERRORS, iter_lines, open_members
from threatlens.storage.db import transaction


def ingest_path(
    conn: sqlite3.Connection,
    path: Path,
    opts: IngestOptions,
    *,
    default_timezone: str,
    max_bytes: int,
    display_name: str | None = None,
    progress: Callable[[BatchReport], None] | None = None,
) -> list[BatchReport]:
    """Ingest ``path``. Unsafe or unreadable input yields a failed batch, not an exception."""
    name = display_name or path.name
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    opts = replace(opts, reference_time=opts.reference_time or mtime)
    reports: list[BatchReport] = []
    try:
        for member in open_members(path, name, max_bytes):
            member_opts = replace(
                opts,
                source_name=opts.source_name or source_name_for(member.name),
                parser_type=member.parser or opts.parser_type,  # EVTX is always "evtx"
            )
            rep = ingest_stream(
                conn,
                iter_lines(member.stream),
                member.name,
                member_opts,
                default_timezone,
                progress=progress,
            )
            reports.append(rep)
    except READ_ERRORS as exc:
        reports.append(failed_batch(conn, name, opts, str(exc)))
    return reports


def source_name_for(member_name: str) -> str:
    """Default source name: the file name without archive prefix and rotation suffix."""
    base = member_name.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
    parts = base.split(".")
    while len(parts) > 1 and (parts[-1].isdigit() or parts[-1] in ("gz", "zip", "evtx")):
        parts.pop()
    return ".".join(parts) or base


def failed_batch(
    conn: sqlite3.Connection, file_name: str, opts: IngestOptions, error: str
) -> BatchReport:
    source = opts.source_name or source_name_for(file_name)
    with transaction(conn):
        source_id, _ = get_or_create_source(conn, source, opts.parser_type)
    writer = BatchWriter(conn, source_id, source, file_name, opts.parser_type, opts)
    return writer.finish("failed", error)
