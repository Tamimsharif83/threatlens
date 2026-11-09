"""Ingest page: upload files, watch progress, browse batch history and reports."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from starlette.datastructures import FormData, UploadFile

from threatlens import audit, stats
from threatlens.config import Settings
from threatlens.ingest.jobs import IngestWorker
from threatlens.ingest.pipeline import IngestOptions
from threatlens.ingest.readers import (
    EVTX_MAGIC,
    GZIP_MAGIC,
    ZIP_MAGIC,
    UnsafeInputError,
    allowed_filename,
    check_text,
)
from threatlens.parsers import PARSER_TYPES, FieldMapping
from threatlens.parsers.web_access import PRESETS, compile_format
from threatlens.storage.db import transaction
from threatlens.web.deps import DbDep, SessionDep, SettingsDep, client_ip
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)
MAX_FILES_PER_UPLOAD = 20
COPY_CHUNK = 1024 * 1024
SOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/@-]{0,63}$")


def _worker(request: Request) -> IngestWorker:
    worker: IngestWorker = request.app.state.services.worker
    return worker


def mapping_dir(settings: Settings) -> Path:
    return settings.data_dir / "mappings"


def available_mappings(settings: Settings) -> dict[str, FieldMapping | str]:
    """Mapping files in <data>/mappings: name -> mapping, or an error message."""
    found: dict[str, FieldMapping | str] = {}
    directory = mapping_dir(settings)
    if not directory.is_dir():
        return found
    for path in sorted(directory.glob("*.y*ml")):
        try:
            found[path.stem] = FieldMapping.from_file(path)
        except (ValueError, OSError) as exc:
            found[path.stem] = str(exc)
    return found


def _live_context(request: Request, db: sqlite3.Connection) -> dict[str, Any]:
    jobs = _worker(request).recent()
    return {
        "jobs": jobs,
        "jobs_active": any(j.state in ("queued", "running") for j in jobs),
        "batches": stats.recent_batches(db, 30),
    }


@router.get("/ingest")
def ingest_page(
    request: Request, session: SessionDep, db: DbDep, settings: SettingsDep
) -> Response:
    return render(
        request,
        "ingest.html",
        {
            "active": "ingest",
            "parser_types": PARSER_TYPES,
            "web_presets": list(PRESETS),
            "mappings": available_mappings(settings),
            "max_upload_mb": settings.max_upload_mb,
            "max_files": MAX_FILES_PER_UPLOAD,
            "errors": [],
            "accepted": [],
            **_live_context(request, db),
        },
    )


@router.get("/ingest/live")
def ingest_live(request: Request, session: SessionDep, db: DbDep) -> Response:
    return render(request, "_ingest_live.html", _live_context(request, db))


def _field(form: FormData, name: str, max_len: int = 512) -> str:
    value = form.get(name)
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_len]


def _options_from_form(
    form: FormData, settings: Settings, actor: str
) -> tuple[IngestOptions, list[str]]:
    errors: list[str] = []
    parser_type = _field(form, "parser") or "auto"
    if parser_type not in PARSER_TYPES:
        errors.append("Unknown log type.")
        parser_type = "auto"
    source_name = _field(form, "source_name", 64) or None
    if source_name and not SOURCE_NAME_RE.match(source_name):
        errors.append("Source name: 1-64 letters, digits, spaces or . _ : / @ -")
    tz = _field(form, "timezone", 64) or None
    if tz:
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError):
            errors.append(f"Unknown timezone: {tz}")
            tz = None
    web_format = _field(form, "web_format", 1024) or None
    if web_format and web_format not in PRESETS:
        try:
            compile_format(web_format)
        except (ValueError, re.error) as exc:
            errors.append(f"Web log format: {exc}")
    mapping = None
    mapping_name = _field(form, "mapping", 128)
    if mapping_name:
        found = available_mappings(settings).get(mapping_name)
        if isinstance(found, FieldMapping):
            mapping = found
        else:
            errors.append(f"Mapping {mapping_name!r} is not available or invalid.")
    opts = IngestOptions(
        parser_type=parser_type,
        source_name=source_name,
        timezone=tz,
        web_format=web_format,
        mapping=mapping,
        store_raw=settings.store_raw,
        origin="upload",
        created_by=actor,
    )
    return opts, errors


async def _save_upload(upload: UploadFile, dest: Path) -> int:
    size = 0
    with dest.open("xb") as out:
        dest.chmod(0o600)
        while chunk := await upload.read(COPY_CHUNK):
            size += len(chunk)
            out.write(chunk)
    return size


def _check_magic(path: Path, name: str) -> None:
    with path.open("rb") as fh:
        head = fh.read(8192)
    if not head:
        raise UnsafeInputError(f"{name}: empty file")
    lower = name.lower()
    if head.startswith(GZIP_MAGIC):
        if not lower.endswith(".gz"):
            raise UnsafeInputError(f"{name}: gzip data but the name does not end in .gz")
        return
    if head.startswith(ZIP_MAGIC):
        if not lower.endswith(".zip"):
            raise UnsafeInputError(f"{name}: zip data but the name does not end in .zip")
        return
    if head.startswith(EVTX_MAGIC):
        if not lower.endswith(".evtx"):
            raise UnsafeInputError(f"{name}: EVTX data but the name does not end in .evtx")
        return
    if lower.endswith(".evtx"):
        raise UnsafeInputError(f"{name}: not an EVTX file (no ElfFile header)")
    if lower.endswith((".gz", ".zip")):
        raise UnsafeInputError(f"{name}: not a valid {lower.rsplit('.', 1)[-1]} file")
    check_text(head, name)


@router.post("/ingest/upload")
async def upload(
    request: Request, session: SessionDep, db: DbDep, settings: SettingsDep
) -> Response:
    form = await request.form(max_files=MAX_FILES_PER_UPLOAD, max_fields=20)
    opts, errors = _options_from_form(form, settings, session.user.username)
    files = [f for f in form.getlist("files") if isinstance(f, UploadFile) and f.filename]
    if not files:
        errors.append("Choose at least one file.")
    accepted: list[str] = []
    worker = _worker(request)
    if not errors:
        for upload_file in files:
            name = Path((upload_file.filename or "upload").replace("\\", "/")).name[:200]
            if not allowed_filename(name):
                errors.append(
                    f"{name}: file type not accepted (.log, .txt, .json, .evtx, .gz, .zip ...)"
                )
                continue
            dest = worker.new_upload_path()
            try:
                size = await _save_upload(upload_file, dest)
            except OSError as exc:  # ENOSPC: the data volume is full
                dest.unlink(missing_ok=True)
                errors.append(f"{name}: could not be saved ({exc.strerror or exc})")
                continue
            try:
                _check_magic(dest, name)
            except UnsafeInputError as exc:
                dest.unlink(missing_ok=True)
                errors.append(str(exc))
                continue
            worker.submit(dest, name, opts)
            accepted.append(name)
            with transaction(db):
                audit.record(
                    db,
                    "ingest.upload",
                    actor=session.user.username,
                    target=name,
                    details={"bytes": size, "parser": opts.parser_type, "source": opts.source_name},
                    ip=client_ip(request),
                )
    if not request.headers.get("hx-request"):
        if errors:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, " ".join(errors))
        return RedirectResponse("/ingest", status.HTTP_303_SEE_OTHER)
    return render(
        request,
        "_upload_result.html",
        {"errors": errors, "accepted": accepted, **_live_context(request, db)},
        status_code=status.HTTP_400_BAD_REQUEST if errors and not accepted else 200,
    )


@router.get("/ingest/batches/{batch_id}")
def batch_report(request: Request, batch_id: int, session: SessionDep, db: DbDep) -> Response:
    row = db.execute(
        "SELECT b.*, s.name AS source FROM ingest_batches b JOIN sources s ON s.id = b.source_id "
        "WHERE b.id = ?",
        (batch_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "batch not found")
    tables = db.execute(
        "SELECT table_name, events, min_id, max_id FROM ingest_batch_tables WHERE batch_id = ? "
        "ORDER BY table_name",
        (batch_id,),
    ).fetchall()
    return render(
        request,
        "batch.html",
        {
            "active": "ingest",
            "b": row,
            "tables": tables,
            "samples": json.loads(row["malformed_samples"] or "[]"),
        },
    )
