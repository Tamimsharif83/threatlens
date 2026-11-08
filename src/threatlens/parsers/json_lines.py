"""JSON Lines: ECS-formatted application events, and generic JSON with a field mapping.

ECS JSON Lines
    One JSON object per line using Elastic Common Schema names, nested
    (``{"http": {"request": {"method": "GET"}}}``) or dotted
    (``{"http.request.method": "GET"}``). ``@timestamp`` is required. Events go to
    the ``ecs`` log source; Sigma rules select them with
    ``logsource: {product: ecs, category: <event.category>}``.

Generic JSON Lines
    Any JSON objects. A mapping file (YAML) says where the timestamp is, how to
    rename fields to ECS, and which Sigma log source the events belong to.
    Without a mapping, keys are kept as they are and the timestamp is taken
    from the first of ``@timestamp``, ``timestamp``, ``time``, ``ts``, ``date``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from threatlens.normalize.schema import ECS, GENERIC_JSON, Event, LogSource
from threatlens.normalize.values import flatten
from threatlens.parsers.base import ParseContext, ParseError, Parser
from threatlens.timeutil import TimestampError, dt_to_ms, parse_epoch, parse_iso8601

AUTO_TS_KEYS = ("@timestamp", "timestamp", "time", "ts", "date", "datetime", "eventTime")
MAX_LINE_FIELDS = 1000


def _load_object(line: str) -> dict[str, Any]:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ParseError("JSON value is not an object")
    return obj


def parse_timestamp(value: object, fmt: str, tz: tzinfo) -> int:
    """Parse a timestamp value using ``fmt``: ``auto``, ``iso8601``, ``epoch``,
    ``epoch_s``, ``epoch_ms``, ``epoch_us``, ``epoch_ns`` or a strptime pattern."""
    try:
        if fmt == "auto":
            if isinstance(value, int | float) and not isinstance(value, bool):
                return parse_epoch(value)
            text = str(value)
            if text.replace(".", "", 1).isdigit():
                return parse_epoch(text)
            return parse_iso8601(text, tz)
        if fmt == "iso8601":
            return parse_iso8601(str(value), tz)
        if fmt == "epoch":
            return parse_epoch(str(value))
        scale = {"epoch_s": 1000.0, "epoch_ms": 1.0, "epoch_us": 1e-3, "epoch_ns": 1e-6}
        if fmt in scale:
            return int(float(str(value)) * scale[fmt])
        dt = datetime.strptime(str(value), fmt)  # noqa: DTZ007 - tz applied below
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
        return dt_to_ms(dt)
    except (TimestampError, ValueError, TypeError, OverflowError) as exc:
        raise ParseError(f"bad timestamp {str(value)[:64]!r}: {exc}") from exc


class EcsJsonParser(Parser):
    name = "ecs-json"

    def parse(self, line: str, ctx: ParseContext) -> Event:
        fields = flatten(_load_object(line))
        raw_ts = fields.pop("@timestamp", None)
        if raw_ts is None:
            raise ParseError("ECS event has no @timestamp")
        ts = parse_timestamp(raw_ts, "auto", ctx.tz)
        fields.setdefault("event.dataset", "ecs")
        return Event(ts=ts, fields=fields, logsource=ECS, raw=line)

    def sniff(self, lines: Sequence[str], ctx: ParseContext) -> float:
        # Prefer ECS over generic JSON only when lines look like ECS.
        score = super().sniff(lines, ctx)
        if not score:
            return 0.0
        ecs_like = 0
        for line in lines:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            keys = set(obj) if isinstance(obj, dict) else set()
            tops = {k.split(".", 1)[0] for k in keys}
            if "@timestamp" in keys and tops & {"event", "http", "url", "source", "user", "ecs"}:
                ecs_like += 1
        return score * (ecs_like / len(lines)) if lines else 0.0


@dataclass(frozen=True, slots=True)
class FieldMapping:
    """A generic-JSON mapping file (YAML). See docs/log-formats.md."""

    name: str
    logsource: LogSource = GENERIC_JSON
    timestamp_field: str | None = None
    timestamp_format: str = "auto"
    timezone: str | None = None
    fields: dict[str, str] = field(default_factory=dict)
    keep_unmapped: bool = True
    constants: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, text: str, default_name: str = "mapping") -> FieldMapping:
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"mapping is not valid YAML: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("mapping must be a YAML mapping")
        unknown = set(doc) - {
            "name",
            "logsource",
            "timestamp",
            "fields",
            "keep_unmapped",
            "constants",
        }
        if unknown:
            raise ValueError(f"unknown mapping keys: {sorted(unknown)}")
        ls = doc.get("logsource") or {}
        if not isinstance(ls, dict) or not set(ls) <= {"category", "product", "service"}:
            raise ValueError("logsource must have only category / product / service")
        if not ls:
            ls = {"product": "json"}
        ts = doc.get("timestamp") or {}
        if isinstance(ts, str):
            ts = {"field": ts}
        if not isinstance(ts, dict):
            raise ValueError("timestamp must be a field name or {field, format, timezone}")
        tz = ts.get("timezone")
        if tz is not None:
            try:
                ZoneInfo(str(tz))
            except (ZoneInfoNotFoundError, ValueError) as exc:
                raise ValueError(f"unknown timezone in mapping: {tz}") from exc
        fields = doc.get("fields") or {}
        if not isinstance(fields, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in fields.items()
        ):
            raise ValueError("fields must map source keys (strings) to field names (strings)")
        constants = doc.get("constants") or {}
        if not isinstance(constants, dict):
            raise ValueError("constants must be a mapping of field name to value")
        return cls(
            name=str(doc.get("name") or default_name),
            logsource=LogSource(**{k: str(v) for k, v in ls.items()}),
            timestamp_field=str(ts["field"]) if ts.get("field") else None,
            timestamp_format=str(ts.get("format") or "auto"),
            timezone=str(tz) if tz else None,
            fields=dict(fields),
            keep_unmapped=bool(doc.get("keep_unmapped", True)),
            constants=dict(constants),
        )

    @classmethod
    def from_file(cls, path: Path) -> FieldMapping:
        return cls.from_yaml(path.read_text(encoding="utf-8"), default_name=path.stem)


class GenericJsonParser(Parser):
    name = "json"

    def __init__(self, mapping: FieldMapping | None = None) -> None:
        self.mapping = mapping or FieldMapping(name="json")
        self._tz = ZoneInfo(self.mapping.timezone) if self.mapping.timezone else None

    def parse(self, line: str, ctx: ParseContext) -> Event:
        m = self.mapping
        flat = flatten(_load_object(line))
        tz = self._tz or ctx.tz
        if m.timestamp_field:
            if m.timestamp_field not in flat:
                raise ParseError(f"timestamp field {m.timestamp_field!r} missing")
            ts = parse_timestamp(flat.pop(m.timestamp_field), m.timestamp_format, tz)
        else:
            key = next((k for k in AUTO_TS_KEYS if k in flat), None)
            if key is None:
                raise ParseError("no timestamp field found (set one in a mapping file)")
            ts = parse_timestamp(flat.pop(key), m.timestamp_format, tz)
        fields: dict[str, Any] = {}
        for key, value in flat.items():
            target = m.fields.get(key)
            if target:
                fields[target] = value
            elif m.keep_unmapped:
                fields.setdefault(key, value)
        fields.update(m.constants)
        fields.setdefault("event.dataset", m.name)
        return Event(ts=ts, fields=fields, logsource=m.logsource, raw=line)
