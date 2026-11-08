"""Value helpers: flattening nested JSON and converting values for SQLite."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Any

MAX_DEPTH = 12
MAX_KEYS = 1000
INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1


def flatten(obj: Mapping[str, Any], prefix: str = "", depth: int = 0) -> dict[str, Any]:
    """Flatten nested objects to dotted keys: ``{"a": {"b": 1}} -> {"a.b": 1}``.

    Lists are kept as values. Depth and key counts are capped so a hostile
    JSON document cannot explode memory or the column catalog.
    """
    out: dict[str, Any] = {}
    for key, value in obj.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping) and value and depth < MAX_DEPTH:
            out.update(flatten(value, name, depth + 1))
        else:
            out[name] = value
        if len(out) >= MAX_KEYS:
            break
    return out


def sql_value(value: object) -> object:
    """Convert a Python value to something SQLite stores sensibly.

    Booleans become ``'true'``/``'false'`` (what Sigma rules compare against),
    lists/dicts become JSON text, out-of-range numbers become text.
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return value if INT64_MIN <= value <= INT64_MAX else str(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, list | tuple | dict):
        if (
            isinstance(value, list | tuple)
            and len(value) == 1
            and not isinstance(value[0], list | dict)
        ):
            return sql_value(value[0])  # ["web"] -> "web": single-valued ECS arrays
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)
    return str(value)


def sql_type_for(value: object) -> str:
    """Column affinity for the first value seen of a field."""
    if isinstance(value, bool):
        return "TEXT"
    if isinstance(value, int):
        return "INTEGER"
    if isinstance(value, float):
        return "REAL"
    return "TEXT"
