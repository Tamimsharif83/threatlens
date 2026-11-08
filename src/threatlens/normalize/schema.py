"""The normalized event model.

Every parser turns a log line into an `Event`: a UTC timestamp, a flat mapping
of field names (ECS names where one exists, e.g. ``source.ip``, ``url.path``)
to values, and the Sigma log source the event belongs to. The log source picks
the event table (see ADR-0002): one table per Sigma log source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_TABLE_PART = re.compile(r"[^a-z0-9]+")
MAX_TABLE_NAME = 48


@dataclass(frozen=True, slots=True)
class LogSource:
    """A Sigma log source: ``category`` / ``product`` / ``service``."""

    category: str | None = None
    product: str | None = None
    service: str | None = None

    @property
    def table_name(self) -> str:
        parts = [p for p in (self.product, self.service, self.category) if p]
        cleaned = [_TABLE_PART.sub("_", p.lower()).strip("_") for p in parts]
        name = "ev_" + "_".join(c for c in cleaned if c)
        if name == "ev_":
            name = "ev_unknown"
        return name[:MAX_TABLE_NAME]

    def as_dict(self) -> dict[str, str]:
        return {
            k: v
            for k, v in (
                ("category", self.category),
                ("product", self.product),
                ("service", self.service),
            )
            if v
        }


# The log sources ThreatLens' built-in parsers produce.
WEBSERVER = LogSource(category="webserver")
LINUX_AUTH = LogSource(product="linux", service="auth")
ECS = LogSource(product="ecs")
GENERIC_JSON = LogSource(product="json")


@dataclass(slots=True)
class Event:
    ts: int  # unix milliseconds, UTC
    fields: dict[str, Any]
    logsource: LogSource
    raw: str = ""  # the original line (used for dedup and optional raw storage)
    record_no: int = 0  # line / record number within the file
    extra: dict[str, Any] = field(default_factory=dict)
