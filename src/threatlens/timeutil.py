"""Time helpers. ThreatLens stores every timestamp as UTC unix milliseconds."""

from __future__ import annotations

import time
from datetime import UTC, datetime


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def ms_to_iso(ms: int) -> str:
    """Render unix ms as an ISO-8601 UTC string, e.g. ``2026-01-01T00:00:00.000Z``."""
    return (
        datetime.fromtimestamp(ms / 1000, tz=UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
