"""Time helpers. ThreatLens stores every timestamp as UTC unix milliseconds."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta, tzinfo

MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


class TimestampError(ValueError):
    """A timestamp could not be parsed."""


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def ms_to_iso(ms: int) -> str:
    """Render unix ms as an ISO-8601 UTC string, e.g. ``2026-01-01T00:00:00.000Z``."""
    return (
        datetime.fromtimestamp(ms / 1000, tz=UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def dt_to_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def parse_offset(text: str) -> timedelta:
    m = _OFFSET.match(text)
    if not m:
        raise TimestampError(f"bad UTC offset: {text!r}")
    sign = -1 if m.group(1) == "-" else 1
    return sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))


def parse_iso8601(text: str, default_tz: tzinfo = UTC) -> int:
    """ISO-8601 (``2026-01-02T03:04:05.123Z``, ``...+05:30``, space separator) to ms.

    Timestamps without an offset are interpreted in ``default_tz``.
    """
    value = text.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    # Python accepts at most microseconds; trim nanosecond precision.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TimestampError(f"not an ISO-8601 timestamp: {text[:64]!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt_to_ms(dt)


def parse_epoch(value: float | str) -> int:
    """Unix epoch in s, ms, µs or ns (guessed from magnitude) to ms."""
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise TimestampError(f"not an epoch timestamp: {value!r}") from exc
    magnitude = abs(number)
    if magnitude >= 1e17:
        return int(number / 1e6)
    if magnitude >= 1e14:
        return int(number / 1e3)
    if magnitude >= 1e11:
        return int(number)
    return int(number * 1000)


def parse_apache_time(text: str) -> int:
    """``10/Oct/2000:13:55:36 -0700`` (Apache/Nginx ``%t`` / ``$time_local``) to ms."""
    try:
        day = int(text[0:2])
        month = MONTHS[text[3:6]]
        year = int(text[7:11])
        hour, minute, second = int(text[12:14]), int(text[15:17]), int(text[18:20])
        rest = text[20:]
        frac = 0
        if rest.startswith("."):  # optional fractional seconds
            digits = re.match(r"\.(\d+)", rest)
            assert digits is not None  # noqa: S101 - startswith(".") guarantees a match
            frac = int(digits.group(1)[:3].ljust(3, "0"))
            rest = rest[digits.end() :]
        offset = parse_offset(rest.strip())
    except (ValueError, KeyError, IndexError, AssertionError) as exc:
        raise TimestampError(f"bad web log time: {text[:40]!r}") from exc
    dt = datetime(year, month, day, hour, minute, second, tzinfo=UTC) - offset
    return dt_to_ms(dt) + frac


def parse_syslog_time(month: str, day: str, clock: str, tz: tzinfo, reference: datetime) -> int:
    """RFC 3164 ``Nov  8 10:00:00`` (no year) to ms.

    The year is taken from ``reference`` (the file's modification time, or now),
    and moved back one year if that would put the event more than two days in
    the future — which handles a December log read in January.
    """
    try:
        hour, minute, second = (int(p) for p in clock.split(":"))
        candidate = datetime(
            reference.year, MONTHS[month], int(day), hour, minute, second, tzinfo=tz
        )
    except (ValueError, KeyError) as exc:
        raise TimestampError(f"bad syslog time: {month} {day} {clock}") from exc
    if candidate - reference > timedelta(days=2):
        candidate = candidate.replace(year=reference.year - 1)
    return dt_to_ms(candidate)
