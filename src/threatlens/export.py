"""Safe exports.

CSV opened in a spreadsheet can execute formulas. Log data is attacker-controlled,
so any cell starting with ``= + - @`` (or a tab / carriage return that some
spreadsheets strip first) is prefixed with a single quote, which makes it text.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Sequence

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def neutralize(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_START):
        return "'" + text
    return text


def to_csv(header: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow([neutralize(h) for h in header])
    for row in rows:
        writer.writerow([neutralize(v) for v in row])
    return out.getvalue()
