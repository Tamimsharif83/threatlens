"""Vendored third-party files must match the hashes recorded in VENDORED.md."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

VENDOR = Path(__file__).resolve().parents[1] / "src/threatlens/web/static/vendor"
ROW = re.compile(r"`([\w/.-]+)` \| `([0-9a-f]{64})`")


def test_vendored_hashes_match() -> None:
    rows = ROW.findall((VENDOR / "VENDORED.md").read_text())
    assert len(rows) >= 3
    for rel, expected in rows:
        actual = hashlib.sha256((VENDOR / rel).read_bytes()).hexdigest()
        assert actual == expected, rel
