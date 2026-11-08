"""Terminal-safe output.

Log data is attacker-controlled. Printing it raw lets an attacker inject
terminal escape sequences (move the cursor, rewrite earlier lines, change the
window title, or worse on some terminals). Everything the CLI prints that could
contain log data goes through `sanitize`.
"""

from __future__ import annotations

import re

import click

# CSI (ESC [ ... final), OSC (ESC ] ... BEL/ST), other 2-byte ESC sequences, and the
# 8-bit C1 forms of CSI/OSC/DCS/etc.
_ESCAPES = re.compile(
    r"""
    \x1b\[[0-?]*[ -/]*[@-~]            # CSI
  | \x1b\][^\x07\x1b]*(?:\x07|\x1b\\)? # OSC
  | \x1b[PX^_][^\x1b]*(?:\x1b\\)?      # DCS / SOS / PM / APC
  | \x1b[@-Z\\-_]                       # other Fe escapes
  | [\x80-\x9f]                         # C1 controls
    """,
    re.VERBOSE,
)
# Remaining C0 controls except tab and newline.
_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize(text: str) -> str:
    """Remove terminal escape sequences and control characters."""
    return _CONTROLS.sub("", _ESCAPES.sub("", text))


def echo(text: str, *, err: bool = False) -> None:
    click.echo(sanitize(text), err=err)
