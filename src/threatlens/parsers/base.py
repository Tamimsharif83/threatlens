"""Parser interface shared by every log format."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, tzinfo
from typing import Any

from threatlens.normalize.schema import Event


class ParseError(ValueError):
    """A line could not be parsed. The message becomes the malformed-line reason."""


@dataclass(frozen=True, slots=True)
class ParseContext:
    tz: tzinfo = UTC  # for timestamps without an offset
    reference_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    options: dict[str, Any] = field(default_factory=dict)


class Parser(ABC):
    #: Name used in the CLI/UI (``--type``) and stored on sources and batches.
    name: str = ""

    @abstractmethod
    def parse(self, line: str, ctx: ParseContext) -> Event:
        """Parse one line. Raise `ParseError` if the line is not in this format."""

    def sniff(self, lines: Sequence[str], ctx: ParseContext) -> float:
        """Fraction of sample lines this parser understands (for ``--type auto``)."""
        if not lines:
            return 0.0
        ok = 0
        for line in lines:
            try:
                self.parse(line, ctx)
                ok += 1
            except (ParseError, ValueError):
                pass
        return ok / len(lines)
