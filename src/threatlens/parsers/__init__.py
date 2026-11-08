"""Log parsers and format auto-detection."""

from __future__ import annotations

from collections.abc import Sequence

from threatlens.parsers.base import ParseContext, ParseError, Parser
from threatlens.parsers.json_lines import EcsJsonParser, FieldMapping, GenericJsonParser
from threatlens.parsers.linux_auth import LinuxAuthParser
from threatlens.parsers.web_access import WebAccessParser

PARSER_TYPES = ("auto", "apache", "nginx", "ecs-json", "linux-auth", "json")
SNIFF_THRESHOLD = 0.6

__all__ = [
    "PARSER_TYPES",
    "FieldMapping",
    "ParseContext",
    "ParseError",
    "Parser",
    "UnknownFormatError",
    "detect_parser",
    "make_parser",
]


class UnknownFormatError(ValueError):
    """No parser understands the sample lines."""


def make_parser(
    kind: str, *, web_format: str | None = None, mapping: FieldMapping | None = None
) -> Parser:
    if kind in ("apache", "nginx"):
        return WebAccessParser(kind, fmt=web_format)
    if kind == "ecs-json":
        return EcsJsonParser()
    if kind == "linux-auth":
        return LinuxAuthParser()
    if kind == "json":
        return GenericJsonParser(mapping)
    raise ValueError(f"unknown parser type {kind!r}; choose from {', '.join(PARSER_TYPES)}")


def detect_parser(
    sample: Sequence[str],
    ctx: ParseContext,
    *,
    web_format: str | None = None,
    mapping: FieldMapping | None = None,
) -> Parser:
    """Pick the parser that understands most of the sample lines (``--type auto``)."""
    lines = [s for s in sample if s.strip()]
    if not lines:
        raise UnknownFormatError("no lines to detect the format from")
    if mapping is not None:
        return GenericJsonParser(mapping)
    candidates: list[Parser] = [
        EcsJsonParser(),
        WebAccessParser("apache", fmt=web_format),
        LinuxAuthParser(),
        GenericJsonParser(),
    ]
    best, best_score = None, 0.0
    for parser in candidates:
        score = parser.sniff(lines, ctx)
        if score > best_score + 1e-9:
            best, best_score = parser, score
    if best is None or best_score < SNIFF_THRESHOLD:
        raise UnknownFormatError(
            "could not recognise the log format; choose a type explicitly "
            f"(best match: {best.name if best else 'none'}, {best_score:.0%} of sample lines)"
        )
    if isinstance(best, WebAccessParser):
        best.dataset = "web.access"  # apache vs nginx is not distinguishable from the line
    return best
