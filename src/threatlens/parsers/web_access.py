"""Apache / Nginx access logs: combined, common, or a custom format string.

Values are stored exactly as the server logged them (no URL decoding), because
Sigma webserver rules are written against logged values. Field names follow ECS;
the Sigma webserver names (``cs-uri-stem`` ...) are mapped onto them when rules
are compiled.

Custom formats accept Apache ``LogFormat`` directives (``%h %l %u %t "%r" %>s %b``)
or Nginx ``log_format`` variables (``$remote_addr - $remote_user [$time_local] ...``).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from threatlens.normalize.schema import WEBSERVER, Event
from threatlens.parsers.base import ParseContext, ParseError, Parser
from threatlens.timeutil import TimestampError, parse_apache_time, parse_epoch, parse_iso8601

COMBINED = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'
COMMON = '%h %l %u %t "%r" %>s %b'
VHOST_COMBINED = '%v:%p %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'
PRESETS = {"combined": COMBINED, "common": COMMON, "vhost_combined": VHOST_COMBINED}

_QUOTED = r'(?:[^"\\]|\\.)*'
_NONSPACE = r"\S+"
_BRACKET = r"[^\]]+"

# Apache directive / nginx variable -> (field name or special handler key)
_APACHE: dict[str, str] = {
    "h": "source.ip",
    "a": "source.ip",
    "A": "destination.ip",
    "l": "-ident",
    "u": "user.name",
    "t": "@time_local",
    "r": "@request",
    "m": "http.request.method",
    "U": "url.path",
    "q": "@query",
    "H": "http.version",
    ">s": "http.response.status_code",
    "s": "http.response.status_code",
    "b": "http.response.body.bytes",
    "B": "http.response.body.bytes",
    "O": "http.response.bytes",
    "I": "http.request.bytes",
    "D": "@duration_us",
    "T": "@duration_s",
    "v": "url.domain",
    "V": "url.domain",
    "p": "destination.port",
    "P": "process.pid",
    "L": "http.request.id",
}
_NGINX: dict[str, str] = {
    "remote_addr": "source.ip",
    "binary_remote_addr": "-",
    "remote_user": "user.name",
    "time_local": "@time_local",
    "time_iso8601": "@time_iso",
    "msec": "@time_epoch",
    "request": "@request",
    "request_method": "http.request.method",
    "request_uri": "@request_uri",
    "uri": "url.path",
    "document_uri": "url.path",
    "args": "url.query",
    "query_string": "url.query",
    "server_protocol": "@protocol",
    "status": "http.response.status_code",
    "body_bytes_sent": "http.response.body.bytes",
    "bytes_sent": "http.response.bytes",
    "request_length": "http.request.bytes",
    "request_time": "@duration_s",
    "http_referer": "http.request.referrer",
    "http_user_agent": "user_agent.original",
    "http_x_forwarded_for": "http.request.headers.x_forwarded_for",
    "host": "url.domain",
    "server_name": "url.domain",
    "server_port": "destination.port",
    "request_id": "http.request.id",
    "remote_port": "source.port",
    "upstream_response_time": "-",
}
_INT_FIELDS = frozenset(
    {
        "http.response.status_code",
        "http.response.body.bytes",
        "http.response.bytes",
        "http.request.bytes",
        "destination.port",
        "source.port",
        "process.pid",
    }
)
_APACHE_TOKEN = re.compile(r"%(?:\{([^}]*)\})?([<>]?[a-zA-Z%])")
_NGINX_TOKEN = re.compile(r"\$\{?([a-z_][a-z0-9_]*)\}?")
_REQUEST_LINE = re.compile(r"^(\S+) (\S+)(?: (HTTP/\S+))?$")


def _header_field(name: str, kind: str) -> str:
    key = name.lower().replace("-", "_")
    if kind == "i":
        if key == "referer":
            return "http.request.referrer"
        if key == "user_agent":
            return "user_agent.original"
        return f"http.request.headers.{key}"
    if kind == "o":
        return f"http.response.headers.{key}"
    return "-"  # %{..}e / %{..}n / %{..}C ... are matched but not kept


@dataclass(frozen=True, slots=True)
class CompiledFormat:
    pattern: re.Pattern[str]
    fields: tuple[str, ...]  # field (or handler key) per capture group
    source: str


def compile_format(fmt: str, *, allow_trailing: bool = False) -> CompiledFormat:
    """Translate an Apache LogFormat or Nginx log_format string into a regex.

    ``allow_trailing`` accepts extra space-separated fields after the format
    (servers often append e.g. request time to the combined format).
    """
    is_nginx = "$" in fmt and "%" not in fmt.replace("%%", "")
    token_re = _NGINX_TOKEN if is_nginx else _APACHE_TOKEN
    parts: list[str] = []
    fields: list[str] = []
    pos = 0
    for m in token_re.finditer(fmt):
        literal = fmt[pos : m.start()]
        parts.append(re.escape(literal).replace(r"\ ", " "))
        if is_nginx:
            key = m.group(1)
            target = _NGINX.get(key) or (
                _header_field(key[5:], "i") if key.startswith("http_") else "-"
            )
        else:
            arg, directive = m.group(1), m.group(2)
            if directive == "%":
                parts.append("%")
                pos = m.end()
                continue
            if arg is not None and directive in "ioeCn":
                target = _header_field(arg, directive)
            elif directive == "t" and arg:
                target = "-"  # custom strftime formats are not supported; matched, not kept
            else:
                target = _APACHE.get(directive.lstrip("<"), "-")
        if literal.endswith('"'):
            group = f"({_QUOTED})"
        elif target == "@time_local" and literal.endswith("["):
            group = f"({_BRACKET})"  # nginx: [$time_local]
        elif target == "@time_local":
            group = rf"\[({_BRACKET})\]"  # apache: %t includes the brackets
        else:
            group = f"({_NONSPACE})"
        parts.append(group)
        fields.append(target)
        pos = m.end()
    parts.append(re.escape(fmt[pos:]).replace(r"\ ", " "))
    regex = "^" + "".join(parts) + (r"(?: .*)?$" if allow_trailing else "$")
    if not fields:
        raise ValueError("format string has no fields")
    return CompiledFormat(re.compile(regex), tuple(fields), fmt)


def _to_int(value: str) -> int | None:
    if value in ("-", ""):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _apply(  # noqa: PLR0912 - one branch per directive kind
    fields: dict[str, Any], target: str, value: str, ts: list[int]
) -> None:
    if target.startswith("-"):
        return
    if target == "@time_local":
        ts.append(parse_apache_time(value))
    elif target == "@time_iso":
        ts.append(parse_iso8601(value))
    elif target == "@time_epoch":
        ts.append(parse_epoch(value))
    elif target == "@request":
        fields["url.original"] = value
        m = _REQUEST_LINE.match(value)
        if m:
            fields["http.request.method"] = m.group(1)
            _split_target(fields, m.group(2))
            if m.group(3):
                fields["http.version"] = m.group(3).removeprefix("HTTP/")
    elif target == "@request_uri":
        fields.setdefault("url.original", value)
        _split_target(fields, value)
    elif target == "@protocol":
        if value != "-":
            fields["http.version"] = value.removeprefix("HTTP/")
    elif target == "@query":
        if value not in ("", "-"):
            fields["url.query"] = value.removeprefix("?")
    elif target == "@duration_us":
        n = _to_int(value)
        if n is not None:
            fields["event.duration"] = n * 1000  # ECS: nanoseconds
    elif target == "@duration_s":
        with suppress(ValueError):
            fields["event.duration"] = int(float(value) * 1e9)
    elif target in _INT_FIELDS:
        n = _to_int(value)
        if n is not None:
            fields[target] = n
    elif value != "-":
        fields[target] = value


def _split_target(fields: dict[str, Any], target: str) -> None:
    path, sep, query = target.partition("?")
    fields["url.path"] = path
    if sep and query:
        fields["url.query"] = query


class WebAccessParser(Parser):
    """Combined/common (auto) or a custom format; ``name`` is apache or nginx."""

    def __init__(self, name: str = "apache", fmt: str | None = None) -> None:
        self.name = name
        self.dataset = f"{name}.access"
        if fmt and fmt not in PRESETS:
            self.formats: tuple[CompiledFormat, ...] = (compile_format(fmt),)
        elif fmt:
            self.formats = (compile_format(PRESETS[fmt], allow_trailing=True),)
        else:
            # Try the richest format first; common is a prefix of combined.
            self.formats = (
                compile_format(COMBINED, allow_trailing=True),
                compile_format(COMMON),
            )

    def parse(self, line: str, ctx: ParseContext) -> Event:
        for compiled in self.formats:
            m = compiled.pattern.match(line)
            if m:
                return self._event(m.groups(), compiled.fields, line)
        raise ParseError(f"line does not match the {self.name} access log format")

    def _event(self, values: Sequence[str], targets: Sequence[str], line: str) -> Event:
        fields: dict[str, Any] = {}
        ts: list[int] = []
        try:
            for target, value in zip(targets, values, strict=True):
                _apply(fields, target, value, ts)
        except TimestampError as exc:
            raise ParseError(str(exc)) from exc
        if not ts:
            raise ParseError("no timestamp field in the log format")
        fields["event.category"] = "web"
        fields["event.dataset"] = self.dataset
        return Event(ts=ts[0], fields=fields, logsource=WEBSERVER, raw=line)


ParserFactory = Callable[[], Parser]
