"""Incident report export: Markdown and self-contained HTML.

Sections follow a common incident-response layout: executive summary, scope,
timeline, findings mapped to ATT&CK, IOCs, impact, root cause, recommendations,
appendix. Narrative sections are written by the analyst on the case page;
timeline, findings and IOCs are generated from the case.

Log values are attacker-controlled. In Markdown they are emitted as escaped
code spans (so they cannot break tables or inject formatting); the HTML export
is autoescaped, has no scripts, and carries its own restrictive CSP so it is
safe to open as a local file.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from threatlens import __version__
from threatlens.cases import store
from threatlens.timeutil import ms_to_iso

TEMPLATES = Path(__file__).parent / "templates"
REPORT_EVENTS = 200
SECTION_TITLES = {
    "summary": "Executive summary",
    "scope": "Scope",
    "impact": "Impact",
    "root_cause": "Root cause",
    "recommendations": "Recommendations",
    "appendix": "Appendix",
}
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def md_code(value: object) -> str:
    """Inline code span safe inside a Markdown table cell."""
    text = _CONTROL.sub("", "" if value is None else str(value)).replace("\n", " ").strip()
    if not text:
        return ""
    text = text.replace("|", "\\|")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_text(value: object) -> str:
    """Plain text with Markdown/HTML metacharacters escaped (titles, rule names)."""
    text = _CONTROL.sub("", "" if value is None else str(value)).replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|<>~])", r"\\\1", text)


def _dt(ms: int | None) -> str:
    return "—" if ms is None else ms_to_iso(ms).replace("T", " ")[:19] + " UTC"


def _env(autoescape: bool) -> Environment:
    # The Markdown export is text, not HTML: values are escaped by the `code` / `mdtext`
    # filters instead. The HTML export always autoescapes.
    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=autoescape,  # noqa: S701 - see comment above
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["code"] = md_code
    env.filters["mdtext"] = md_text
    env.filters["dt"] = _dt
    return env


_MD = _env(autoescape=False)
_HTML = _env(autoescape=True)


def build_context(conn: sqlite3.Connection, case_id: int) -> dict[str, Any]:
    case = store.get(conn, case_id)
    if case is None:
        raise store.CaseError("case not found")
    alerts = store.case_alerts(conn, case_id)
    entries, hidden = store.timeline(conn, case_id, REPORT_EVENTS)
    first = min((a.first_seen for a in alerts), default=None)
    last = max((a.last_seen for a in alerts), default=None)
    return {
        "case": case,
        "sections": SECTION_TITLES,
        "alerts": alerts,
        "findings": store.attack_findings(alerts),
        "timeline": entries,
        "timeline_hidden": hidden,
        "iocs": store.iocs(conn, case_id),
        "notes": store.notes(conn, case_id),
        "first_seen": first,
        "last_seen": last,
        "generated_at": int(datetime.now(UTC).timestamp() * 1000),
        "version": __version__,
    }


def render_markdown(conn: sqlite3.Connection, case_id: int) -> str:
    return _MD.get_template("report.md.j2").render(build_context(conn, case_id))


def render_html(conn: sqlite3.Connection, case_id: int) -> str:
    return _HTML.get_template("report.html.j2").render(build_context(conn, case_id))
