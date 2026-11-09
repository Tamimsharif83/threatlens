"""Compile Sigma rules to SQLite SQL for ThreatLens' event tables.

pySigma parses the rule; pySigma-backend-sqlite generates the SQL. ThreatLens
only decides *where* a rule runs (which event tables) and how Sigma field names
map onto stored field names:

* ``category: webserver`` rules use the Sigma webserver names (``cs-uri-query``,
  ``c-ip`` ...), which are mapped onto the ECS columns of every table whose log
  source has ``category: webserver``.
* ``product: ecs`` rules run on ``ev_ecs``; the rule's ``category`` becomes an
  extra ``event.category = <category>`` condition.
* ``product: windows`` rules use pySigma's official Windows pipelines. A rule
  with a ``service`` runs on that channel's table (``ev_windows_security`` ...).
  A rule with a generic ``category`` runs on every table that can produce it:
  ``process_creation`` on Sysmon (EventID 1, `sysmon_pipeline`) and on Security
  (EventID 4688 with field mapping, `windows_audit_pipeline`); ``ps_script`` on
  PowerShell/Operational (EventID 4104) and so on. When a pipeline rejects a rule
  for one table (a Sysmon field with no Security counterpart), the rule still
  runs on the other tables (`NotApplicableError`).
* Every other rule runs on the tables whose declared log source matches
  (see `tables_for`).

pySigma's processing pipelines modify the rule object while converting it, so a
rule is always parsed fresh from its YAML before each compilation.
"""

from __future__ import annotations

import re
import re._constants as sre_constants  # type: ignore[import-not-found]
import re._parser as sre_parse  # type: ignore[import-not-found]
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from sigma.backends.sqlite.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaTransformationError
from sigma.filters import SigmaFilter
from sigma.pipelines.common import windows_logsource_mapping
from sigma.pipelines.sysmon.sysmon import (
    sysmon_generic_logsource_eventid_mapping,
    sysmon_pipeline,
)
from sigma.pipelines.windows.windows import (
    generic_logsource_to_windows_audit_event_mapping,
    windows_audit_pipeline,
    windows_generic_category_channel_mapping,
    windows_logsource_pipeline,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.rule import SigmaRule

from threatlens.normalize.schema import LogSource
from threatlens.storage.events import ID, TS

# Sigma webserver taxonomy -> ECS fields stored by ThreatLens.
WEBSERVER_FIELDS: dict[str | None, str | list[str]] = {
    "c-ip": "source.ip",
    "cs-username": "user.name",
    "cs-method": "http.request.method",
    "cs-uri-stem": "url.path",
    "cs-uri-query": "url.query",
    "cs-uri": "url.original",
    "sc-status": "http.response.status_code",
    "cs-user-agent": "user_agent.original",
    "cs-referer": "http.request.referrer",
    "cs-host": "url.domain",
    "cs-version": "http.version",
    "cs-bytes": "http.request.bytes",
    "sc-bytes": "http.response.body.bytes",
    "s-ip": "destination.ip",
    "s-port": "destination.port",
    "time-taken": "event.duration",
    "cs-cookie": "http.request.headers.cookie",
}

# Field that Sigma "keywords" (field-less values) are matched against, per table.
FULLTEXT_FIELD = {"ev_webserver": "url.original"}
DEFAULT_FULLTEXT_FIELD = "message"

ECS_TABLE = "ev_ecs"
WINDOWS = "windows"
NOT_APPLICABLE = "not applicable to this table: "


class CompileError(ValueError):
    """The rule cannot be turned into SQL."""


class NotApplicableError(CompileError):
    """A pipeline rejects the rule for this table only (it may run on others)."""

    def __init__(self, reason: str) -> None:
        super().__init__(NOT_APPLICABLE + reason)


def windows_table(service: str | None) -> str:
    return LogSource(product=WINDOWS, service=service).table_name


# Event table -> Sigma service, for every channel the official pipeline knows.
WINDOWS_TABLE_SERVICES: dict[str, str] = {windows_table(s): s for s in windows_logsource_mapping}


def windows_category_services(category: str) -> list[str]:
    """Services (channels) whose events a generic Windows ``category`` can come from."""
    services = []
    if category in sysmon_generic_logsource_eventid_mapping:
        services.append("sysmon")
    audit: Mapping[str, object] = generic_logsource_to_windows_audit_event_mapping  # type: ignore[assignment]
    if category in audit:
        services.append("security")
    if category in windows_generic_category_channel_mapping:
        services.append(str(windows_generic_category_channel_mapping[category]["service"]))
    return services


def windows_pipeline(logsource: Mapping[str, str], table: str) -> ProcessingPipeline | None:
    """The official pySigma pipelines for a Windows rule on ``table`` (None otherwise)."""
    if logsource.get("product") != WINDOWS:
        return None
    service = WINDOWS_TABLE_SERVICES.get(table)
    pipeline = windows_logsource_pipeline()  # Channel condition per service
    if logsource.get("category") and not logsource.get("service"):
        if service == "sysmon":
            pipeline = sysmon_pipeline() + pipeline
        elif service == "security":
            pipeline = windows_audit_pipeline() + pipeline
    return pipeline


@dataclass(frozen=True, slots=True)
class CompiledRule:
    rule_id: str
    table: str
    sql: str  # SELECT * FROM <table> WHERE ...
    fields: tuple[str, ...]  # stored field names the query needs (columns)


def parse_rule(yaml_text: str) -> SigmaRule | SigmaCorrelationRule:
    """Parse one rule. References of correlation rules are not resolved here: the
    rules they reference usually live in other files."""
    try:
        collection = SigmaCollection.from_yaml(yaml_text, resolve_references=False)
    except Exception as exc:  # pySigma raises many exception types for bad rules
        raise CompileError(str(exc)) from exc
    if len(collection.rules) != 1:
        raise CompileError("expected exactly one rule")
    rule = collection.rules[0]
    if isinstance(rule, SigmaRule):
        try:  # conditions are parsed lazily; force it so errors surface at load time
            for condition in rule.detection.parsed_condition:
                condition.parse()
        except Exception as exc:
            raise CompileError(f"invalid condition: {exc}") from exc
    return rule


def tables_for(logsource: dict[str, str], catalog: Iterable[tuple[str, LogSource]]) -> list[str]:
    """Event tables a rule with ``logsource`` should run on.

    ``catalog`` lists (table, declared log source) for every known table,
    including built-in tables not created yet.
    """
    category = logsource.get("category")
    product = logsource.get("product")
    service = logsource.get("service")
    if product == "ecs":
        return [ECS_TABLE]
    if product == WINDOWS and (service or category):
        services = [service] if service else windows_category_services(str(category))
        return sorted({t for t, ls in catalog if ls.product == WINDOWS and ls.service in services})
    found: list[str] = []
    for table, ls in catalog:
        if ls.product == "ecs":
            continue
        if category:
            ok = (
                ls.category == category
                and (product is None or ls.product is None or ls.product == product)
                and (service is None or ls.service is None or ls.service == service)
            )
        else:
            ok = (
                product is not None
                and ls.product == product
                and (service is None or ls.service == service)
            )
        if ok:
            found.append(table)
    return sorted(set(found))


def _pipeline(logsource: dict[str, str], table: str) -> ProcessingPipeline:
    items: list[ProcessingItem] = []
    if logsource.get("category") == "webserver":
        items.append(ProcessingItem(FieldMappingTransformation(WEBSERVER_FIELDS)))
    if logsource.get("product") == "ecs" and logsource.get("category"):
        items.append(
            ProcessingItem(AddConditionTransformation({"event.category": logsource["category"]}))
        )
    items.append(ProcessingItem(SetStateTransformation("table", table)))
    own = ProcessingPipeline(name="threatlens", priority=20, items=items)
    official = windows_pipeline(logsource, table)
    return official + own if official is not None else own


def backend_for(logsource: dict[str, str], table: str) -> sqliteBackend:
    return sqliteBackend(
        _pipeline(logsource, table),
        timestamp_field=TS,
        timestamp_format="unix_ms",
        event_id_field=ID,
        fulltext_field=FULLTEXT_FIELD.get(table, DEFAULT_FULLTEXT_FIELD),
    )


def parse_filter(yaml_text: str) -> SigmaFilter:
    try:
        collection = SigmaCollection.from_yaml(yaml_text, collect_filters=True)
    except Exception as exc:
        raise CompileError(str(exc)) from exc
    if len(collection.filters) != 1:
        raise CompileError("expected exactly one Sigma filter")
    return collection.filters[0]


def compile_detection(yaml_text: str, table: str, filters: Sequence[str] = ()) -> CompiledRule:
    """Compile a detection rule for ``table``, with Sigma ``filters`` (YAML) applied."""
    rule = parse_rule(yaml_text)
    if not isinstance(rule, SigmaRule):
        raise CompileError("not a detection rule")
    for filter_yaml in filters:
        try:
            applied = parse_filter(filter_yaml).apply_on_rule(rule)
        except CompileError:
            continue  # a broken filter is reported on its own; never breaks a rule
        except Exception as exc:
            raise CompileError(f"applying a Sigma filter failed: {exc}") from exc
        if isinstance(applied, SigmaRule):
            rule = applied
    logsource = logsource_dict(rule)
    backend = backend_for(logsource, table)
    try:
        queries = backend.convert_rule(rule)
    except SigmaTransformationError as exc:  # e.g. a Sysmon-only field on Security events
        raise NotApplicableError(str(exc)) from exc
    except Exception as exc:  # pySigma raises many exception types for unsupported features
        raise CompileError(f"cannot convert rule: {exc}") from exc
    if len(queries) != 1 or not isinstance(queries[0], str):
        raise CompileError("rule did not produce exactly one query")
    fields = tuple(sorted(backend.required_fields(rule)))
    return CompiledRule(str(rule.id), table, queries[0], fields)


def logsource_dict(rule: SigmaRule) -> dict[str, str]:
    ls = rule.logsource
    return {
        k: v
        for k, v in (("category", ls.category), ("product", ls.product), ("service", ls.service))
        if v
    }


# ---------------------------------------------------------------- REGEXP for SQLite


@lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def sql_regexp(pattern: str | None, value: object) -> bool:
    """SQLite ``REGEXP`` (``X REGEXP Y`` calls ``regexp(Y, X)``) used by Sigma ``|re``."""
    if pattern is None or value is None:
        return False
    try:
        return _compiled(pattern).search(str(value)) is not None
    except re.error:
        return False


_REPEATS = {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT}


def _children(op: object, av: Any, *, atomic: bool) -> list[Any]:  # noqa: ANN401 - sre parse tree
    """Sub-patterns of a parsed regex node. ``atomic``: also look inside atomic groups
    and possessive repeats (they cannot backtrack *into*, but can backtrack *inside*)."""
    if op in _REPEATS:
        return [av[2]]
    if op == sre_constants.SUBPATTERN:
        return [av[3]]
    if op == sre_constants.BRANCH:
        return list(av[1])
    if op in {sre_constants.ASSERT, sre_constants.ASSERT_NOT}:
        return [av[1]]
    if atomic and op == sre_constants.ATOMIC_GROUP:
        return [av]
    if atomic and op == sre_constants.POSSESSIVE_REPEAT:
        return [av[2]]
    return []


def _has_repeat(items: Iterable[Any]) -> bool:
    """Does a parsed (sub)pattern contain a backtracking variable-count repeat?"""
    for op, av in items:
        if op in _REPEATS and av[1] > av[0]:
            return True
        if any(_has_repeat(c) for c in _children(op, av, atomic=False)):
            return True
    return False


def _nested(items: Iterable[Any]) -> bool:
    for op, av in items:
        if op in _REPEATS and av[1] > av[0] and _has_repeat(av[2]):
            return True
        if any(_nested(c) for c in _children(op, av, atomic=True)):
            return True
    return False


@lru_cache(maxsize=512)
def catastrophic_regex(pattern: str) -> bool:
    """True for a repeated group that itself contains a repeat, such as ``(a+)+``.

    Python's ``re`` backtracks: on a near-miss input such patterns take
    exponential time, and SQLite's time limit cannot interrupt a Python
    function. Atomic groups and possessive quantifiers (``(?>a+)+``, ``(a++)+``)
    do not backtrack and are not reported.
    """
    try:
        return _nested(sre_parse.parse(pattern))
    except (re.error, RecursionError, OverflowError):
        return False
