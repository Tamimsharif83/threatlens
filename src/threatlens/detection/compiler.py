"""Compile Sigma rules to SQLite SQL for ThreatLens' event tables.

pySigma parses the rule; pySigma-backend-sqlite generates the SQL. ThreatLens
only decides *where* a rule runs (which event tables) and how Sigma field names
map onto stored field names:

* ``category: webserver`` rules use the Sigma webserver names (``cs-uri-query``,
  ``c-ip`` ...), which are mapped onto the ECS columns of every table whose log
  source has ``category: webserver``.
* ``product: ecs`` rules run on ``ev_ecs``; the rule's ``category`` becomes an
  extra ``event.category = <category>`` condition.
* Every other rule runs on the tables whose declared log source matches
  (see `tables_for`).

pySigma's processing pipelines modify the rule object while converting it, so a
rule is always parsed fresh from its YAML before each compilation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

from sigma.backends.sqlite.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
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


class CompileError(ValueError):
    """The rule cannot be turned into SQL."""


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
    return ProcessingPipeline(name="threatlens", priority=20, items=items)


def backend_for(logsource: dict[str, str], table: str) -> sqliteBackend:
    return sqliteBackend(
        _pipeline(logsource, table),
        timestamp_field=TS,
        timestamp_format="unix_ms",
        event_id_field=ID,
        fulltext_field=FULLTEXT_FIELD.get(table, DEFAULT_FULLTEXT_FIELD),
    )


def compile_detection(yaml_text: str, table: str) -> CompiledRule:
    rule = parse_rule(yaml_text)
    if not isinstance(rule, SigmaRule):
        raise CompileError("not a detection rule")
    logsource = logsource_dict(rule)
    backend = backend_for(logsource, table)
    try:
        queries = backend.convert_rule(rule)
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
