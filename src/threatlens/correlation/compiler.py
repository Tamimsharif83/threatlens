"""Compile Sigma v2 correlation rules to SQL.

A correlation is compiled together with the detection rules it references
(and the Sigma filters in effect). Each referenced rule is routed to its own
event table; pySigma-backend-sqlite then generates one query that evaluates the
sliding windows (``event_count``, ``value_count``, ``temporal``,
``temporal_ordered``, ``value_sum``, ``value_avg``).

The query reads from *window views* (``tlw_<table>``) instead of the tables, so
the caller can restrict a run to a time range by (re)creating those views.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import yaml
from sigma.backends.sqlite.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import (
    IsSigmaCorrelationRuleCondition,
    RuleAttributeCondition,
    RuleProcessingCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    SetStateTransformation,
)
from sigma.rule import SigmaRule

from threatlens.detection.compiler import (
    DEFAULT_FULLTEXT_FIELD,
    FULLTEXT_FIELD,
    WEBSERVER_FIELDS,
    CompileError,
    parse_filter,
)
from threatlens.storage.events import ID, TS

VIEW_PREFIX = "tlw_"


@dataclass(frozen=True, slots=True)
class BaseRule:
    """A detection rule referenced by a correlation, and the table it runs on."""

    id: str
    name: str | None
    yaml: str
    table: str
    logsource: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class CompiledCorrelation:
    rule_id: str
    type: str
    sql: str
    timespan_ms: int
    generate: bool
    base_rule_ids: tuple[str, ...]
    source_tables: dict[str, str]  # index used in event ids ("0:12") -> real table
    required_fields: dict[str, list[str]] = field(default_factory=dict)  # real table -> fields
    entity_fields: dict[str, str] = field(default_factory=dict)  # group key -> stored field


def view_name(table: str) -> str:
    return VIEW_PREFIX + table


def references(corr_yaml: str) -> list[str]:
    """Rule ids / names a correlation refers to (without resolving them)."""
    doc = yaml.safe_load(corr_yaml) or {}
    corr = doc.get("correlation") or {}
    refs = corr.get("rules") or []
    if isinstance(refs, str):
        refs = [refs]
    return [str(r) for r in refs]


def _pipeline(bases: Sequence[BaseRule]) -> ProcessingPipeline:
    items: list[ProcessingItem] = []
    for b in bases:
        # pySigma binds each condition object to one processing item: build fresh ones.
        def cond(rule_id: str = b.id) -> list[RuleProcessingCondition]:
            return [RuleAttributeCondition("id", rule_id)]

        if b.logsource.get("category") == "webserver":
            items.append(
                ProcessingItem(FieldMappingTransformation(WEBSERVER_FIELDS), rule_conditions=cond())
            )
        if b.logsource.get("product") == "ecs" and b.logsource.get("category"):
            items.append(
                ProcessingItem(
                    AddConditionTransformation({"event.category": b.logsource["category"]}),
                    rule_conditions=cond(),
                )
            )
        items.append(
            ProcessingItem(
                SetStateTransformation("table", view_name(b.table)), rule_conditions=cond()
            )
        )
    # Sigma webserver names in the correlation's group-by, aliases and value fields.
    # Applied always: these names (c-ip, cs-*, sc-*) never collide with stored fields.
    items.append(
        ProcessingItem(
            FieldMappingTransformation(WEBSERVER_FIELDS),
            rule_conditions=[IsSigmaCorrelationRuleCondition()],
        )
    )
    return ProcessingPipeline(name="threatlens-correlation", priority=20, items=items)


def _entity_fields(corr: SigmaCorrelationRule, bases: Sequence[BaseRule]) -> dict[str, str]:
    """Map each group-by key to a stored field (resolving aliases), for pivots."""
    out: dict[str, str] = {}
    first = bases[0] if bases else None
    aliases = corr.aliases.aliases if corr.aliases else {}
    for key in corr.group_by or []:
        name = key
        alias = aliases.get(key)
        if alias is not None and first is not None:
            for ref, fld in alias.mapping.items():
                if ref.reference in (first.name, first.id):
                    name = fld
                    break
        if first is not None and first.logsource.get("category") == "webserver":
            mapped = WEBSERVER_FIELDS.get(name, name)
            name = mapped if isinstance(mapped, str) else name
        out[key] = name
    return out


def compile_correlation(
    corr_yaml: str, bases: Sequence[BaseRule], filters: Sequence[str] = ()
) -> CompiledCorrelation:
    if not bases:
        raise CompileError("the correlation references no loadable detection rule")
    text = "\n---\n".join([*(b.yaml.strip() for b in bases), corr_yaml.strip()]) + "\n"
    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as exc:
        raise CompileError(f"cannot resolve the correlation's rules: {exc}") from exc
    corrs = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    if len(corrs) != 1:
        raise CompileError("expected exactly one correlation rule")
    corr = corrs[0]
    for filter_yaml in filters:
        try:
            flt = parse_filter(filter_yaml)
        except CompileError:
            continue
        for rule in collection.rules:
            if isinstance(rule, SigmaRule):
                flt.apply_on_rule(rule)
    fulltext = {FULLTEXT_FIELD.get(b.table, DEFAULT_FULLTEXT_FIELD) for b in bases}
    backend = sqliteBackend(
        _pipeline(bases),
        timestamp_field=TS,
        timestamp_format="unix_ms",
        event_id_field=ID,
        fulltext_field=fulltext.pop() if len(fulltext) == 1 else DEFAULT_FULLTEXT_FIELD,
    )
    try:
        # Referenced rules must be converted first: the correlation reuses their state.
        for rule in collection.rules:
            if isinstance(rule, SigmaRule):
                backend.convert_rule(rule, output_format="zircolite")
        out: list[Any] = backend.convert_correlation_rule(corr, output_format="zircolite")
    except Exception as exc:
        raise CompileError(f"cannot convert correlation: {exc}") from exc
    if len(out) != 1 or not isinstance(out[0], dict):
        raise CompileError("correlation did not produce exactly one query")
    plan = out[0]["correlation_plan"]
    sql = out[0]["rule"][0]
    strip = len(VIEW_PREFIX)

    def real(table: str) -> str:
        name = table.strip('`"')
        return name[strip:] if name.startswith(VIEW_PREFIX) else name

    return CompiledCorrelation(
        rule_id=str(corr.id),
        type=str(corr.type.name).lower() if hasattr(corr.type, "name") else str(corr.type),
        sql=sql,
        timespan_ms=int(corr.timespan.seconds * 1000),
        generate=bool(corr.generate),
        base_rule_ids=tuple(b.id for b in bases),
        source_tables={k: real(v) for k, v in plan["source_tables"].items()},
        required_fields={real(t): list(fs) for t, fs in plan["required_fields"].items()},
        entity_fields=_entity_fields(corr, bases),
    )
