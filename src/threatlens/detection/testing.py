"""Detection-as-code: per-rule true-positive / true-negative fixtures.

Layout (one folder per rule id)::

    tests/rules/<rule-id>/tp.log     raw log lines that MUST all match the rule
    tests/rules/<rule-id>/tn.log     raw log lines that must NOT match
    tests/rules/<rule-id>/tp.jsonl   ...or events as JSON objects with ECS field names
    tests/rules/<rule-id>/tn.jsonl
    tests/rules/<rule-id>/tp.evtx    Windows: an EVTX file (every record must match)
    tests/rules/<rule-id>/tn.evtx

Raw lines go through the same parsers as real ingestion (format auto-detected),
so a test also proves the parser extracts what the rule needs. JSON events are
inserted as they are; ``@timestamp`` is optional. A JSON line holding a Windows
record (``{"Event": {"System": ..., "EventData": ...}}``, as ``evtx_dump -o jsonl``
writes it) is parsed like an EVTX record and lands in its channel's table.

Each rule is tested in a throwaway database, so tests never touch real data.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from threatlens.correlation.compiler import BaseRule, CompiledCorrelation, compile_correlation
from threatlens.correlation.runner import create_views, ensure_columns
from threatlens.detection.compiler import (
    CompileError,
    NotApplicableError,
    compile_detection,
    tables_for,
)
from threatlens.detection.engine import BUILTIN_TABLES, register_functions, table_catalog
from threatlens.detection.loader import LoadedRule
from threatlens.ingest.readers import MALFORMED, EvtxLines, iter_lines
from threatlens.normalize.schema import Event, LogSource
from threatlens.normalize.values import flatten
from threatlens.parsers import ParseContext, ParseError, UnknownFormatError, detect_parser
from threatlens.parsers.json_lines import parse_timestamp
from threatlens.parsers.windows import WindowsEventParser
from threatlens.storage.db import connect, init_db, transaction
from threatlens.storage.events import ID, EventStore, PreparedEvent, content_hash, quote_ident

FIXTURE_TS = int(datetime(2026, 1, 5, 12, 0, tzinfo=UTC).timestamp() * 1000)


@dataclass(slots=True)
class RuleTestResult:
    rule_id: str
    title: str
    status: str  # pass | fail | none
    messages: list[str] = field(default_factory=list)
    tp: int = 0
    tn: int = 0


def find_fixture_dir(rule_id: str, test_dirs: list[Path]) -> Path | None:
    for base in test_dirs:
        candidate = base / rule_id
        if candidate.is_dir():
            return candidate
    return None


def _events_from_jsonl(path: Path, table_ls: LogSource) -> list[Event]:
    events = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name}:{n}: invalid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"{path.name}:{n}: expected a JSON object")
        if isinstance(obj.get("Event"), dict):  # a Windows record (evtx_dump JSON)
            try:
                ev = WindowsEventParser().parse(line, ParseContext())
            except ParseError as exc:
                raise ValueError(f"{path.name}:{n}: {exc}") from exc
            ev.record_no = n
            events.append(ev)
            continue
        fields = flatten(obj)
        raw_ts = fields.pop("@timestamp", None)
        ts = parse_timestamp(raw_ts, "auto", UTC) if raw_ts is not None else FIXTURE_TS + n
        events.append(Event(ts, fields, table_ls, raw=line, record_no=n))
    return events


def _events_from_log(path: Path) -> list[Event]:
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return []
    ctx = ParseContext(reference_time=datetime(2026, 12, 31, tzinfo=UTC))
    try:
        parser = detect_parser(lines, ctx)
    except UnknownFormatError as exc:
        raise ValueError(f"{path.name}: {exc}") from exc
    events = []
    for n, line in enumerate(lines, start=1):
        try:
            ev = parser.parse(line, ctx)
        except ParseError as exc:
            raise ValueError(f"{path.name}:{n}: cannot parse fixture line: {exc}") from exc
        ev.record_no = n
        events.append(ev)
    return events


def _events_from_evtx(path: Path) -> list[Event]:
    parser = WindowsEventParser()
    events = []
    lines = EvtxLines(path, path.name)
    for n, line in iter_lines(lines):
        if line.startswith(MALFORMED):
            raise ValueError(f"{path.name}: record {n}: {line[len(MALFORMED) :]}")
        try:
            ev = parser.parse(line, ParseContext())
        except ParseError as exc:
            raise ValueError(f"{path.name}: record {n}: {exc}") from exc
        ev.record_no = n
        events.append(ev)
    return events


def _load_fixture(directory: Path, kind: str, table_ls: LogSource) -> list[Event] | None:
    jsonl, log, evtx = (directory / f"{kind}.{ext}" for ext in ("jsonl", "log", "evtx"))
    if not jsonl.exists() and not log.exists() and not evtx.exists():
        return None
    events: list[Event] = []
    if jsonl.exists():
        events += _events_from_jsonl(jsonl, table_ls)
    if log.exists():
        events += _events_from_log(log)
    if evtx.exists():
        events += _events_from_evtx(evtx)
    return events


def _target_logsource(rule: LoadedRule) -> tuple[str, LogSource]:
    """The table (and its log source) JSON fixture events are stored in."""
    tables = tables_for(rule.logsource, list(BUILTIN_TABLES))
    if tables:
        table = tables[0]
        return table, dict(BUILTIN_TABLES)[table]
    ls = LogSource(**{k: rule.logsource.get(k) for k in ("category", "product", "service")})
    return ls.table_name, ls


EventKey = tuple[str, int]  # (table, tl_id)


def _evaluate(
    rule: LoadedRule, tp: list[Event], tn: list[Event], filters: Sequence[str] = ()
) -> tuple[dict[str, set[EventKey]], set[EventKey], list[str]]:
    """Load the fixtures into a scratch database and run the rule over them.

    Returns (inserted event keys per kind, matched keys, tables the rule reads).
    """
    with tempfile.TemporaryDirectory(prefix="tl-ruletest-") as tmp:
        db_path = Path(tmp) / "test.db"
        init_db(db_path, quiet=True)
        conn = connect(db_path)
        try:
            register_functions(conn)
            store = EventStore(conn)
            ids: dict[str, set[EventKey]] = {"tp": set(), "tn": set()}
            for kind, events in (("tp", tp), ("tn", tn)):
                for i, ev in enumerate(events):
                    with transaction(conn):
                        res = store.insert(
                            [PreparedEvent(ev, content_hash(kind, ev.raw or str(i), i))], 1
                        )
                    ids[kind] |= {(t.table, t.max_id) for t in res.tables.values() if t.max_id}
            matched: set[EventKey] = set()
            rule_tables = tables_for(rule.logsource, table_catalog(conn))
            present = set(store.event_tables())
            for table in rule_tables:
                if table not in present:
                    continue
                try:
                    compiled = compile_detection(rule.yaml, table, filters)
                except NotApplicableError:
                    continue  # e.g. a Sysmon-only field: the rule runs on other tables
                existing = store.table_columns(table)
                with transaction(conn):
                    for f in compiled.fields:
                        if f.lower() not in existing:
                            conn.execute(
                                f"ALTER TABLE {quote_ident(table)} ADD COLUMN "
                                f"{quote_ident(f)} TEXT COLLATE NOCASE"
                            )
                rows = conn.execute(f"SELECT {ID} FROM ({compiled.sql})")  # noqa: S608
                matched |= {(table, r[0]) for r in rows}
            return ids, matched, rule_tables
        finally:
            conn.close()


def run_rule_test(
    rule: LoadedRule,
    test_dirs: list[Path],
    filters: Sequence[str] = (),
    bases: Sequence[LoadedRule] | None = None,
) -> RuleTestResult:
    result = RuleTestResult(rule.id, rule.title, "none")
    if rule.kind == "correlation":
        return run_correlation_test(rule, bases or [], test_dirs, filters)
    if rule.kind != "detection":
        return result
    if rule.load_error:
        result.status = "fail"
        result.messages.append(rule.load_error)
        return result
    directory = find_fixture_dir(rule.id, test_dirs)
    if directory is None:
        result.messages.append(
            "no fixtures (tests/rules/<rule-id>/tp.log, tn.log, *.jsonl, *.evtx)"
        )
        return result
    _, table_ls = _target_logsource(rule)
    try:
        tp = _load_fixture(directory, "tp", table_ls)
        tn = _load_fixture(directory, "tn", table_ls)
    except (ValueError, OSError) as exc:
        result.status = "fail"
        result.messages.append(str(exc))
        return result
    if not tp and not tn:
        result.messages.append("fixture folder has no tp/tn files")
        return result

    try:
        ids, matched, rule_tables = _evaluate(rule, tp or [], tn or [], filters)
    except CompileError as exc:
        result.status = "fail"
        result.messages.append(f"cannot compile: {exc}")
        return result
    missed = ids["tp"] - matched
    false_hits = ids["tn"] & matched
    result.tp, result.tn = len(ids["tp"]), len(ids["tn"])
    stray = {t for t, _ in ids["tp"] | ids["tn"]} - set(rule_tables)
    if stray:
        result.messages.append(
            f"fixture events landed in {', '.join(sorted(stray))}, which this rule does not "
            "read; check the rule's logsource or the fixture format"
        )
    if missed:
        result.messages.append(
            f"{len(missed)} of {len(ids['tp'])} true-positive event(s) did not match"
        )
    if false_hits:
        result.messages.append(f"{len(false_hits)} true-negative event(s) matched")
    result.status = "fail" if result.messages else "pass"
    return result


# ---------------------------------------------------------------- correlation rules


def _table_for(rule: LoadedRule) -> tuple[str, LogSource]:
    return _target_logsource(rule)


def _correlation_rows(compiled: CompiledCorrelation, events: list[Event]) -> int:
    """Number of window results the correlation produces over ``events`` alone."""
    with tempfile.TemporaryDirectory(prefix="tl-corrtest-") as tmp:
        db_path = Path(tmp) / "test.db"
        init_db(db_path, quiet=True)
        conn = connect(db_path)
        try:
            register_functions(conn)
            store = EventStore(conn)
            for i, ev in enumerate(events):
                with transaction(conn):
                    store.insert([PreparedEvent(ev, content_hash("c", ev.raw or str(i), i))], 1)
            tables = set(compiled.source_tables.values())
            if not tables <= set(store.event_tables()):
                return 0
            ensure_columns(conn, compiled)
            create_views(conn, tables, 0, 2**62)
            return len(conn.execute(compiled.sql).fetchall())
        finally:
            conn.close()


def run_correlation_test(
    rule: LoadedRule,
    bases: Sequence[LoadedRule],
    test_dirs: list[Path],
    filters: Sequence[str] = (),
) -> RuleTestResult:
    """tp fixtures must make the correlation fire at least once; tn fixtures never."""
    result = RuleTestResult(rule.id, rule.title, "none")
    if rule.load_error:
        result.status = "fail"
        result.messages.append(rule.load_error)
        return result
    directory = find_fixture_dir(rule.id, test_dirs)
    if directory is None:
        result.messages.append(
            "no fixtures (tests/rules/<rule-id>/tp.log, tn.log, *.jsonl, *.evtx)"
        )
        return result
    if not bases:
        result.status = "fail"
        result.messages.append("the rules this correlation references are not loaded")
        return result
    base_rules = [BaseRule(b.id, b.name, b.yaml, _table_for(b)[0], b.logsource) for b in bases]
    try:
        compiled = compile_correlation(rule.yaml, base_rules, filters)
        _, table_ls = _table_for(bases[0])
        tp = _load_fixture(directory, "tp", table_ls)
        tn = _load_fixture(directory, "tn", table_ls)
    except (CompileError, ValueError, OSError) as exc:
        result.status = "fail"
        result.messages.append(str(exc))
        return result
    if not tp and not tn:
        result.messages.append("fixture folder has no tp/tn files")
        return result
    result.tp, result.tn = len(tp or []), len(tn or [])
    if tp is not None and _correlation_rows(compiled, tp) == 0:
        result.messages.append("the true-positive events did not make the correlation fire")
    if tn is not None and (n := _correlation_rows(compiled, tn)):
        result.messages.append(
            f"the true-negative events made the correlation fire ({n} window(s))"
        )
    result.status = "fail" if result.messages else "pass"
    return result
