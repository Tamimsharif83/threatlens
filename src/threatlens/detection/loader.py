"""Find, parse and validate Sigma rule files.

Rules are plain YAML files: built-in examples (shipped with ThreatLens) and the
analyst's own rules in ``/data/rules`` (searched recursively; a ``tests`` folder
is skipped because it holds rule test fixtures). A file may contain several
YAML documents (e.g. base rules plus a correlation rule).
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators

from threatlens.detection.compiler import CompileError, logsource_dict, parse_rule

RULE_SUFFIXES = (".yml", ".yaml")
MAX_RULE_BYTES = 256 * 1024
_DOC_SPLIT = re.compile(r"^---[ \t]*$", re.MULTILINE)
ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
LEVELS = ("informational", "low", "medium", "high", "critical")
# Validators that only produce noise for an analyst's own rule repository.
_SKIP_VALIDATORS = {
    "duplicate_filename",
    "filename_length",
    "filename_lowercase",
    "sigmahq_filename_convention",
    "sigmahq_filename_prefix",
    # These download the MITRE ATT&CK / D3FEND datasets from the internet at runtime.
    # ThreatLens is offline by design; ATT&CK tags are checked by `lint` instead.
    "attacktag",
    "d3_fendtag",
}


@dataclass(slots=True)
class LoadedRule:
    id: str
    title: str
    kind: str  # detection | correlation
    origin: str  # builtin | user
    path: str
    yaml: str
    sha256: str
    name: str | None = None  # Sigma "name" (used by correlation rules to reference it)
    level: str | None = None
    status: str | None = None
    description: str | None = None
    author: str | None = None
    date: str | None = None
    tags: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    load_error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def attack_tags(self) -> list[str]:
        return [t for t in self.tags if t.startswith("attack.")]


@dataclass(slots=True)
class LoadResult:
    rules: list[LoadedRule] = field(default_factory=list)
    file_errors: dict[str, str] = field(default_factory=dict)


def builtin_rules_dir() -> Path | None:
    """Example rules shipped in the package, or the repository copy in a source checkout."""
    try:
        bundled = Path(str(resources.files("threatlens") / "_bundled" / "rules"))
        if bundled.is_dir():
            return bundled
    except (ModuleNotFoundError, TypeError):  # pragma: no cover
        pass
    repo = Path(__file__).resolve().parents[3] / "rules" / "examples"
    return repo if repo.is_dir() else None


def builtin_tests_dir() -> Path | None:
    try:
        bundled = Path(str(resources.files("threatlens") / "_bundled" / "rule-tests"))
        if bundled.is_dir():
            return bundled
    except (ModuleNotFoundError, TypeError):  # pragma: no cover
        pass
    repo = Path(__file__).resolve().parents[3] / "tests" / "rules"
    return repo if repo.is_dir() else None


def discover(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    found = []
    for path in sorted(directory.rglob("*")):
        rel = path.relative_to(directory)
        if any(part.startswith(".") or part == "tests" for part in rel.parts):
            continue
        if path.suffix.lower() in RULE_SUFFIXES and path.is_file() and not path.is_symlink():
            found.append(path)
    return found


def split_documents(text: str) -> list[str]:
    docs = [d.strip("\n") for d in _DOC_SPLIT.split(text)]
    return [d + "\n" for d in docs if d.strip()]


def _as_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _validator() -> SigmaValidator:
    return SigmaValidator(
        [v for name, v in core_validators.items() if name not in _SKIP_VALIDATORS]
    )


def load_document(doc: str, path: str, origin: str) -> LoadedRule:
    """Parse one YAML document into a LoadedRule (never raises for bad rules)."""
    try:
        raw = yaml.safe_load(doc)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("a rule must be a YAML mapping")
    rule_id = str(raw.get("id") or "").strip()
    if not rule_id:
        raise ValueError("rule has no 'id'")
    lr = LoadedRule(
        id=rule_id,
        title=str(raw.get("title") or "(untitled)")[:300],
        kind="correlation" if "correlation" in raw else "detection",
        origin=origin,
        path=path,
        yaml=doc,
        sha256=hashlib.sha256(doc.encode()).hexdigest(),
        name=str(raw["name"]) if raw.get("name") else None,
        level=str(raw.get("level") or "") or None,
        status=str(raw.get("status") or "") or None,
        description=str(raw.get("description") or "") or None,
        author=str(raw.get("author") or "") or None,
        date=str(raw.get("date") or "") or None,
        tags=_as_str_list(raw.get("tags")),
        logsource={k: str(v) for k, v in (raw.get("logsource") or {}).items()}
        if isinstance(raw.get("logsource"), dict)
        else {},
        falsepositives=_as_str_list(raw.get("falsepositives")),
        references=_as_str_list(raw.get("references")),
    )
    try:
        rule = parse_rule(doc)
    except (SigmaError, CompileError, ValueError, TypeError, KeyError) as exc:
        lr.load_error = f"invalid Sigma rule: {exc}"
        return lr
    if isinstance(rule, SigmaRule):
        lr.logsource = logsource_dict(rule)
        lr.level = rule.level.name.lower() if rule.level else lr.level
    elif isinstance(rule, SigmaCorrelationRule):
        lr.level = rule.level.name.lower() if rule.level else lr.level
    try:
        parsed = [
            r for r in SigmaCollection.from_yaml(doc).rules if isinstance(r, SigmaRule)
        ]  # validators apply to detection rules
        issues = _validator().validate_rules(iter(parsed))
        lr.warnings = sorted({f"{type(i).__name__}: {i.description}" for i in issues})
    except Exception as exc:  # validators must never block loading
        lr.warnings = [f"validation skipped: {exc}"]
    return lr


def _read_documents(path: Path) -> list[str]:
    if path.stat().st_size > MAX_RULE_BYTES:
        raise ValueError(f"file larger than {MAX_RULE_BYTES // 1024} KB")
    docs = split_documents(path.read_text(encoding="utf-8"))
    if not docs:
        raise ValueError("file is empty")
    return docs


def load_rules(sources: Iterable[tuple[Path, str]]) -> LoadResult:
    """Load every rule file from (directory, origin) pairs."""
    result = LoadResult()
    seen: dict[str, str] = {}
    for directory, origin in sources:
        for path in discover(directory):
            display = f"{origin}:{path.relative_to(directory)}"
            try:
                for doc in _read_documents(path):
                    lr = load_document(doc, display, origin)
                    if lr.id in seen:
                        result.file_errors[display] = (
                            f"duplicate rule id {lr.id} (already loaded from {seen[lr.id]})"
                        )
                        continue
                    seen[lr.id] = display
                    result.rules.append(lr)
            except (ValueError, OSError, UnicodeDecodeError) as exc:
                result.file_errors[display] = str(exc)
    return result


# ---------------------------------------------------------------- lint


@dataclass(frozen=True, slots=True)
class LintIssue:
    path: str
    rule_id: str | None
    message: str


REQUIRED = (
    "id",
    "title",
    "description",
    "author",
    "date",
    "level",
    "tags",
    "falsepositives",
    "references",
)


def lint(result: LoadResult) -> list[LintIssue]:
    """Detection-as-code checks: valid Sigma, unique ids, complete metadata."""
    issues = [LintIssue(p, None, e) for p, e in sorted(result.file_errors.items())]
    for r in result.rules:

        def add(message: str, rule: LoadedRule = r) -> None:
            issues.append(LintIssue(rule.path, rule.id, message))

        if r.load_error:
            add(r.load_error)
        try:
            uuid.UUID(r.id)
        except ValueError:
            add("id is not a UUID")
        raw = yaml.safe_load(r.yaml) or {}
        for key in REQUIRED:
            if not raw.get(key):
                add(f"missing required field '{key}'")
        if r.kind == "detection":
            if r.level and r.level not in LEVELS:
                add(f"level must be one of {', '.join(LEVELS)}")
            if not any(ATTACK_TECHNIQUE.match(t) for t in r.tags):
                add("tags must include at least one ATT&CK technique (e.g. attack.t1190)")
        for w in r.warnings:
            add(f"warning: {w}")
    return issues
