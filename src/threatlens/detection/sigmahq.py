"""Import community rules from a *local* SigmaHQ clone into the user's rules folder.

ThreatLens never ships SigmaHQ rules. This copies the ones whose log source
ThreatLens can ingest, keeping the original files untouched and adding the
Detection Rule License (DRL 1.1) notice next to them.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from threatlens.detection.compiler import tables_for
from threatlens.detection.engine import BUILTIN_TABLES

RULE_ROOTS = ("rules", "rules-emerging-threats", "rules-threat-hunting")
LICENSE_FILES = ("LICENSE.Detection.Rules.md", "LICENSE")


@dataclass(slots=True)
class ImportReport:
    target: Path
    imported: int = 0
    skipped: int = 0
    by_logsource: dict[str, int] = field(default_factory=dict)
    errors: list[tuple[str, str]] = field(default_factory=list)


def import_sigmahq(clone: Path, target: Path) -> ImportReport:
    report = ImportReport(target=target)
    roots = [clone / r for r in RULE_ROOTS if (clone / r).is_dir()]
    if not roots:
        report.errors.append((str(clone), "no rules/ folder: is this a SigmaHQ clone?"))
        return report
    target.mkdir(parents=True, exist_ok=True)
    for root in roots:
        for path in sorted(root.rglob("*.yml")):
            if path.is_symlink():
                continue
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
                report.errors.append((str(path.relative_to(clone)), str(exc)))
                continue
            if not isinstance(doc, dict) or not isinstance(doc.get("logsource"), dict):
                report.skipped += 1
                continue
            logsource = {
                k: str(v)
                for k, v in doc["logsource"].items()
                if k in ("category", "product", "service")
            }
            if not tables_for(logsource, list(BUILTIN_TABLES)):
                report.skipped += 1
                continue
            rel = path.relative_to(clone)
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)
            key = ", ".join(f"{k}: {v}" for k, v in sorted(logsource.items()))
            report.by_logsource[key] = report.by_logsource.get(key, 0) + 1
            report.imported += 1
    for name in LICENSE_FILES:
        if (clone / name).is_file():
            shutil.copyfile(clone / name, target / name)
            break
    (target / "README.md").write_text(
        "# SigmaHQ rules (imported)\n\n"
        "Copied from a local clone of https://github.com/SigmaHQ/sigma by "
        "`threatlens rules import-sigmahq`.\n"
        "These rules are licensed under the Detection Rule License (DRL) 1.1: keep the "
        "author attribution when you share or modify them.\n",
        encoding="utf-8",
    )
    return report
