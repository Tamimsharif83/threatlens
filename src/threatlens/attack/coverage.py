"""Detection coverage over MITRE ATT&CK, per-rule metrics, and Navigator export.

A technique is *covered* by every enabled, valid rule tagged with it (or with
one of its sub-techniques). For each technique the matrix shows how many such
rules exist, how many have passing tests, and how many have ever fired.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from threatlens import __version__
from threatlens.attack.catalog import Catalog, load, techniques_in_tags

NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"


@dataclass(slots=True)
class RuleRef:
    id: str
    title: str
    tested: bool
    fired: bool


@dataclass(slots=True)
class Cell:
    technique: str
    name: str
    rules: list[RuleRef] = field(default_factory=list)
    sub_covered: list[str] = field(default_factory=list)  # covered sub-techniques

    @property
    def enabled(self) -> int:
        return len(self.rules)

    @property
    def tested(self) -> int:
        return sum(r.tested for r in self.rules)

    @property
    def fired(self) -> int:
        return sum(r.fired for r in self.rules)

    @property
    def level(self) -> int:
        """0 none · 1 rules · 2 rules with passing tests · 3 a tested rule has fired."""
        if not self.rules:
            return 0
        if any(r.tested and r.fired for r in self.rules):
            return 3
        if self.tested:
            return 2
        return 1


@dataclass(slots=True)
class Coverage:
    catalog: Catalog
    columns: list[tuple[str, str, list[Cell]]]  # (tactic shortname, tactic name, cells)
    covered: int
    total: int
    unknown_tags: dict[str, list[str]]  # technique id not in the catalog -> rule titles
    rule_count: int


def _rules(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, title, tags, test_status, hits, enabled, load_error, kind FROM rules "
        "WHERE enabled = 1 AND load_error IS NULL"
    ).fetchall()


def compute(conn: sqlite3.Connection, catalog: Catalog | None = None) -> Coverage:
    catalog = catalog or load()
    by_tech: dict[str, list[RuleRef]] = {}
    unknown: dict[str, list[str]] = {}
    rules = _rules(conn)
    for r in rules:
        ref = RuleRef(r["id"], r["title"], r["test_status"] == "pass", (r["hits"] or 0) > 0)
        for tid in techniques_in_tags(json.loads(r["tags"])):
            if catalog.technique(tid) is None:
                unknown.setdefault(tid, []).append(r["title"])
                continue
            by_tech.setdefault(tid, []).append(ref)
            parent = catalog.techniques[tid].parent
            if parent:  # a sub-technique rule also covers its parent technique
                by_tech.setdefault(parent, []).append(ref)
    columns = []
    covered = 0
    parents = [t for t in catalog.techniques.values() if t.parent is None]
    for tactic in catalog.tactics:
        cells = []
        for tech in parents:
            if tactic.shortname not in tech.tactics:
                continue
            refs = {r.id: r for r in by_tech.get(tech.id, [])}  # dedupe per rule
            subs = sorted(s.id for s in catalog.subtechniques(tech.id) if s.id in by_tech)
            cells.append(Cell(tech.id, tech.name, list(refs.values()), subs))
        cells.sort(key=lambda c: (-c.level, -c.enabled, c.name))
        columns.append((tactic.shortname, tactic.name, cells))
    covered = sum(1 for t in parents if t.id in by_tech)
    return Coverage(catalog, columns, covered, len(parents), unknown, len(rules))


def navigator_layer(cov: Coverage, name: str = "ThreatLens detection coverage") -> dict[str, Any]:
    """An ATT&CK Navigator layer: score = number of enabled rules per technique."""
    techniques: list[dict[str, Any]] = []
    seen: dict[str, Any] = {}
    for _, _, cells in cov.columns:
        for cell in cells:
            if not cell.rules or cell.technique in seen:
                continue
            seen[cell.technique] = True
            techniques.append(
                {
                    "techniqueID": cell.technique,
                    "score": cell.enabled,
                    "enabled": True,
                    "comment": f"{cell.enabled} rule(s), {cell.tested} with passing tests, "
                    f"{cell.fired} fired",
                    "metadata": [{"name": "rule", "value": r.title} for r in cell.rules[:20]],
                    "showSubtechniques": bool(cell.sub_covered),
                }
            )
            for sub in cell.sub_covered:
                if sub not in seen:
                    seen[sub] = True
                    techniques.append({"techniqueID": sub, "score": 1, "enabled": True})
    max_score = max((t["score"] for t in techniques), default=1)
    return {
        "name": name,
        "versions": {
            "attack": cov.catalog.version.split(".")[0],
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": f"Generated by ThreatLens {__version__}: enabled Sigma rules per "
        f"technique ({cov.covered}/{cov.total} techniques covered).",
        "sorting": 3,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#fef3c7", "#16a34a"], "minValue": 0, "maxValue": max_score},
        "legendItems": [{"label": "covered by enabled rules", "color": "#16a34a"}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0b1016",
        "selectTechniquesAcrossTactics": True,
    }


# ---------------------------------------------------------------- per-rule metrics


@dataclass(slots=True)
class RuleMetrics:
    id: str
    title: str
    kind: str
    level: str | None
    enabled: bool
    hits: int
    alerts: int
    suppressed: int
    tp: int
    fp: int
    btp: int
    open: int
    last_fired_at: int | None
    techniques: list[str]
    correlation_only: bool = False

    @property
    def closed(self) -> int:
        return self.tp + self.fp + self.btp

    @property
    def precision(self) -> float | None:
        """TP / (TP + FP); None until at least one TP or FP verdict exists."""
        denom = self.tp + self.fp
        return self.tp / denom if denom else None


def rule_metrics(conn: sqlite3.Connection) -> list[RuleMetrics]:
    outcomes: dict[str, dict[str, int]] = {}
    for rule_id, status, resolution, n in conn.execute(
        "SELECT rule_id, status, resolution, count(*) FROM alerts GROUP BY 1, 2, 3"
    ):
        o = outcomes.setdefault(rule_id, {"tp": 0, "fp": 0, "btp": 0, "open": 0})
        if status != "closed":
            o["open"] += n
        elif resolution == "true_positive":
            o["tp"] += n
        elif resolution == "false_positive":
            o["fp"] += n
        elif resolution == "benign_true_positive":
            o["btp"] += n
    out = []
    for r in conn.execute(
        "SELECT id, title, kind, level, enabled, hits, alerts, suppressed, last_fired_at, tags, "
        "correlation_only FROM rules ORDER BY title"
    ):
        o = outcomes.get(r["id"], {"tp": 0, "fp": 0, "btp": 0, "open": 0})
        out.append(
            RuleMetrics(
                r["id"],
                r["title"],
                r["kind"],
                r["level"],
                bool(r["enabled"]),
                r["hits"],
                r["alerts"],
                r["suppressed"],
                o["tp"],
                o["fp"],
                o["btp"],
                o["open"],
                r["last_fired_at"],
                techniques_in_tags(json.loads(r["tags"])),
                bool(r["correlation_only"]),
            )
        )
    return out
