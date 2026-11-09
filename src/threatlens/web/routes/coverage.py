"""ATT&CK coverage matrix, Navigator layer export, and per-rule metrics."""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import Response

from threatlens.attack.coverage import compute, navigator_layer, rule_metrics
from threatlens.web.deps import DbDep, SessionDep
from threatlens.web.templating import render

router = APIRouter(include_in_schema=False)
SORTS = {
    "noise": lambda m: (-m.hits, -m.alerts),
    "alerts": lambda m: (-m.alerts, -m.hits),
    "precision": lambda m: (m.precision is None, m.precision if m.precision is not None else 0),
    "fp": lambda m: (-m.fp, -m.alerts),
    "title": lambda m: m.title.lower(),
}


@router.get("/coverage")
def coverage_page(request: Request, session: SessionDep, db: DbDep, covered: int = 0) -> Response:
    cov = compute(db)
    columns = cov.columns
    if covered:
        columns = [(s, n, [c for c in cells if c.rules]) for s, n, cells in columns]
    return render(
        request,
        "coverage.html",
        {
            "active": "attack",
            "cov": cov,
            "columns": columns,
            "only_covered": bool(covered),
            "pct": round(100 * cov.covered / cov.total, 1) if cov.total else 0.0,
        },
    )


@router.get("/coverage/navigator.json")
def navigator(session: SessionDep, db: DbDep) -> Response:
    layer = navigator_layer(compute(db))
    return Response(
        json.dumps(layer, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="threatlens-attack-layer.json"'},
    )


@router.get("/metrics")
def metrics_page(request: Request, session: SessionDep, db: DbDep, sort: str = "noise") -> Response:
    metrics = rule_metrics(db)
    metrics.sort(key=SORTS.get(sort, SORTS["noise"]))
    totals = {
        "tp": sum(m.tp for m in metrics),
        "fp": sum(m.fp for m in metrics),
        "btp": sum(m.btp for m in metrics),
        "open": sum(m.open for m in metrics),
    }
    denom = totals["tp"] + totals["fp"]
    return render(
        request,
        "metrics.html",
        {
            "active": "metrics",
            "metrics": metrics,
            "sort": sort if sort in SORTS else "noise",
            "totals": totals,
            "overall_precision": totals["tp"] / denom if denom else None,
            "noisiest": [
                m for m in sorted(metrics, key=lambda m: (-m.alerts, -m.hits)) if m.alerts
            ][:5],
        },
    )
