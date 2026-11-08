"""Storage layout spike for ADR-0002.

Compares two SQLite layouts for Sigma rules compiled by pySigma-backend-sqlite:

  A  one `events` core table (typed columns for known fields + JSON `extra` for the rest)
     with one VIEW per Sigma log source that exposes Sigma/ECS field names as aliases.
  B  Zircolite-style: one wide flattened table per log source, a column per field
     (unknown fields become new columns).

Same synthetic data, same rules, same pySigma field-mapping pipeline.
Run:  python scripts/bench/storage_layout_spike.py [n_events]
Needs: pysigma, pysigma-backend-sqlite (dev dependencies).
"""

from __future__ import annotations

import json
import os
import random
import sqlite3
import sys
import tempfile
import time

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldMappingTransformation,
    SetStateTransformation,
)

SEED = 1337
SIGMA_TO_ECS = {
    "c-ip": "source.ip",
    "cs-method": "http.request.method",
    "cs-uri-stem": "url.path",
    "cs-uri-query": "url.query",
    "sc-status": "http.response.status_code",
    "cs-user-agent": "user_agent.original",
    "cs-referer": "http.request.referrer",
}
# Known ECS field -> physical column in layout A
KNOWN = {
    "source.ip": "source_ip",
    "http.request.method": "http_method",
    "url.path": "url_path",
    "url.query": "url_query",
    "http.response.status_code": "http_status",
    "user_agent.original": "user_agent",
    "http.request.referrer": "http_referrer",
    "user.name": "user_name",
}
EXTRA_FIELDS = ["app.tenant", "app.request_id", "app.region"]

RULES = """
title: SQLi in query
id: 00000000-0000-0000-0000-000000000001
logsource: {category: webserver}
detection:
  sel: {cs-uri-query|contains: ['union select', "' or 1=1"]}
  condition: sel
---
title: Scanner UA
id: 00000000-0000-0000-0000-000000000002
logsource: {category: webserver}
detection:
  sel: {cs-user-agent|contains: ['sqlmap', 'nikto', 'nuclei']}
  condition: sel
---
title: Failed login
id: 00000000-0000-0000-0000-000000000003
name: web_failed_login
logsource: {category: webserver}
generate: true
detection:
  sel: {cs-method: POST, sc-status: 401, cs-uri-stem|endswith: /login}
  condition: sel
---
title: Unknown-field rule
id: 00000000-0000-0000-0000-000000000004
logsource: {category: webserver}
detection:
  sel: {app.tenant: ACME, app.region: eu-west}
  condition: sel
---
title: Brute force
id: 00000000-0000-0000-0000-000000000005
correlation:
  type: event_count
  rules: [web_failed_login]
  group-by: [c-ip]
  timespan: 5m
  condition: {gte: 20}
"""


def gen(n: int) -> list[dict[str, object]]:
    rnd = random.Random(SEED)
    ips = [
        f"10.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(2000)
    ]
    attackers = ips[:5]
    paths = ["/", "/index.html", "/api/items", "/login", "/static/app.js", "/search", "/admin"]
    uas = ["Mozilla/5.0 (X11; Linux x86_64)", "curl/8.5.0", "Mozilla/5.0 (Windows NT 10.0)"]
    t0 = 1_767_225_600_000
    out = []
    for i in range(n):
        ts = t0 + i * 300 + rnd.randint(0, 299)
        burst = 40_000 <= i < 40_600  # one dense brute-force burst
        ip = (
            attackers[0]
            if burst
            else (rnd.choice(attackers) if rnd.random() < 0.02 else rnd.choice(ips))
        )
        path = "/login" if burst else rnd.choice(paths)
        q = ""
        if rnd.random() < 0.3:
            q = f"q=item{rnd.randint(1, 999)}"
        if rnd.random() < 0.001:
            q = "id=1' or 1=1--"
        method = "POST" if path == "/login" else "GET"
        status = (
            401 if (path == "/login" and ip in attackers) else rnd.choice([200, 200, 200, 304, 404])
        )
        ua = "sqlmap/1.8" if rnd.random() < 0.0005 else rnd.choice(uas)
        ev: dict[str, object] = {
            "ts": ts,
            "source.ip": ip,
            "http.request.method": method,
            "url.path": path,
            "url.query": q or None,
            "http.response.status_code": status,
            "user_agent.original": ua,
            "http.request.referrer": None,
            "user.name": None,
            "app.tenant": rnd.choice(["acme", "globex", "initech"]),
            "app.request_id": f"{rnd.getrandbits(64):016x}",
            "app.region": rnd.choice(["eu-west", "us-east"]),
        }
        ev["hash"] = hash(json.dumps(ev, sort_keys=True))
        out.append(ev)
    return out


def q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def build_a(db: sqlite3.Connection, events: list[dict[str, object]]) -> str:
    cols = ", ".join(f"{c} TEXT COLLATE NOCASE" for c in KNOWN.values() if c != "http_status")
    db.executescript(
        f"""
        CREATE TABLE events(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, logsource TEXT NOT NULL,
          hash INTEGER NOT NULL UNIQUE, http_status INTEGER, {cols}, extra TEXT);
        CREATE INDEX ev_ts ON events(ts);
        CREATE INDEX ev_ip ON events(source_ip);
        """
    )
    rows = []
    for e in events:
        extra = {k: e[k] for k in EXTRA_FIELDS}
        rows.append(
            (e["ts"], "webserver", e["hash"], e["http.response.status_code"])
            + tuple(e[f] for f, c in KNOWN.items() if c != "http_status")
            + (json.dumps(extra, separators=(",", ":")),)
        )
    ph = ",".join("?" * len(rows[0]))
    names = (
        "ts, logsource, hash, http_status, "
        + ", ".join(c for c in KNOWN.values() if c != "http_status")
        + ", extra"
    )
    db.executemany(f"INSERT INTO events({names}) VALUES ({ph})", rows)
    sel = ["id AS rowid_", "ts AS timestamp"]
    sel += [f"{c} AS {q(f)}" for f, c in KNOWN.items()]
    for f in EXTRA_FIELDS:
        path = "'$.\"" + f.replace("'", "''") + "\"'"
        sel.append(f"json_extract(extra, {path}) COLLATE NOCASE AS {q(f)}")
    db.execute(
        f"CREATE VIEW v_webserver AS SELECT {', '.join(sel)} FROM events WHERE logsource='webserver'"
    )
    return "v_webserver"


def build_b(db: sqlite3.Connection, events: list[dict[str, object]]) -> str:
    fields = list(KNOWN) + EXTRA_FIELDS
    cols = ", ".join(
        f"{q(f)} TEXT COLLATE NOCASE" for f in fields if f != "http.response.status_code"
    )
    db.executescript(
        f"""
        CREATE TABLE webserver(rowid_ INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL,
          hash INTEGER NOT NULL UNIQUE, "http.response.status_code" INTEGER, {cols});
        CREATE INDEX wb_ts ON webserver(timestamp);
        CREATE INDEX wb_ip ON webserver("source.ip");
        """
    )
    order = ["http.response.status_code"] + [f for f in fields if f != "http.response.status_code"]
    rows = [(e["ts"], e["hash"]) + tuple(e[f] for f in order) for e in events]
    ph = ",".join("?" * len(rows[0]))
    db.executemany(
        f"INSERT INTO webserver(timestamp, hash, {', '.join(q(f) for f in order)}) VALUES ({ph})",
        rows,
    )
    return "webserver"


def compile_rules(table: str) -> list[tuple[str, str]]:
    pipe = ProcessingPipeline(
        name="spike",
        priority=20,
        items=[
            ProcessingItem(
                FieldMappingTransformation(SIGMA_TO_ECS),
                rule_conditions=[LogsourceCondition(category="webserver")],
            ),
            ProcessingItem(
                SetStateTransformation("table", table),
                rule_conditions=[LogsourceCondition(category="webserver")],
            ),
        ],
    )
    backend = sqliteBackend(pipe, timestamp_format="unix_ms", event_id_field="rowid_")
    # Parse the whole collection first so correlation references resolve,
    # then convert rule by rule to keep each query labelled with its title.
    out: list[tuple[str, str]] = []
    for rule in SigmaCollection.from_yaml(RULES):
        if isinstance(rule, SigmaCorrelationRule):
            queries = backend.convert_correlation_rule(rule)
        else:
            queries = backend.convert_rule(rule)
        out.extend((str(rule.title), sql) for sql in queries)
    return out


def run(layout: str, events: list[dict[str, object]]) -> dict[str, object]:
    path = tempfile.mktemp(suffix=f"-{layout}.db")
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    t = time.perf_counter()
    with db:
        table = (build_a if layout == "A" else build_b)(db, events)
    ingest_s = time.perf_counter() - t
    db.execute("VACUUM")
    size = os.path.getsize(path)
    res: dict[str, object] = {
        "layout": layout,
        "ingest_s": round(ingest_s, 2),
        "db_mb": round(size / 1e6, 1),
    }
    for title, sql in compile_rules(table):
        t = time.perf_counter()
        n = len(db.execute(sql).fetchall())
        res[title] = f"{n} rows / {(time.perf_counter() - t) * 1000:.0f} ms"
    db.close()
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            os.remove(path + suffix)
    return res


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
    events = gen(n)
    print(f"events: {n}  sqlite {sqlite3.sqlite_version}")
    for layout in ("A", "B"):
        print(json.dumps(run(layout, events)))


if __name__ == "__main__":
    main()
