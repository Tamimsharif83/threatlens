# 0005. Detection engine: rule routing, run-on-ingest, alert grouping

- **Status:** Accepted
- **Date:** 2026-11-08

## Context

Phase 2 runs Sigma rules. pySigma parses and validates them, and
pySigma-backend-sqlite turns them into SQL (ADR-0002). Four questions remain:
which event tables a rule runs on, how to run rules on only the new data, how
matches become alerts, and how analysts test their rules.

## Decisions

### Rule → table routing in Python, one pipeline per rule
A single global pySigma pipeline with `LogsourceCondition`s cannot express
"no table yet" or "several tables". ThreatLens resolves the tables itself from
the rule's log source and the event-table catalog:

- `category: X` → every table whose declared category is X (product/service, if
  the rule gives them, must not contradict the table's).
- otherwise `product: P` (+ `service: S`) → tables with that product (and service).
- `product: ecs` → `ev_ecs`, with `event.category = <category>` added as a condition.

Then it builds a small pipeline for that rule and table: the Sigma webserver
field mapping (`cs-uri-query` → `url.query` ...), the extra ECS condition, and the
target table. A rule whose logs have not been ingested yet simply waits. It is
not an error.

pySigma pipelines modify the rule object while converting it, so every compile
re-parses the rule from its YAML. Compiled SQL is cached per (rule, table)
until the next reload.

### Run on ingest by id range
Each ingest batch reports the `tl_id` range it inserted per table. After the
batch, every enabled rule for those tables runs as
`SELECT * FROM (<rule SQL>) WHERE tl_id BETWEEN ? AND ?`. SQLite flattens the
subquery into a rowid range scan, so cost grows with the batch, not the table.
**Retro-hunt** runs the same query over the whole table in 100,000-row ranges.

Fields a rule references that a table has never seen are added as empty
columns before the query runs, so `not`/`exists: false` conditions behave correctly.

### Alerts: group by primary entity, reference events once
- One alert per rule and **primary entity**: the first present of `source.ip`,
  `user.name`, `host.name`, `destination.ip`. A brute force from one IP against 50
  user names is one alert, not 50.
- Matches join an open (not closed) alert if they are within
  `TL_ALERT_THROTTLE_MINUTES` of it in **event time**. Otherwise a new alert starts.
- `alert_events` stores a reference (table, event id) for every matched event,
  keyed by (rule, table, event). The same rule never counts an event twice, so
  retro-hunts can re-scan safely and counters stay honest.
- An alert keeps only the entity values shared by all of its events, so it never
  shows one random user name for a multi-user attack.

### Detection-as-code
- `threatlens rules lint`: valid Sigma, unique ids, UUID ids, required metadata
  (`id title description author date level tags falsepositives references`), at
  least one ATT&CK technique tag; pySigma validator findings are warnings
  (errors with `--strict`).
- `threatlens rules test`: `tests/rules/<rule-id>/tp.(log|jsonl)` must all match,
  `tn.(log|jsonl)` must not. Raw `.log` fixtures go through the real parsers, so a
  test also proves the parser extracts the fields the rule needs. Each rule runs
  in a throwaway database. CI runs lint and tests with `--require-fixtures`.
- The app runs the same tests on every reload and shows pass/fail per rule.

### Rule sources
Bundled examples (`rules/examples/`, five rules marked `[Example]`) and the
analyst's folder (`/data/rules`, recursive; `tests/` subfolders hold fixtures).
`TL_BUILTIN_RULES=false` hides the examples. `threatlens rules import-sigmahq`
copies supported SigmaHQ rules from a local clone, with the DRL licence notice.
ThreatLens never vendors SigmaHQ rules.

## Consequences

- Rules can be written with Sigma webserver names or ECS names. Both work.
- A noisy rule stores one 30-byte reference per matched event; precision metrics
  (Phase 6) depend on these references, and tuning is the analyst's job.
- Sigma `|re` uses Python's `re` through a SQLite function. A pathological regex
  in a rule can be slow on attacker-controlled input; rules are trusted analyst
  content (threat model, Phase 8).
- Correlation rules load and are listed, but run from Phase 4. In Sigma v2,
  `generate: true` belongs on the **correlation** rule (it makes the referenced
  rules alert on their own too), not on the base rule.
