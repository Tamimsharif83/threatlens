# 0007. Correlation rules: compilation, incremental runs, alert merging

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

Sigma v2 correlation rules aggregate the matches of other rules over sliding
time windows. pySigma-backend-sqlite compiles them into a single SQL query
(ADR-0002 verified this). Three problems remain: making that query run on
ThreatLens' per-log-source tables, running it incrementally after each batch
without re-scanning all history, and turning its one-row-per-window output into
something an analyst can triage.

## Decisions

### Compile with the referenced rules, routed by rule id
A correlation is parsed together with the detection rules it references (by
`name` or `id`, resolved from the rule catalog) and the active Sigma filters.
A pipeline routes **each referenced rule to its own table** with
`RuleAttributeCondition("id", …)`, applies the Sigma webserver field mapping to
web rules, and maps the correlation's own group-by/alias/value fields (the
Sigma webserver names never collide with stored field names). The referenced
rules are converted first, because the correlation reuses their conversion
state. The backend's Zircolite plan provides the authoritative map from the
event-id prefixes (`"0:12"`) to tables, and the fields each table needs.

### Incremental runs through temporary window views
The compiled query reads `tlw_<table>` instead of the table. Before a run,
ThreatLens creates `TEMP VIEW tlw_<table> AS SELECT * FROM <table> WHERE tl_ts
BETWEEN lo AND hi`, with integer bounds it computes itself. After a batch, `lo` is
the batch's oldest event minus the correlation `timespan` and `hi` its newest
event. The cost follows the batch, and bursts split across batches are still
caught. Retro-hunts use the full range.

### One alert per group; event references deduplicate windows
Each result row is a window. Rows are merged per group (`rule id + group-by
values`). Only events this correlation has never referenced count, so
overlapping windows and re-runs add nothing new. New events join the group's
open alert if they are within the throttle window, else start a new alert. The
alert stores the metric (type, value, latest window). Child alerts — base-rule
alerts on the same events, present when `generate: true` — are linked in
`alert_links`.

### `generate` semantics
Base rules referenced only by enabled correlations with `generate: false` are
flagged `correlation_only` and skipped in ingest-time detection. The flag is
recomputed on reload and whenever a rule is enabled or disabled. Explicit
retro-hunts of such a rule still run.

### Tests
Correlation fixtures are evaluated per set (`tp` must fire at least once, `tn`
never), each set in its own scratch database, through the same compiler.

## Consequences

- Correlations across log sources (web + auth) work, with aliases.
- Alert volume stays proportional to incidents, not to window counts.
- A base rule may match several tables. A correlation reads it from one table,
  the first with data (documented limitation).
- Correlations of correlations are not supported by the backend.
