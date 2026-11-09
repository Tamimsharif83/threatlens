# Architecture Decision Records

An ADR is a short note explaining one significant design decision: the
situation, the options considered, what was chosen, and what it costs us.
They are never edited after acceptance — a later ADR supersedes an earlier one.

| # | Title | Status |
|---|---|---|
| [0001](0001-application-stack.md) | Application stack | Accepted |
| [0002](0002-storage-engine-and-event-layout.md) | Storage engine and event table layout | Accepted |
| [0003](0003-security-baseline.md) | Security baseline for the web application and container | Accepted |
| [0004](0004-ingestion-pipeline.md) | Ingestion pipeline: dedup, retention, watch folder, archives | Accepted |
| [0005](0005-detection-engine.md) | Detection engine: rule routing, run-on-ingest, alert grouping | Accepted |
| [0006](0006-triage-hunt-and-tuning.md) | Triage, the read-only hunt console, and tuning | Accepted |
| [0007](0007-correlation-rules.md) | Correlation rules: compilation, incremental runs, alert merging | Accepted |
| [0008](0008-cases-and-reports.md) | Cases, timelines, IOCs and report export | Accepted |
| [0009](0009-attack-coverage-and-metrics.md) | ATT&CK catalogue, coverage matrix and rule metrics | Accepted |
| [0010](0010-windows-evtx.md) | Windows EVTX: reading, field names, routing with the official pipelines | Accepted |
| [0011](0011-v1-hardening.md) | v1.0 hardening: whole-app checks, hunt console limits, log evasion, scale | Accepted |

Template: copy [`template.md`](template.md).
