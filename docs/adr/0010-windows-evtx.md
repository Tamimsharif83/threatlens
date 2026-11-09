# 0010. Windows EVTX: reading, field names and routing with the official pipelines

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

Phase 7 adds Windows event logs: Security, Sysmon, PowerShell and System. EVTX
is a binary format (chunks of BinXML records), unlike every other input. Windows
Sigma rules come in two shapes: `service:` rules for one channel, and generic
`category:` rules (`process_creation`, `registry_set` ...) that several channels
can satisfy with different event IDs and field names. SigmaHQ's rules assume the
field names of pySigma's Windows pipelines.

## Decisions

### Read EVTX with the Rust `evtx` library, one JSON line per record
`EvtxLines` wraps `evtx.PyEvtxParser` (`records_json`, one thread, no
indentation) and presents the file as a stream of lines, so the existing
pipeline (batching, dedup, malformed samples, detection after each chunk) is
reused unchanged. The library is fast (≈62,000 Security records in 4 s with an
84 MB peak on a laptop) and ships wheels for amd64 and arm64.

A record or chunk the library cannot decode raises `RuntimeError`; the reader
turns it into a malformed line with the reason and continues with the next
record (at most 10,000 errors in a row). A damaged log never stops an ingest.

The library needs a seekable file. A plain `.evtx` is read in place (and must
fit the decompressed-size limit). An EVTX inside `.gz` or `.zip` is copied,
through the same size- and ratio-limited reader as other archives, to an
anonymous temporary file in `TMPDIR` (`/data/tmp` in the container) first.

EVTX is recognised by its header (`ElfFile\0`), never by name: the upload
refuses `.evtx` names without the header, and EVTX data under another name.

### Field names follow Sigma, plus ECS aliases
Records are flattened the way Sigma's Windows rules expect: System values as
`EventID`, `Channel`, `Computer`, `Provider_Name` ...; `EventData` and
`UserData` values under their own names; unnamed data joined into `Data`.
`EventID` is stored as a number, so `EventID: 4625` compiles to `EventID=4625`
and matches. A handful of ECS fields (`host.name`, `user.name`, `source.ip`,
`process.*`, `file.hash.*`, `event.action` ...) are added so alert grouping,
pivots, IOC extraction and case timelines work without Windows-specific code.

JSON Lines written by `evtx_dump -o jsonl` are parsed by the same parser
(auto-detected), which also makes Windows rule fixtures easy to write by hand.

### One table per channel, named after the Sigma service
The channel → service map is pySigma's own (`windows_logsource_mapping`), so
storage routing and rule compilation cannot disagree: `Security` →
`service: security` → `ev_windows_security`. Unknown channels go to
`ev_windows`. Security logs carry hundreds of distinct fields across event IDs,
so the per-table column cap was raised from 400 to 1,000 (SQLite allows 2,000);
fields beyond it still go to the JSON overflow column.

### Compile Windows rules with the official pySigma pipelines
For a Windows rule on a given table ThreatLens prepends the official pipelines
to its own:

- `service:` rules: `windows_logsource_pipeline` (adds the `Channel` condition);
- `category:` rules on `ev_windows_sysmon`: `sysmon_pipeline` (EventID per
  category) + the logsource pipeline;
- `category:` rules on `ev_windows_security`: `windows_audit_pipeline` (4688 /
  4657, field mapping such as `Image` → `NewProcessName`) + the logsource
  pipeline;
- `ps_*` categories: the logsource pipeline maps them to PowerShell channels.

`tables_for` routes a category rule to every channel whose pipeline can produce
it. When a pipeline rejects a rule for one table (a `DetectionItemFailure`, e.g.
`EventType` has no Security 4657 counterpart), compilation raises
`NotApplicableError`: the rule runs on the remaining tables, and only a rule
that fits no table is reported as broken. Correlation rules apply the same
pipelines to each referenced rule before compiling the correlation.

### No bundled Windows rules
The example rules stay at five files (web and Linux). Windows rules come from
the user or from `rules import-sigmahq`, which now imports SigmaHQ's Windows
rules as well. The docs show a Windows example rule and fixtures.

## Consequences

- SigmaHQ Windows rules run unmodified, with the same semantics as other
  pySigma backends.
- A `process_creation` rule matches on Sysmon *and* on Security 4688, so an
  environment that logs both sees the same process start twice (as in SIEMs
  that use the same pipelines).
- Test fixtures are small public EVTX samples from the `evtx` project
  (MIT/Apache-2.0), trimmed to one chunk.
- Live `.evtx` files on a Windows host are locked; users export or copy them
  (Event Viewer *Save All Events As*, `wevtutil epl`) before ingesting.
