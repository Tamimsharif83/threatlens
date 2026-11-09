# 0008. Cases, timelines, IOCs and report export

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

Phase 5 turns triaged alerts into an investigation (a "case") and a report that
can leave ThreatLens. The report carries attacker-controlled log values, may be
opened outside ThreatLens (as a local HTML file, or Markdown pasted into a wiki
or ticket), and mixes generated facts with the analyst's own narrative.

## Decisions

### A case references alerts; everything else is derived
A case links alerts (`case_alerts`) instead of copying them. The **timeline** is
computed on demand from the case's alerts, their referenced events (capped at
500 on the page, 200 in the report) and the analyst's **annotations**, which are
notes pinned to an event time. **ATT&CK findings** group the alerts by
technique tag, with tactics taken from the fixed list of ATT&CK tactic names.
Technique names come with the technique catalogue (Phase 6).

### IOCs: automatic plus manual, never silently overwritten
"Extract from events" rebuilds the automatic IOCs from well-known fields
(`source.ip`, `destination.ip`, domains, `url.original`, `user_agent.original`,
user names, file names and hashes), with occurrence counts and first/last seen.
Manual entries (with an optional note) are kept across re-extractions. Hashes
are validated as MD5/SHA-1/SHA-256 hex. Exports: formula-safe CSV and JSON.

### Narrative sections are analyst-owned text
Executive summary, scope, impact, root cause, recommendations and appendix are
stored on the case and edited on the case page. Exports insert them as written:
as Markdown in `.md`, and as pre-formatted, escaped text in HTML. No Markdown
renderer, and no extra dependency or HTML-injection surface.

### Export safety
- **Markdown:** log values are emitted as code spans with a fence longer than
  any backtick run in the value, with `|` escaped and control characters removed,
  so they cannot break tables or inject links or formatting. Titles and rule
  names are backslash-escaped.
- **HTML:** a separate Jinja environment with autoescaping, inline CSS, no
  scripts, and its own `Content-Security-Policy` meta tag (`default-src 'none';
  style-src 'unsafe-inline'`), so it stays inert when opened as a local file. It
  is laid out for print-to-PDF.
- Both are served as downloads (`Content-Disposition: attachment`) with a
  sanitized file name.

### Audit
Every case action (create, update, alert add/remove, notes, annotations, IOC
changes, extraction) is audited with `target = case:<id>`.

## Consequences

- Reports always reflect the current case; re-exporting after more triage is free.
- Events deleted by retention appear as "purged" in timelines; the alert and
  case keep their counts and IOCs.
- Analysts who want rich formatting get it in the Markdown export; the HTML
  report stays deliberately plain and safe.
