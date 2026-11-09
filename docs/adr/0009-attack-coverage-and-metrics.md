# 0009. ATT&CK catalogue, coverage matrix and rule metrics

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

Phase 6 answers two questions an analyst asks about their own rules: *what
techniques can I detect?* and *which rules are worth keeping?* ThreatLens must
stay offline at runtime, so it cannot fetch ATT&CK data when a page loads, and
the answer must reflect the rules as they really run (enabled, compiled, tested).

## Decisions

### Bundle a compact ATT&CK list, generated from MITRE's STIX
`scripts/gen_attack_techniques.py` reads MITRE's official STIX bundle
(`attack-stix-data`) and writes `src/threatlens/attack/data/enterprise-attack.json`
(~95 KB): tactics in matrix order, and every technique and sub-technique that is
neither revoked nor deprecated, with its name, tactics and parent. The file
records the ATT&CK version, the source URL, the SHA-256 of the bundle and MITRE's
attribution. It is loaded once (`importlib.resources`, cached). Updating ATT&CK
is a deliberate, reviewable commit, never a runtime download. The bundled version
is ATT&CK Enterprise v20.0.

Rule tags written for older ATT&CK releases keep working: `attack.t1110.001` maps
to `T1110.001`, and the retired tactic tag `defense-evasion` is still shown with
its name. A technique tag that is not in the bundled release (revoked, deprecated
or mistyped) is a **lint warning** and is listed on the coverage page, so stale
rules are visible instead of silently uncounted.

### Coverage counts enabled rules that compile
A technique is covered by a rule when the rule is enabled, compiled without a load
error and carries its tag. A sub-technique rule also counts toward its parent, so
the parent cell shows the sub-techniques covered. Each cell has a level:
0 none, 1 rules, 2 at least one rule with passing tests, 3 tested **and** fired
at least once. Levels reward rules that are proven, not just present.

### Navigator export is a layer file, not a hosted Navigator
`/coverage/navigator.json` is an ATT&CK Navigator layer (layer format 4.5) with
the enabled-rule count as the score and the rule titles as comments. Users open
it in their own Navigator. Bundling the Navigator app would add a large
JavaScript application that conflicts with the strict CSP and the
no-build-step rule.

### Precision comes from the analyst's verdicts
Per-rule metrics are aggregated from alerts: events matched, alerts, suppressed
hits, open alerts, and the verdicts given when alerts are closed.
**Precision = TP / (TP + FP)**; benign true positives (authorised activity) are
not held against a rule. A rule with no verdicts has no precision ("—") rather
than 0% or 100%. The noisiest rules (most alerts) are listed first, as tuning
candidates.

## Consequences

- No network access at runtime; ATT&CK updates are a one-line script run plus a
  commit.
- Coverage reflects rules as deployed. A rule that fails to compile does not
  count, even if its tags look right.
- Metrics are only as good as the verdicts. Closing alerts without a resolution
  leaves precision empty.
- MITRE ATT&CK® is a registered trademark of The MITRE Corporation; ATT&CK
  content is used under MITRE's terms of use and attributed on the coverage page
  and in the data file.
