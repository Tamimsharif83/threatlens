# Correlation rules

[Sigma v2 correlation rules](https://sigmahq.io/docs/meta/correlations.html)
combine the matches of other rules over time: "10 failed logins from one
address in 5 minutes", "a failed web login followed by a successful SSH login
from the same address". ThreatLens compiles them with pySigma-backend-sqlite and
runs them after every ingested batch, like detection rules.

## Supported types

| `type` | Fires when, per group and within `timespan` | Needs |
|---|---|---|
| `event_count` | the referenced rules matched at least N times | `condition: {gte: N}` |
| `value_count` | a field took at least N distinct values (e.g. user names per IP) | `condition: {field: F, gte: N}` |
| `value_sum` / `value_avg` | the sum / average of a numeric field crossed a threshold | `condition: {field: F, gt: N}` |
| `temporal` | every referenced rule matched (any order) | 2+ rules |
| `temporal_ordered` | the referenced rules matched in the listed order | 2+ rules |

Condition operators: `gt`, `gte`, `lt`, `lte`, `eq`.

## Example: brute force (bundled)

```yaml
title: "[Example] SSH Brute Force From One Address"
id: 90faa98e-828e-45c8-a4e2-c53f8e9d2b99
correlation:
  type: event_count
  rules:
    - example_ssh_failed_login   # the `name:` (or `id:`) of a detection rule
  group-by:
    - source.ip
  timespan: 5m
  condition:
    gte: 10
  generate: false
level: high
```

## Example: failed web login, then SSH success from the same address

Different rules often use different field names for the same thing. **Aliases**
give them one name to group by. Sigma webserver names (`c-ip`) work here too.

```yaml
title: Web Login Failure Followed by SSH Access
id: 2b1e4f7a-9c33-4f0e-8d55-6a1b2c3d4e5f
correlation:
  type: temporal_ordered
  rules:
    - web_login_failed       # logsource: category webserver
    - ssh_login_success      # logsource: product linux, service auth
  group-by:
    - ip
  aliases:
    ip:
      web_login_failed: c-ip
      ssh_login_success: source.ip
  timespan: 10m
level: high
```

A correlation can mix log sources: each referenced rule reads its own event
table, and the alert links events from both.

## `generate`: does the base rule alert on its own?

`generate` belongs to the **correlation** (putting it on a base rule does nothing):

- `generate: false` (the default): only the correlation alerts. The referenced
  rules are marked **correlation only** on the Rules page and do not alert on
  their own (unless another enabled correlation uses them with `generate: true`).
  You can still retro-hunt them individually.
- `generate: true`: the referenced rules also alert on their own, and each
  correlation alert lists those alerts as **child alerts**.

Disabling a correlation updates this immediately.

## How results become alerts

The SQL returns one row **per sliding window** where the condition holds, so one
burst of 15 failed logins appears in many overlapping windows. ThreatLens turns
them into one alert:

- **One alert per group** (e.g. per `source.ip`), including every event of every
  window that fired, each counted once.
- Further matches for the same group within `TL_ALERT_THROTTLE_MINUTES` (event
  time) join the open alert; a later burst starts a new one. A closed alert is
  never reopened by new matches.
- The alert shows the correlation **metric**: type, value and the latest window.
- **Incremental:** after each batch the correlation runs over the new events'
  time range, widened backwards by `timespan`, so a burst split across two uploads
  (or two watch-folder polls) is still detected. Re-running never double-counts.

## Testing correlation rules

Fixtures work as for detection rules (see [writing rules](writing-rules.md)):

```
tests/rules/<correlation-id>/tp.log   # these events MUST make the correlation fire
tests/rules/<correlation-id>/tn.log   # these must NOT (put your near-misses here)
```

`tp` and `tn` are evaluated **separately**, each in its own scratch database, so
negative events can never trigger because of positive ones. Good `tn` cases for a
threshold rule: one event short of the threshold, the same count spread over more
addresses, and the same count spread over a longer time than `timespan`. The
bundled brute-force example tests all three.

```bash
threatlens rules test --dir my-rules --tests my-rules/tests --require-fixtures
```

## Limits

- A referenced rule that matches several event tables (e.g. two webserver
  sources) is read from the first table that holds data.
- Correlations of correlations are not supported (pySigma-backend-sqlite).
