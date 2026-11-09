# Writing detection rules

ThreatLens runs standard [Sigma](https://sigmahq.io/docs/basics/rules.html) rules.
This page covers what is specific to ThreatLens: where rules go, which log
sources and field names exist, and how to test rules like code.

## Where rules live

| Location | What |
|---|---|
| `/data/rules/**/*.yml` | **your rules** (mount a folder there; sub-folders are fine) |
| `/data/rules/tests/<rule-id>/` | your rules' test fixtures |
| bundled | five `[Example]` rules (turn off with `TL_BUILTIN_RULES=false`) |

After editing, click **Rules → Reload rules**. Each rule's enabled/disabled
choice and its counters survive reloads. A file may contain several rules
separated by `---`.

## Log sources and fields

| Sigma `logsource` | Runs on | Field names you can use |
|---|---|---|
| `category: webserver` | web access logs (and any mapped JSON source with `category: webserver`) | Sigma names `c-ip`, `cs-method`, `cs-uri-stem`, `cs-uri-query`, `cs-uri`, `sc-status`, `cs-user-agent`, `cs-referer`, `cs-host`, `cs-username`, `cs-bytes`, `sc-bytes`, `time-taken`, `cs-cookie`; or ECS names (`url.path`, `source.ip` …) |
| `product: linux`, `service: auth` | auth.log / secure | `event.action`, `event.outcome`, `user.name`, `user.target.name`, `source.ip`, `process.name`, `process.command_line`, `group.name`, `message` … ([list](log-formats.md#linux-auth-linux-auth)) |
| `product: ecs`, `category: <c>` | ECS JSON application events with `event.category = c` | any ECS field present in your events |
| `product: windows`, `service: <s>` | that Windows channel (`security`, `system`, `sysmon`, `powershell` ...) | Windows names: `EventID`, `Channel`, `TargetUserName`, `IpAddress`, `LogonType`, `Image`, `CommandLine` ... ([list](log-formats.md#windows-event-logs-evtx)) |
| `product: windows`, `category: <c>` | every channel that can produce the category (see below) | Sysmon names (`Image`, `ParentImage`, `CommandLine`, `TargetObject` ...) |
| `product: <p>` (`service`, `category`) | JSON sources whose mapping declares that log source | the field names your mapping produces |

**Keywords** (values without a field, e.g. `keywords: ['Failed password']`) are
matched against `message` (Linux auth, JSON) or `url.original` (web).

String matching is case-insensitive, like Sigma. Supported modifiers include
`contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `exists`, `cased`,
`windash`, `base64`, `base64offset`, and numeric comparisons (`gt`, `lt` …).
The rule page shows the exact SQL ThreatLens runs.

## Example

```yaml
title: Admin Panel Accessed From Outside the Office Range
id: 6a5c2d8e-6f7b-4b8e-9a51-1d6a2f1c9e01
status: experimental
description: Successful requests to /admin from addresses outside 198.51.100.0/24.
references:
  - https://attack.mitre.org/techniques/T1078/
author: Your Name
date: 2026-11-08
tags:
  - attack.initial-access
  - attack.t1078
logsource:
  category: webserver
detection:
  admin:
    cs-uri-stem|startswith: /admin
    sc-status: 200
  office:
    c-ip|cidr: 198.51.100.0/24
  condition: admin and not office
falsepositives:
  - Administrators working remotely without the VPN
level: high
```

## Windows rules

Windows rules are compiled with pySigma's **official Windows and Sysmon
pipelines**, so SigmaHQ rules work as written:

- `service: security` (or `system`, `sysmon`, `powershell` ...) runs on that
  channel's table, with a `Channel = ...` condition.
- A generic `category` runs on every channel that can produce it:
  `process_creation` on Sysmon (EventID 1) **and** on Security (EventID 4688,
  with `Image` → `NewProcessName`, `ParentImage` → `ParentProcessName`);
  `network_connection`, `file_event`, `image_load`, `registry_*`, `dns_query`
  ... on Sysmon; `registry_*` also on Security 4657; `ps_script` (4104) and
  `ps_module` (4103) on PowerShell/Operational; `ps_classic_*` on Windows
  PowerShell.
- When a pipeline rejects a rule for one channel (for example a Sysmon-only
  field on Security 4657), the rule still runs on the others. The rule page
  shows the SQL per table, and "not applicable" for the rejected one.

```yaml
title: Failed Network Logon
id: 0c7a3f5e-2b8d-4e61-9f1a-7d3c2b9e8a41
status: experimental
description: A failed network logon (4625, logon type 3). Correlate it to find brute force.
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
author: Your Name
date: 2026-11-09
tags:
  - attack.credential-access
  - attack.t1110.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
  condition: selection
falsepositives:
  - A service with an expired password
level: low
```

Fixtures for Windows rules can be `tp.evtx` / `tn.evtx` files, or `tp.jsonl`
with records as `evtx_dump -o jsonl` writes them (see below).

## Required metadata (lint)

`threatlens rules lint` enforces, for every rule: a UUID `id`, `title`,
`description`, `author`, `date`, `level` (`informational`…`critical`), `tags`
including at least one ATT&CK technique (`attack.t1190`), `falsepositives` and
`references`. pySigma's own validators report style issues as warnings
(`--strict` turns them into errors).

## Testing rules (detection-as-code)

Create a folder named after the rule id, next to your rules:

```
/data/rules/tests/6a5c2d8e-6f7b-4b8e-9a51-1d6a2f1c9e01/
  tp.log     # every line MUST trigger the rule
  tn.log     # no line may trigger it
```

- `*.log` files hold **raw log lines**. They go through the same parsers as real
  ingestion (format auto-detected), so the test also proves that the fields your
  rule needs are extracted.
- `*.jsonl` files hold **events** as JSON objects with the stored field names
  (ECS), e.g. `{"event": {"category": "file", "action": "file-upload"}, "file": {"name": "x.php"}}`.
  A line holding a Windows record (`{"Event": {"System": ..., "EventData": ...}}`,
  as `evtx_dump -o jsonl` writes it) is parsed like an EVTX record instead.
- `*.evtx` files are Windows event logs: every record of `tp.evtx` must match,
  none of `tn.evtx`. Export a few events from Event Viewer (*Save Selected
  Events...*) to make one.

Run them:

```bash
docker exec threatlens threatlens rules test                 # bundled + your rules
threatlens rules test --dir my-rules --tests my-rules/tests --require-fixtures   # in CI
threatlens rules lint --dir my-rules
```

The Rules page shows each rule's test result after every reload. Write the
`tn` file with the near-misses you worry about: the bundled SQL-injection example
has `reunion%20selection` in its negatives for exactly that reason.

## Running a rule over old data

**Rule page → Retro-hunt** (or `threatlens rules hunt <rule-id>`) runs the rule
over everything stored. Events the rule already alerted on are never counted twice.

## Correlation rules

Thresholds, distinct counts and sequences across rules (and log sources):
see [correlation rules](correlation-rules.md).

## Alerts

Matches of one rule for the same source IP (or, if absent, user / host) within
`TL_ALERT_THROTTLE_MINUTES` (default 60) of event time become one alert with a
counter. The alert links to every matched event.

## Community rules

```bash
git clone https://github.com/SigmaHQ/sigma /tmp/sigma
docker cp /tmp/sigma threatlens:/data/tmp/sigma
docker exec threatlens threatlens rules import-sigmahq /data/tmp/sigma
```

This copies the SigmaHQ rules for log sources ThreatLens ingests into
`/data/rules/sigmahq/`, with the Detection Rule License notice. Keep the authors'
attribution if you share or modify them.
