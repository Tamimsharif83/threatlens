# Supported log formats

ThreatLens parses each line into a normalized event (see [schema.md](schema.md)).
Choose the type explicitly, or let `auto` detect it from the first 50 lines (it
needs at least 60% of them to match one format).

| Type (`--type`) | Input | Sigma log source | Event table |
|---|---|---|---|
| `apache`, `nginx` | access logs: combined, common, or a custom format | `category: webserver` | `ev_webserver` |
| `ecs-json` | JSON Lines with Elastic Common Schema names | `product: ecs`, `category: <event.category>` | `ev_ecs` |
| `linux-auth` | `auth.log` / `secure` | `product: linux`, `service: auth` | `ev_linux_auth` |
| `json` | any JSON Lines, optionally with a field mapping | from the mapping (default `product: json`) | `ev_<product>_<service>_<category>` |
| `evtx` | Windows `.evtx` files, or their records as JSON Lines (`evtx_dump -o jsonl`) | `product: windows`, `service: <channel>` | `ev_windows_<service>` |

Files can be plain text, `.evtx`, `.gz`, or `.zip` (members may themselves be `.gz`).
Lines longer than 1 MiB, and lines a parser cannot read, are counted as
**malformed**. They never stop an ingest, and the first 20 are shown in the
ingest report.

Ways in:

- **Web UI:** *Ingest → Upload logs* (drag & drop, several files at once)
- **CLI:** `threatlens ingest <file|dir>... [--type T] [--tz Zone] [--source-name N] [--format F] [--mapping M.yaml]`
- **Watch folder:** put files in `/data/inbox`. A sub-folder name becomes the source
  name (`/data/inbox/web-prod/access.log` → source `web-prod`).

## Web server access logs (`apache`, `nginx`)

Auto-detected: **combined** and **common**. Extra fields after the combined format
(e.g. a request time appended to each line) are tolerated.

```text
203.0.113.7 - alice [10/Oct/2026:13:55:36 +0000] "GET /a.php?id=1 HTTP/1.1" 200 2326 "https://ref/" "Mozilla/5.0"
```

Presets for `--format`: `combined`, `common`, `vhost_combined`. Or give your
server's own format string, in **Apache `LogFormat`** or **Nginx `log_format`** syntax:

```bash
threatlens ingest access.log --type nginx \
  --format '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time'
threatlens ingest access.log --type apache --format '%v %a %l %u %t "%r" %>s %B %D "%{X-Forwarded-For}i"'
```

| Field | Apache | Nginx |
|---|---|---|
| `source.ip` | `%h`, `%a` | `$remote_addr` |
| `user.name` | `%u` | `$remote_user` |
| time | `%t` | `$time_local`, `$time_iso8601`, `$msec` |
| `url.original` + method, path, query, version | `%r` | `$request` |
| `http.request.method` | `%m` | `$request_method` |
| `url.path` / `url.query` | `%U` / `%q` | `$uri` / `$args` (or `$request_uri`) |
| `http.response.status_code` | `%>s` | `$status` |
| `http.response.body.bytes` | `%b`, `%B` | `$body_bytes_sent` |
| `http.request.referrer` | `%{Referer}i` | `$http_referer` |
| `user_agent.original` | `%{User-Agent}i` | `$http_user_agent` |
| `event.duration` (ns) | `%D` (µs), `%T` (s) | `$request_time` (s) |
| `url.domain` | `%v`, `%V` | `$host`, `$server_name` |
| `http.request.id` | `%L` | `$request_id` |
| other request headers | `%{Name}i` → `http.request.headers.name` | `$http_name` |

Values are stored **as logged** (no URL decoding), because Sigma webserver rules
are written against logged values. Rules may use the Sigma names `cs-method`,
`cs-uri-stem`, `cs-uri-query`, `c-ip`, `sc-status`, `cs-user-agent` and
`cs-referer`; they are mapped to the ECS fields above when rules are compiled (Phase 2).

## ECS JSON Lines (`ecs-json`)

One JSON object per line, nested or dotted, with a required `@timestamp`
(ISO-8601 or epoch). Unknown fields are kept and searchable.

```json
{"@timestamp":"2026-01-05T08:00:00.120Z","event":{"category":["authentication"],"action":"user-login","outcome":"failure"},"user":{"name":"admin"},"source":{"ip":"203.0.113.66"},"url":{"path":"/api/v1/login"},"http":{"request":{"method":"POST","id":"req-17"},"response":{"status_code":401}}}
```

Recognised fields include `event.kind`, `event.category`, `event.type`,
`event.action`, `event.outcome`, `event.dataset`, `event.duration`,
`http.request.id`, `http.request.method`, `http.request.referrer`,
`http.request.body.content`, `http.request.body.bytes`, `http.request.mime_type`,
`http.response.status_code`, `http.response.body.bytes`, `url.original`,
`url.path`, `url.query`, `source.ip`, `source.port`, `user_agent.original`,
`user.name`, `user.id`, `file.name`, `file.path`, `file.size`, `file.mime_type`,
`file.hash.sha256`, `process.command_line`, `destination.ip`,
`destination.domain`, `error.type`, `error.message`, `service.name`, and `host.name`.

Single-element arrays (ECS `event.category: ["web"]`) are stored as the plain
value so rules can match `event.category: web`. Longer arrays are stored as JSON
text.

## Linux auth (`linux-auth`)

Headers: RFC 3164 (`Nov  8 10:00:00 host proc[pid]: msg`; the year is taken from
the file's modification time, with December logs read in January placed in the
previous year), ISO / rsyslog high-precision timestamps, and RFC 5424. Timestamps
without an offset use the source's timezone (`--tz`, or the default in Settings).

Every line keeps `message`, `process.name`, `process.pid` and `host.hostname`.
Recognised messages also get structured fields:

| Program | Messages | `event.action` |
|---|---|---|
| sshd | Accepted / Failed *method* for *user* from *ip* | `ssh_login` (success/failure) |
| sshd | Invalid user, maximum authentication attempts, Did not receive identification | `ssh_invalid_user`, `ssh_max_auth_attempts`, `ssh_no_identification` |
| sshd | Connection closed / Disconnected / Received disconnect | `ssh_disconnect` |
| any (PAM) | `pam_unix(x:auth): authentication failure` | `authentication_failure` |
| any (PAM) | `pam_unix(x:session): session opened/closed` | `session_opened`, `session_closed` |
| sudo | `user : TTY=… ; PWD=… ; USER=… ; COMMAND=…` (with failure reasons) | `sudo_command` |
| su | Successful / FAILED su | `su` |
| useradd, usermod, userdel, groupadd, passwd | new user / group, add to group, delete, password change, lock | `user_created`, `group_created`, `user_added_to_group`, `user_deleted`, `password_changed`, `user_locked` |
| CRON | `(user) CMD (command)` | `cron_command` |
| systemd-logind | New / Removed session | `session_opened`, `session_closed` |

Fields used: `user.name`, `user.target.name`, `source.ip`, `source.port`,
`process.command_line`, `process.working_directory`, `group.name`,
`event.outcome`, `event.reason`, plus `linux.*` extras (auth method, TTY, PAM service).

## Generic JSON Lines (`json`) and field mappings

Without a mapping, keys are kept as they are (nested objects flattened to dotted
names) and the timestamp is taken from the first of `@timestamp`, `timestamp`,
`time`, `ts`, `date`, `datetime`, `eventTime`.

A **mapping file** (YAML) renames fields to ECS, says where the timestamp is,
and assigns a Sigma log source. Put mapping files in `/data/mappings/` to choose
them in the UI, or pass `--mapping file.yaml` to the CLI. Examples are in
[`examples/mappings/`](../examples/mappings/).

```yaml
name: shop-api                 # becomes event.dataset
logsource:                     # Sigma log source -> event table ev_shop_api
  product: shop
  service: api
timestamp:
  field: ts                    # dotted path into the JSON
  format: epoch_ms             # auto | iso8601 | epoch | epoch_s | epoch_ms | epoch_us | epoch_ns | strptime pattern
  timezone: UTC                # only for formats without an offset
fields:                        # source key -> ECS field
  client.ip: source.ip
  req.method: http.request.method
  req.path: url.path
  status: http.response.status_code
  actor: user.name
keep_unmapped: true            # keep other keys as they are (default true)
constants:                     # fields added to every event
  event.category: web
```

## Windows event logs (`evtx`)

Upload `.evtx` files as they are (also inside `.zip` or as `.evtx.gz`), drop
them in the watch folder, or use `threatlens ingest Security.evtx`. EVTX is
recognised by its header, so `--type` is not needed. JSON Lines written by
`evtx_dump -o jsonl` (one `{"Event": {...}}` record per line) are auto-detected
too.

The **channel** decides the log source and the table, using the same channel
names as pySigma's official Windows pipeline:

| Channel | Sigma log source | Table |
|---|---|---|
| `Security` | `product: windows, service: security` | `ev_windows_security` |
| `System` | `service: system` | `ev_windows_system` |
| `Application` | `service: application` | `ev_windows_application` |
| `Microsoft-Windows-Sysmon/Operational` | `service: sysmon` | `ev_windows_sysmon` |
| `Microsoft-Windows-PowerShell/Operational`, `PowerShellCore/Operational` | `service: powershell` | `ev_windows_powershell` |
| `Windows PowerShell` | `service: powershell-classic` | `ev_windows_powershell_classic` |
| other channels pySigma knows (TaskScheduler, WMI, Defender ...) | `service: <name>` | `ev_windows_<name>` |
| anything else | `product: windows` | `ev_windows` |

**Fields** are named the way Sigma's Windows rules expect:

- System values: `EventID` (a number), `Channel`, `Computer`, `Provider_Name`,
  `Provider_Guid`, `Level`, `Task`, `Opcode`, `Keywords`, `EventRecordID`,
  `Version`, `ExecutionProcessID`, `ExecutionThreadID`, `UserID`, `ActivityID`.
- `EventData` and `UserData` values under their own names: `TargetUserName`,
  `IpAddress`, `LogonType`, `Image`, `CommandLine`, `ParentImage`,
  `ScriptBlockText`, `ServiceName` ... Unnamed data (classic PowerShell, many
  System events) is joined into `Data`. If an event reuses a System name in its
  data, the System value is kept as `System_<name>`.
- ECS fields added for alert grouping, pivots, IOCs and the case timeline:
  `host.name` (Computer), `user.name` (TargetUserName, SubjectUserName or User),
  `source.ip` (IpAddress, SourceIp ...), `destination.ip`, `event.code`,
  `event.action` (`logon-failed`, `process-created` ...), `process.executable`,
  `process.name`, `process.command_line`, `file.path`, `file.name`,
  `file.hash.md5/sha1/sha256` (from Sysmon `Hashes`), `dns.question.name`.

The time is `TimeCreated/SystemTime` (UTC). Records the reader cannot decode (a
damaged chunk, a cleared log) are counted as malformed, with the reason, and the
rest of the file is still read. Records are deduplicated like log lines, so
ingesting a newer copy of the same log only adds the new records. In the watch
folder an `.evtx` file is read whole once it stops changing, and again when a
newer copy replaces it.

## Timezones

Everything is stored in UTC. A line's own offset always wins. Otherwise the
timezone comes from, in order: `--tz` / the upload form, the source's saved
timezone, and the default in *Settings* (`TL_DEFAULT_TIMEZONE`).
