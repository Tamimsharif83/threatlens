# Event schema

ThreatLens stores events in one table per Sigma log source (see
[ADR-0002](adr/0002-storage-engine-and-event-layout.md)). Field names follow the
[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
wherever ECS has a name for the value. Fields that ECS does not cover keep a
descriptive dotted name (e.g. `linux.auth.method`).

## Event tables

| Table | Sigma log source | Filled by |
|---|---|---|
| `ev_webserver` | `category: webserver` | `apache`, `nginx` |
| `ev_linux_auth` | `product: linux`, `service: auth` | `linux-auth` |
| `ev_ecs` | `product: ecs` (+ `category` = `event.category`) | `ecs-json` |
| `ev_json` | `product: json` | `json` without a mapping |
| `ev_<product>_<service>_<category>` | as declared in the mapping | `json` with a mapping |

## Columns

Every table has these provenance columns (the `tl_` prefix is reserved):

| Column | Type | Meaning |
|---|---|---|
| `tl_id` | INTEGER PK | event id (alerts and cases reference events by table + id) |
| `tl_ts` | INTEGER | event time, UTC unix **milliseconds** |
| `tl_batch` | INTEGER | ingest batch (→ `ingest_batches`: source, file, origin, user) |
| `tl_record` | INTEGER | line number within the file / archive member |
| `tl_hash` | INTEGER UNIQUE | 64-bit dedup key (see [ADR-0004](adr/0004-ingestion-pipeline.md)) |
| `tl_raw` | BLOB | the original line, zstd-compressed, only with `TL_STORE_RAW=true` |
| `tl_extra` | TEXT (JSON) | fields that could not become columns (see below) |

Then **one column per field**, named exactly like the field (`"url.path"`,
`"source.ip"` …; always double-quoted in SQL). Columns are added the first time a
field appears. The column type follows the first value seen: `INTEGER`, `REAL` or
`TEXT`, all with `COLLATE NOCASE`, because Sigma string matching is
case-insensitive. Booleans are stored as `'true'`/`'false'`. Lists and objects
are stored as JSON text, except that a list with one scalar element is stored as
that value.

A field goes to `tl_extra` (JSON) instead of a column when:

- its name is not a simple dotted identifier (letters, digits, `_ @ . - : /`, ≤ 128 chars),
- it starts with the reserved `tl_` prefix,
- it differs from an existing column only by letter case (SQLite column names are
  case-insensitive), or
- the table already has 400 field columns. This stops hostile JSON with random
  keys from creating thousands of columns.

`tl_extra` stays queryable: `json_extract(tl_extra, '$."weird key"')`.

Indexes: `tl_ts`, `tl_hash`, plus `source.ip`, `destination.ip`, `user.name` and
`host.name` (pivot fields), each created when its column first appears.

## Catalog tables

| Table | Contents |
|---|---|
| `event_tables` | each event table and its Sigma log source |
| `event_fields` | each field (column) per table, its type, and when it was first seen |
| `sources` | named sources: detected type, timezone override, options, newest event |
| `ingest_batches` | one per file / archive member / watched file per day: origin, counts, malformed samples, status, error |
| `ingest_batch_tables` | per batch and table: event count and the `tl_id` range |
| `raw_dicts` | zstd dictionaries for `tl_raw` |
| `watch_files` | watch-folder follow state (inode, offset, fingerprint) |

## Common fields by source

| Field | web | linux auth | ECS app |
|---|---|---|---|
| `source.ip` | ✓ | ✓ (ssh, PAM rhost) | ✓ |
| `user.name` | ✓ (`%u`) | ✓ | ✓ |
| `url.original`, `url.path`, `url.query` | ✓ | | ✓ |
| `http.request.method`, `http.response.status_code` | ✓ | | ✓ |
| `user_agent.original`, `http.request.referrer` | ✓ | | ✓ |
| `event.action`, `event.outcome`, `event.category` | `web` | ✓ | ✓ |
| `process.command_line` | | ✓ (sudo, cron) | ✓ |
| `host.name` / `host.hostname` | (`url.domain`) | ✓ | ✓ |
| `message` | | ✓ | if present |
