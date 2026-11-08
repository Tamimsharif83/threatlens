-- 0002: ingestion bookkeeping, event-table catalog, watch-folder state,
-- runtime settings and forced password changes.
-- Event tables themselves (ev_*) are created on demand by storage/events.py.

ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0
    CHECK (must_change_password IN (0, 1));

-- Settings changed from the UI; override the TL_* environment defaults.
CREATE TABLE app_settings (
    key             TEXT    PRIMARY KEY,
    value           TEXT    NOT NULL,
    updated_at      INTEGER NOT NULL,
    updated_by      TEXT
) STRICT;

-- A named log source (e.g. "web-prod", "bastion-auth").
CREATE TABLE sources (
    id              INTEGER PRIMARY KEY,
    name            TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    parser          TEXT    NOT NULL,
    timezone        TEXT,                       -- for timestamps without an offset
    options         TEXT    NOT NULL DEFAULT '{}',  -- JSON: custom web format, mapping name
    created_at      INTEGER NOT NULL,
    last_event_at   INTEGER
) STRICT;

-- zstd dictionaries used to compress raw lines (TL_STORE_RAW=true).
CREATE TABLE raw_dicts (
    id              INTEGER PRIMARY KEY,
    dict            BLOB    NOT NULL,
    created_at      INTEGER NOT NULL
) STRICT;

-- One ingestion of one file (or one archive member, or one day of a watched file).
CREATE TABLE ingest_batches (
    id                  INTEGER PRIMARY KEY,
    source_id           INTEGER NOT NULL REFERENCES sources(id),
    origin              TEXT    NOT NULL CHECK (origin IN ('upload', 'cli', 'watch')),
    file_name           TEXT    NOT NULL,
    parser              TEXT    NOT NULL,
    status              TEXT    NOT NULL CHECK (status IN ('running', 'done', 'failed')),
    started_at          INTEGER NOT NULL,
    finished_at         INTEGER,
    bytes_read          INTEGER NOT NULL DEFAULT 0,
    lines_total         INTEGER NOT NULL DEFAULT 0,
    events_inserted     INTEGER NOT NULL DEFAULT 0,
    duplicates          INTEGER NOT NULL DEFAULT 0,
    malformed           INTEGER NOT NULL DEFAULT 0,
    malformed_samples   TEXT    NOT NULL DEFAULT '[]',  -- JSON list, first N only
    min_ts              INTEGER,
    max_ts              INTEGER,
    error               TEXT,
    created_by          TEXT,
    raw_dict_id         INTEGER REFERENCES raw_dicts(id)
) STRICT;
CREATE INDEX ingest_batches_source ON ingest_batches(source_id, id);
CREATE INDEX ingest_batches_finished ON ingest_batches(finished_at);

-- Which event tables a batch wrote to, with the id range of its rows.
CREATE TABLE ingest_batch_tables (
    batch_id        INTEGER NOT NULL REFERENCES ingest_batches(id) ON DELETE CASCADE,
    table_name      TEXT    NOT NULL,
    min_id          INTEGER NOT NULL,
    max_id          INTEGER NOT NULL,
    events          INTEGER NOT NULL,
    PRIMARY KEY (batch_id, table_name)
) STRICT, WITHOUT ROWID;

-- Catalog of event tables (one per Sigma log source) and their fields.
CREATE TABLE event_tables (
    table_name      TEXT    PRIMARY KEY,
    category        TEXT,
    product         TEXT,
    service         TEXT,
    created_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE event_fields (
    table_name      TEXT    NOT NULL REFERENCES event_tables(table_name) ON DELETE CASCADE,
    field           TEXT    NOT NULL,
    sql_type        TEXT    NOT NULL,
    first_seen      INTEGER NOT NULL,
    PRIMARY KEY (table_name, field)
) STRICT, WITHOUT ROWID;

-- Watch-folder follow state, so restarts resume where they stopped.
CREATE TABLE watch_files (
    path            TEXT    PRIMARY KEY,
    dev             INTEGER NOT NULL,
    inode           INTEGER NOT NULL,
    head_hash       TEXT    NOT NULL,           -- hash of the first bytes: detects inode reuse
    offset          INTEGER NOT NULL,           -- bytes consumed (always at a line boundary)
    size            INTEGER NOT NULL,
    mtime_ns        INTEGER NOT NULL,
    parser          TEXT,
    source_id       INTEGER REFERENCES sources(id),
    done            INTEGER NOT NULL DEFAULT 0, -- archives are ingested once
    updated_at      INTEGER NOT NULL
) STRICT;
