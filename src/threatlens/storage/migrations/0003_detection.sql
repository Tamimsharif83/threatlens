-- 0003: Sigma rules, alerts and the events they reference.

-- One row per loaded rule (keyed by the Sigma rule id). Rebuilt on every reload;
-- `enabled` and the counters survive reloads.
CREATE TABLE rules (
    id              TEXT    PRIMARY KEY,        -- Sigma rule id (UUID)
    title           TEXT    NOT NULL,
    kind            TEXT    NOT NULL CHECK (kind IN ('detection', 'correlation')),
    origin          TEXT    NOT NULL CHECK (origin IN ('builtin', 'user')),
    path            TEXT    NOT NULL,           -- file it was loaded from (display only)
    level           TEXT,
    status          TEXT,                       -- Sigma status: stable, test, experimental ...
    description     TEXT,
    author          TEXT,
    tags            TEXT    NOT NULL DEFAULT '[]',  -- JSON list
    logsource       TEXT    NOT NULL DEFAULT '{}',  -- JSON object
    yaml            TEXT    NOT NULL,
    sha256          TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    load_error      TEXT,                       -- why it cannot run (NULL = ok)
    warnings        TEXT    NOT NULL DEFAULT '[]',  -- JSON list of validator warnings
    test_status     TEXT,                       -- pass | fail | none
    test_message    TEXT,
    tested_at       INTEGER,
    hits            INTEGER NOT NULL DEFAULT 0, -- matched events, all time
    alerts          INTEGER NOT NULL DEFAULT 0, -- alerts created, all time
    last_fired_at   INTEGER,
    loaded_at       INTEGER NOT NULL,
    updated_by      TEXT
) STRICT;

-- Files that could not be parsed at all (no rule id to key them by).
CREATE TABLE rule_load_errors (
    path            TEXT    PRIMARY KEY,
    error           TEXT    NOT NULL,
    seen_at         INTEGER NOT NULL
) STRICT;

CREATE TABLE alerts (
    id              INTEGER PRIMARY KEY,
    rule_id         TEXT    NOT NULL,           -- not a FK: alerts outlive deleted rules
    rule_title      TEXT    NOT NULL,
    level           TEXT    NOT NULL,
    tags            TEXT    NOT NULL DEFAULT '[]',
    origin          TEXT    NOT NULL CHECK (origin IN ('ingest', 'retro')),
    group_key       TEXT    NOT NULL,           -- rule id + entity values (grouping/throttle)
    entities        TEXT    NOT NULL DEFAULT '{}',  -- JSON: source.ip, user.name, host.name ...
    first_seen      INTEGER NOT NULL,           -- event time (ms)
    last_seen       INTEGER NOT NULL,
    event_count     INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new', 'in_progress', 'closed')),
    resolution      TEXT    CHECK (resolution IN ('true_positive', 'false_positive',
                                                  'benign_true_positive')),
    assignee        TEXT,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX alerts_group ON alerts(group_key, last_seen);
CREATE INDEX alerts_status ON alerts(status, level);
CREATE INDEX alerts_rule ON alerts(rule_id);
CREATE INDEX alerts_created ON alerts(created_at);

-- Events behind an alert: references, not copies. Keyed by rule + event, so the
-- same rule never alerts twice on one event (retro-hunts can re-scan safely).
CREATE TABLE alert_events (
    rule_id         TEXT    NOT NULL,
    table_name      TEXT    NOT NULL,
    event_id        INTEGER NOT NULL,
    alert_id        INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_ts        INTEGER NOT NULL,
    PRIMARY KEY (rule_id, table_name, event_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX alert_events_alert ON alert_events(alert_id, event_ts);
