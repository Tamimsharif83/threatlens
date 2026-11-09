-- 0006: cases (investigations), their alerts, notes, timeline annotations and IOCs.

CREATE TABLE cases (
    id              INTEGER PRIMARY KEY,
    title           TEXT    NOT NULL,
    description     TEXT,
    severity        TEXT    NOT NULL DEFAULT 'medium'
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status          TEXT    NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'investigating', 'contained', 'closed')),
    assignee        TEXT,
    created_by      TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    closed_at       INTEGER,
    -- Analyst-written report sections (Markdown).
    summary         TEXT,
    scope           TEXT,
    impact          TEXT,
    root_cause      TEXT,
    recommendations TEXT,
    appendix        TEXT
) STRICT;
CREATE INDEX cases_status ON cases(status, updated_at);

CREATE TABLE case_alerts (
    case_id         INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    alert_id        INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    added_by        TEXT    NOT NULL,
    added_at        INTEGER NOT NULL,
    PRIMARY KEY (case_id, alert_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX case_alerts_alert ON case_alerts(alert_id);

CREATE TABLE case_notes (
    id              INTEGER PRIMARY KEY,
    case_id         INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author          TEXT    NOT NULL,
    body            TEXT    NOT NULL,
    created_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX case_notes_case ON case_notes(case_id, id);

-- Annotations placed on the timeline at an event time ("attacker pivots to host B").
CREATE TABLE case_annotations (
    id              INTEGER PRIMARY KEY,
    case_id         INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    ts              INTEGER NOT NULL,           -- event time (ms, UTC)
    author          TEXT    NOT NULL,
    body            TEXT    NOT NULL,
    created_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX case_annotations_case ON case_annotations(case_id, ts);

CREATE TABLE case_iocs (
    id              INTEGER PRIMARY KEY,
    case_id         INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind            TEXT    NOT NULL
                    CHECK (kind IN ('ip', 'domain', 'url', 'user_agent', 'user', 'file_hash',
                                    'file_name', 'other')),
    value           TEXT    NOT NULL,
    origin          TEXT    NOT NULL CHECK (origin IN ('auto', 'manual')),
    note            TEXT,
    occurrences     INTEGER NOT NULL DEFAULT 0,
    first_seen      INTEGER,
    last_seen       INTEGER,
    added_by        TEXT,
    added_at        INTEGER NOT NULL,
    UNIQUE (case_id, kind, value)
) STRICT;
