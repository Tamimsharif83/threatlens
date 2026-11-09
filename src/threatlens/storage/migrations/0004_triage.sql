-- 0004: triage (notes), tuning (suppressions, Sigma filters), saved hunts.

CREATE TABLE alert_notes (
    id              INTEGER PRIMARY KEY,
    alert_id        INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author          TEXT    NOT NULL,
    body            TEXT    NOT NULL,
    created_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX alert_notes_alert ON alert_notes(alert_id, id);

-- Allowlist entries: matches where <field> equals <value> (case-insensitive) do
-- not create alerts. rule_id NULL means every rule.
CREATE TABLE suppressions (
    id              INTEGER PRIMARY KEY,
    rule_id         TEXT,
    field           TEXT    NOT NULL,
    value           TEXT    NOT NULL,
    reason          TEXT    NOT NULL CHECK (length(trim(reason)) > 0),
    created_by      TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER,
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    hits            INTEGER NOT NULL DEFAULT 0,
    last_hit_at     INTEGER
) STRICT;
CREATE INDEX suppressions_rule ON suppressions(rule_id);

-- Sigma filter documents (meta-rules that add exclusions to detection rules).
CREATE TABLE sigma_filters (
    id              TEXT    PRIMARY KEY,
    title           TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    yaml            TEXT    NOT NULL,
    sha256          TEXT    NOT NULL,
    load_error      TEXT,
    loaded_at       INTEGER NOT NULL
) STRICT;

CREATE TABLE saved_hunts (
    id              INTEGER PRIMARY KEY,
    name            TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    description     TEXT,
    attack_tag      TEXT,
    sql             TEXT    NOT NULL,
    created_by      TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;

ALTER TABLE rules ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0;
CREATE INDEX audit_log_target ON audit_log(target, id);
CREATE INDEX alerts_assignee ON alerts(assignee, status);
