-- 0005: correlation alerts and their links to child alerts.

ALTER TABLE alerts ADD COLUMN kind TEXT NOT NULL DEFAULT 'detection'
    CHECK (kind IN ('detection', 'correlation'));
-- Correlation details: {"type", "value", "window_start", "window_end", "timespan"}.
ALTER TABLE alerts ADD COLUMN metric TEXT;

-- A correlation alert (parent) and the base-rule alerts on the same events (children).
CREATE TABLE alert_links (
    parent_id       INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    child_id        INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_id, child_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX alert_links_child ON alert_links(child_id);

-- 1 when a detection rule is only used by correlations with generate: false,
-- so it must not create alerts on its own (Sigma v2 semantics).
ALTER TABLE rules ADD COLUMN correlation_only INTEGER NOT NULL DEFAULT 0
    CHECK (correlation_only IN (0, 1));

-- The Sigma `name` of a rule (correlations reference rules by name or id).
ALTER TABLE rules ADD COLUMN name TEXT;
CREATE INDEX rules_name ON rules(name);
