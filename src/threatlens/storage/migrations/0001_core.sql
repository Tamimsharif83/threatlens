-- 0001: users, sessions and the analyst audit log.
-- Event tables arrive with ingestion (Phase 1).

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'analyst')),
    disabled        INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at      INTEGER NOT NULL,           -- unix ms, UTC
    last_login_at   INTEGER
) STRICT;

-- Only a SHA-256 of the session token is stored, so a database leak
-- does not hand out live sessions.
CREATE TABLE sessions (
    token_hash      TEXT    PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token      TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    ip              TEXT,
    user_agent      TEXT
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,           -- unix ms, UTC
    actor           TEXT,                       -- username, or NULL for the system
    action          TEXT    NOT NULL,           -- e.g. auth.login.success
    target          TEXT,
    details         TEXT,                       -- JSON object
    ip              TEXT
) STRICT;
CREATE INDEX audit_log_ts ON audit_log(ts);
