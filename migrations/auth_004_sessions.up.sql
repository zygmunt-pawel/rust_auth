CREATE TABLE sessions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id           UUID NOT NULL DEFAULT uuidv7() UNIQUE,
    session_token_hash  TEXT NOT NULL UNIQUE COLLATE "C" CHECK (length(session_token_hash) = 64),
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at          TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent          TEXT,
    ip                  INET,

    CONSTRAINT sessions_temporal CHECK (
        expires_at > created_at
        AND last_seen_at >= created_at
        AND absolute_expires_at > created_at
        AND absolute_expires_at >= expires_at
    ),
    CONSTRAINT sessions_user_agent_length CHECK (user_agent IS NULL OR length(user_agent) <= 1024)
);

CREATE INDEX idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
