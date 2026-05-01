CREATE TABLE users (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id  UUID NOT NULL DEFAULT uuidv7() UNIQUE,
    email      TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_email_format CHECK (
        length(email) BETWEEN 3 AND 254
        AND email LIKE '%@%'
        AND email = lower(email)
    ),
    CONSTRAINT users_name_length CHECK (length(name) BETWEEN 1 AND 200)
);

CREATE TRIGGER trigger_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();


CREATE TABLE magic_links (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE COLLATE "C" CHECK (length(token_hash) = 64),
    source_job_id UUID UNIQUE,                                 -- apalis job id, idempotencja
    email         TEXT NOT NULL,
    ip            INET NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT magic_links_email_format CHECK (
        length(email) BETWEEN 3 AND 254
        AND email LIKE '%@%'
        AND email = lower(email)
    ),
    CONSTRAINT magic_links_temporal CHECK (
        expires_at > created_at
        AND expires_at <= created_at + INTERVAL '15 minutes'
        AND (used_at IS NULL OR used_at >= created_at)
    )
);

CREATE INDEX idx_magic_links_email_created   ON magic_links (email, created_at);
CREATE INDEX idx_magic_links_ip_created      ON magic_links (ip, created_at) INCLUDE (email);
CREATE INDEX idx_magic_links_cleanup_expired ON magic_links (expires_at) WHERE used_at IS NULL;
CREATE INDEX idx_magic_links_cleanup_used    ON magic_links (used_at) WHERE used_at IS NOT NULL;

CREATE TRIGGER trigger_magic_links_no_update
BEFORE UPDATE OF token_hash, source_job_id, email, ip, expires_at, created_at ON magic_links
FOR EACH ROW EXECUTE FUNCTION deny_update();


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
