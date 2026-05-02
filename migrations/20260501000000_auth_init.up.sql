-- Single consolidated migration for auth_rust v0.1.0.
-- Creates: helpers (set_updated_at, deny_update functions), users, magic_links, sessions, auth_verify_attempts.
-- Timestamp prefix is intentional: avoids version-space collision with consumer migrations
-- (sqlx tracks all migrators in a single _sqlx_migrations table by integer version).

-- ───────────────────────────── helpers ─────────────────────────────

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION deny_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'updates are not allowed on table "%"', TG_TABLE_NAME;
END;
$$;

-- ───────────────────────────── users ───────────────────────────────

CREATE TABLE users (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id  UUID NOT NULL DEFAULT uuidv7() UNIQUE,
    email      TEXT NOT NULL UNIQUE,
    status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_email_format CHECK (
        length(email) BETWEEN 3 AND 254
        AND email LIKE '%@%'
        AND email = lower(email)
    )
);

CREATE TRIGGER trigger_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ──────────────────────────── magic_links ──────────────────────────

-- `used_at` is set on successful verification (either path).
-- `code_burned_at` is set when the 6-digit code path is invalidated by 5 wrong
--   attempts; it does NOT affect the link path (token still works from email).
-- The split prevents an attacker who knows only the email from knocking out the
-- magic link by burning the code.
CREATE TABLE magic_links (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash      TEXT NOT NULL UNIQUE COLLATE "C" CHECK (length(token_hash) = 64),
    code_hash       TEXT NOT NULL COLLATE "C" CHECK (length(code_hash) = 64),
    -- Upper bound on attempts is enforced by the lib via `cfg.link_attempts_per_token` /
    -- `cfg.code_attempts_per_row` at INSERT/UPDATE time. DB only enforces non-negative —
    -- config is the single source of truth, no magic numbers in schema.
    link_attempts   INT NOT NULL DEFAULT 0 CHECK (link_attempts >= 0),
    code_attempts   INT NOT NULL DEFAULT 0 CHECK (code_attempts >= 0),
    email           TEXT NOT NULL,
    ip              INET NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    code_expires_at TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    code_burned_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT magic_links_email_format CHECK (
        length(email) BETWEEN 3 AND 254
        AND email LIKE '%@%'
        AND email = lower(email)
    ),
    CONSTRAINT magic_links_temporal CHECK (
        expires_at > created_at
        AND code_expires_at > created_at
        AND code_expires_at <= expires_at
        AND (used_at IS NULL OR used_at >= created_at)
        AND (code_burned_at IS NULL OR code_burned_at >= created_at)
    )
);

CREATE INDEX idx_magic_links_email_created   ON magic_links (email, created_at DESC);
CREATE INDEX idx_magic_links_ip_created      ON magic_links (ip, created_at DESC) INCLUDE (email);
CREATE INDEX idx_magic_links_cleanup_expired ON magic_links (expires_at) WHERE used_at IS NULL;
CREATE INDEX idx_magic_links_cleanup_used    ON magic_links (used_at) WHERE used_at IS NOT NULL;
-- Live-row dedup on issue: "any row exists for this email where the link is still usable".
CREATE INDEX idx_magic_links_email_live      ON magic_links (email, expires_at) WHERE used_at IS NULL;

-- ───────────────────────────── sessions ────────────────────────────

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

-- ────────────────────── auth_verify_attempts (rate limit) ──────────

CREATE TABLE auth_verify_attempts (
    ip           INET NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verify_attempts_ip_time ON auth_verify_attempts (ip, attempted_at DESC);
-- Helps the inline `DELETE WHERE attempted_at < NOW() - INTERVAL '5 minutes'` that runs
-- on every verify_rate_check_ip call (verify.rs).
CREATE INDEX idx_verify_attempts_attempted_at ON auth_verify_attempts (attempted_at);

-- ────────────────────── auth_email_blocks ──────────────────────────
-- Per-email block list: when a single email exceeds the per-email issue cap in the
-- rolling window, we insert a row here that prevents further mails to that address
-- until expires_at. Multi-row per email = history (used for cleanup and audit).

CREATE TABLE auth_email_blocks (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email      TEXT NOT NULL,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT auth_email_blocks_temporal CHECK (expires_at >= blocked_at),
    CONSTRAINT auth_email_blocks_email_format CHECK (
        length(email) BETWEEN 3 AND 254
        AND email LIKE '%@%'
        AND email = lower(email)
    )
);

CREATE INDEX idx_auth_email_blocks_active ON auth_email_blocks (email, expires_at);

-- ────────────────────── auth_ip_blocks ─────────────────────────────
-- Per-IP block list. expires_at = 'infinity' means PERMANENT (escalation: an IP
-- that gets blocked more than `ip_permanent_block_threshold` times in 24h gets
-- a permanent block on next trigger). Multi-row per IP for history; "active"
-- block = any row where expires_at > NOW().

CREATE TABLE auth_ip_blocks (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip         INET NOT NULL,
    blocked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT auth_ip_blocks_temporal CHECK (expires_at >= blocked_at)
);

CREATE INDEX idx_auth_ip_blocks_active ON auth_ip_blocks (ip, expires_at);
