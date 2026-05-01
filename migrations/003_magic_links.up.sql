CREATE TABLE magic_links (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash      TEXT NOT NULL UNIQUE COLLATE "C" CHECK (length(token_hash) = 64),
    code_hash       TEXT NOT NULL COLLATE "C" CHECK (length(code_hash) = 64),
    link_attempts   INT NOT NULL DEFAULT 0 CHECK (link_attempts >= 0 AND link_attempts <= 10),
    code_attempts   INT NOT NULL DEFAULT 0 CHECK (code_attempts >= 0 AND code_attempts <= 10),
    email           TEXT NOT NULL,
    ip              INET NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    code_expires_at TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
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
    )
);

CREATE INDEX idx_magic_links_email_created   ON magic_links (email, created_at DESC);
CREATE INDEX idx_magic_links_ip_created      ON magic_links (ip, created_at DESC) INCLUDE (email);
CREATE INDEX idx_magic_links_cleanup_expired ON magic_links (expires_at) WHERE used_at IS NULL;
CREATE INDEX idx_magic_links_cleanup_used    ON magic_links (used_at) WHERE used_at IS NOT NULL;
