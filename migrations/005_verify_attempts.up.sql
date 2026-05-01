CREATE TABLE auth_verify_attempts (
    ip INET NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_verify_attempts_ip_time ON auth_verify_attempts (ip, attempted_at DESC);
