# Reference migrations

Snapshot of the migrations from the original `auth_rust` prototype
(`~/Desktop/auth_rust/migrations/` as of 2026-05-01). **Not** the migrations
the library will ship — kept here as reference while writing the actual
`migrations/` directory.

Differences the library version needs vs. these reference files:

- prefix file names with `auth_` (e.g. `auth_001_helpers.up.sql`) so they
  sort distinctly from consumer migrations
- `magic_links`: add `code_hash TEXT NOT NULL` (argon2id PHC string),
  `code_attempts INT NOT NULL DEFAULT 0`, `code_expires_at TIMESTAMPTZ NOT NULL`
  (shorter than `expires_at`); drop `source_job_id` (apalis is gone)
- `users`: keep minimal (id, public_id, email, status, created_at, updated_at);
  consumer extends via own `user_profiles` table
- `sessions`: unchanged in shape (sliding + absolute TTL, user_agent, ip)
