-- Partial index supporting the verify_by_code subselect (store/verify.rs):
--   SELECT id FROM magic_links
--    WHERE email = $1
--      AND used_at IS NULL
--      AND code_burned_at IS NULL
--      AND code_expires_at > NOW()
--    ORDER BY created_at DESC LIMIT 1
--
-- The existing idx_magic_links_email_created covers email+created_at sort, but
-- the planner still has to recheck `used_at IS NULL AND code_burned_at IS NULL`
-- per row. A partial index with those predicates baked in lets the planner pick
-- exactly the live rows and read ORDER BY straight from the index. For hot
-- email addresses this avoids touching dead rows during verify.

CREATE INDEX IF NOT EXISTS idx_magic_links_email_live_code
    ON magic_links (email, created_at DESC)
    WHERE used_at IS NULL AND code_burned_at IS NULL;
