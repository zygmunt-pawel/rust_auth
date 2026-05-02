-- Reverse 20260501000000_auth_init.up.sql in dependency order.

DROP TABLE IF EXISTS auth_ip_blocks;
DROP TABLE IF EXISTS auth_email_blocks;
DROP TABLE IF EXISTS auth_verify_attempts;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS magic_links;
DROP TABLE IF EXISTS users;
DROP FUNCTION IF EXISTS deny_update() CASCADE;
DROP FUNCTION IF EXISTS set_updated_at() CASCADE;
