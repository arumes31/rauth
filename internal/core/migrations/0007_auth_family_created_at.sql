-- Release context: auth_session_families is new in this same unreleased
-- migration set (0004). Released versions have no SQL session writers/data.
-- These statements run before HTTP starts; experimental SQL deployments must
-- drain writers under the offline cutover procedure. This is intentionally not
-- a template for backfilling a large, already-active authentication store.
-- Stable device/login chronology for newest-first session management. Token
-- rotation must not move a family between pagination boundaries.
ALTER TABLE auth_session_families ADD COLUMN created_at timestamptz;
UPDATE auth_session_families f SET created_at=COALESCE(
 (SELECT MIN(s.issued_at) FROM auth_sessions s WHERE s.family_id=f.id),clock_timestamp());
ALTER TABLE auth_session_families ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE auth_session_families ALTER COLUMN created_at SET DEFAULT clock_timestamp();
CREATE INDEX auth_session_families_created_idx ON auth_session_families(created_at DESC,id DESC);
CREATE INDEX auth_session_families_user_created_idx ON auth_session_families(username,created_at DESC,id DESC);
