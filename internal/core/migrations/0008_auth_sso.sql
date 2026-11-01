-- Opt-in cross-domain SSO; existing sessions remain canonical-login sessions.
ALTER TABLE auth_sessions ADD COLUMN audience text NOT NULL DEFAULT '' CHECK(length(audience)<=261);
CREATE TABLE auth_sso_transactions (
 transaction_hash bytea PRIMARY KEY CHECK(octet_length(transaction_hash)=32),
 browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 origin text NOT NULL CHECK(length(origin) BETWEEN 9 AND 261),
 key_id text NOT NULL REFERENCES auth_state_keys(key_id),
 payload bytea NOT NULL CHECK(octet_length(payload)<=16384),
 expires_at timestamptz NOT NULL,
 code_hash bytea UNIQUE CHECK(code_hash IS NULL OR octet_length(code_hash)=32),
 code_expires_at timestamptz,
 family_id uuid REFERENCES auth_session_families(id) ON DELETE CASCADE,
 auth_gen bigint CHECK(auth_gen IS NULL OR auth_gen>=0),
 consumed_at timestamptz,
 CHECK((code_hash IS NULL AND code_expires_at IS NULL AND family_id IS NULL AND auth_gen IS NULL)
    OR (code_hash IS NOT NULL AND code_expires_at IS NOT NULL AND family_id IS NOT NULL AND auth_gen IS NOT NULL))
);
CREATE INDEX auth_sso_expiry_idx ON auth_sso_transactions(expires_at);
CREATE INDEX auth_sso_family_idx ON auth_sso_transactions(family_id);
