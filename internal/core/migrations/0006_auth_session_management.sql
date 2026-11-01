-- SQL authority is not enabled yet; newly issued sessions populate this keyed index.
ALTER TABLE auth_sessions ADD COLUMN ip_hash bytea CHECK(ip_hash IS NULL OR octet_length(ip_hash)=32);
CREATE INDEX auth_sessions_ip_idx ON auth_sessions(ip_hash) WHERE NOT retired;
CREATE INDEX auth_sessions_current_family_idx ON auth_sessions(family_id,issued_at DESC) WHERE NOT retired;
CREATE TABLE auth_step_up_grants (
 token_hash bytea PRIMARY KEY REFERENCES auth_sessions(token_hash) ON DELETE CASCADE,
 username text NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 auth_gen bigint NOT NULL CHECK(auth_gen>=0),
 expires_at timestamptz NOT NULL
);
CREATE INDEX auth_step_up_grants_expiry_idx ON auth_step_up_grants(expires_at);

-- Keep revocation reachability after hard replacement or expired grace rows.
-- These are keyed digests, never raw tokens, and expire with their family.
CREATE TABLE auth_session_tokens (
 token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32),
 family_id uuid NOT NULL REFERENCES auth_session_families(id) ON DELETE CASCADE
);
CREATE INDEX auth_session_tokens_family_idx ON auth_session_tokens(family_id);
INSERT INTO auth_session_tokens(token_hash,family_id) SELECT token_hash,family_id FROM auth_sessions;
