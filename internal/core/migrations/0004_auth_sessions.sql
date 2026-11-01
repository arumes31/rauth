-- Additive: the legacy runtime remains Redis-authoritative until all security
-- state adapters and the explicit coordinated cutover are implemented.
CREATE TABLE auth_state_settings (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 index_key_check bytea NOT NULL CHECK (octet_length(index_key_check) = 32)
);
CREATE TABLE auth_state_keys (
 key_id text PRIMARY KEY,
 key_check bytea NOT NULL CHECK (octet_length(key_check) = 32)
);
CREATE TABLE auth_session_families (
 id uuid PRIMARY KEY,
 username text NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 auth_gen bigint NOT NULL CHECK (auth_gen >= 0),
 absolute_expires_at timestamptz NOT NULL,
 revoked_at timestamptz
);
CREATE INDEX auth_session_families_user_idx ON auth_session_families(username);
CREATE INDEX auth_session_families_expiry_idx ON auth_session_families(absolute_expires_at);
CREATE TABLE auth_sessions (
 token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
 family_id uuid NOT NULL REFERENCES auth_session_families(id) ON DELETE CASCADE,
 key_id text NOT NULL REFERENCES auth_state_keys(key_id),
 payload bytea NOT NULL CHECK (octet_length(payload) <= 32768),
 issued_at timestamptz NOT NULL,
 idle_expires_at timestamptz NOT NULL,
 last_refreshed_at timestamptz NOT NULL,
 retired boolean NOT NULL DEFAULT false
);
CREATE INDEX auth_sessions_family_idx ON auth_sessions(family_id);
CREATE INDEX auth_sessions_expiry_idx ON auth_sessions(idle_expires_at);
