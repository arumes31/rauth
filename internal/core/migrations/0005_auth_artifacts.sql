CREATE TABLE auth_artifacts (
 kind text NOT NULL CHECK(kind IN ('pending_2fa','pending_setup','pending_setup_secret','webauthn_reg','webauthn_login_session','invite')),
 token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
 username text REFERENCES users(username) ON DELETE CASCADE,
 auth_gen bigint,
 key_id text NOT NULL REFERENCES auth_state_keys(key_id),
 payload bytea NOT NULL CHECK(octet_length(payload)<=65536),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 CHECK((username IS NULL AND auth_gen IS NULL) OR (username IS NOT NULL AND auth_gen IS NOT NULL AND auth_gen>=0)),
 PRIMARY KEY(kind,token_hash)
);
CREATE INDEX auth_artifacts_expiry_idx ON auth_artifacts(expires_at);
CREATE TABLE auth_security_counters (
 key_hash bytea PRIMARY KEY CHECK(octet_length(key_hash)=32),
 count bigint NOT NULL CHECK(count>=0 AND count<=1000000000),
 expires_at timestamptz NOT NULL
);
CREATE INDEX auth_security_counters_expiry_idx ON auth_security_counters(expires_at);
CREATE TABLE auth_replay_markers (
 key_hash bytea PRIMARY KEY CHECK(octet_length(key_hash)=32),
 expires_at timestamptz NOT NULL
);
CREATE INDEX auth_replay_markers_expiry_idx ON auth_replay_markers(expires_at);
