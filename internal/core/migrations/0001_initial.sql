CREATE TABLE users (
    username    text PRIMARY KEY,
    password    text NOT NULL DEFAULT '',
    email       text NOT NULL DEFAULT '',
    groups      text NOT NULL DEFAULT 'default',
    is_admin    boolean NOT NULL DEFAULT false,
    -- Encrypted ("enc:" prefix) TOTP secret; empty when TOTP is not enrolled.
    totp_secret text NOT NULL DEFAULT '',
    -- WebAuthn user handle. Kept stable: passkeys are bound to it.
    uid         uuid UNIQUE,
    created_at  bigint NOT NULL DEFAULT 0
);

-- Not tied to users: the generation must survive account deletion so a
-- recreated account starts above every token issued to the deleted one.
CREATE TABLE auth_generations (
    username text PRIMARY KEY,
    gen      bigint NOT NULL
);

CREATE TABLE recovery_codes (
    username  text NOT NULL REFERENCES users (username) ON DELETE CASCADE,
    code_hash text NOT NULL,
    PRIMARY KEY (username, code_hash)
);

CREATE TABLE webauthn_credentials (
    username   text NOT NULL REFERENCES users (username) ON DELETE CASCADE,
    -- Hex-encoded credential ID.
    cred_id    text NOT NULL,
    data       jsonb NOT NULL,
    created_at bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (username, cred_id)
);

CREATE TABLE bypass_rules (
    rule text PRIMARY KEY,
    meta jsonb NOT NULL
);

CREATE TABLE audit_logs (
    id       bigserial PRIMARY KEY,
    ts       bigint NOT NULL,
    action   text NOT NULL,
    username text NOT NULL DEFAULT '',
    ip       text NOT NULL DEFAULT '',
    details  jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_logs_username_idx ON audit_logs (username, id DESC) WHERE username <> '';
CREATE INDEX audit_logs_ts_idx ON audit_logs (ts);

-- Small key/value store for one-off markers such as the Redis import.
CREATE TABLE app_meta (
    key   text PRIMARY KEY,
    value text NOT NULL
);
