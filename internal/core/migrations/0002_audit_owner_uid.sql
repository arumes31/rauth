-- The account (by its immutable UID) an audit entry belongs to. Usernames can
-- be reused after deletion, so personal history is selected by UID; entries
-- written before this column existed keep it NULL.
ALTER TABLE audit_logs ADD COLUMN user_uid uuid;
CREATE INDEX audit_logs_user_uid_idx ON audit_logs (user_uid, id DESC) WHERE user_uid IS NOT NULL;
