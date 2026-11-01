CREATE TABLE ip_feeds (
 id uuid PRIMARY KEY,
 name text NOT NULL,
 source_url text NOT NULL,
 refresh_minutes integer NOT NULL CHECK(refresh_minutes BETWEEN 15 AND 1440),
 enabled boolean NOT NULL DEFAULT true,
 active_version bigint NOT NULL DEFAULT 0,
 entry_count integer NOT NULL DEFAULT 0,
 last_success bigint NOT NULL DEFAULT 0,
 last_attempt bigint NOT NULL DEFAULT 0,
 last_error text NOT NULL DEFAULT '',
 revision bigint NOT NULL DEFAULT 1,
 refresh_lease_until bigint NOT NULL DEFAULT 0,
 lease_token uuid,
 created_by text NOT NULL,
 created_at bigint NOT NULL,
 updated_by text NOT NULL,
 updated_at bigint NOT NULL
);
CREATE TABLE ip_feed_versions (
 feed_id uuid NOT NULL REFERENCES ip_feeds(id) ON DELETE CASCADE,
 version bigint NOT NULL,
 checksum text NOT NULL,
 payload bytea NOT NULL,
 created_at bigint NOT NULL,
 PRIMARY KEY(feed_id,version)
);
CREATE TABLE bypass_rule_feeds (
 rule text NOT NULL REFERENCES bypass_rules(rule) ON DELETE CASCADE ON UPDATE CASCADE,
 feed_id uuid NOT NULL REFERENCES ip_feeds(id) ON DELETE RESTRICT,
 PRIMARY KEY(rule,feed_id)
);
CREATE INDEX bypass_rule_feeds_feed_idx ON bypass_rule_feeds(feed_id);
