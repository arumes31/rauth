-- Inert until the private policy runtime is enabled. No legacy rules are changed.
CREATE TABLE cluster_policy_blobs (
 cluster_id uuid NOT NULL,
 sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 bytes bigint NOT NULL CHECK(bytes BETWEEN 0 AND 268435456),
 PRIMARY KEY(cluster_id,sha256), UNIQUE(cluster_id,sha256,bytes)
);
CREATE TABLE cluster_policy_chunks (
 cluster_id uuid NOT NULL,
 sha256 text NOT NULL,
 part integer NOT NULL CHECK(part BETWEEN 0 AND 255),
 payload bytea NOT NULL CHECK(octet_length(payload) BETWEEN 1 AND 1048576),
 PRIMARY KEY(cluster_id,sha256,part),
 FOREIGN KEY(cluster_id,sha256) REFERENCES cluster_policy_blobs ON DELETE CASCADE
);
CREATE TABLE cluster_policy_manifests (
 cluster_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 envelope bytea NOT NULL CHECK(octet_length(envelope) BETWEEN 1 AND 98304),
 PRIMARY KEY(cluster_id,revision), UNIQUE(cluster_id,revision,sha256)
);
CREATE TABLE cluster_policy_dependencies (
 cluster_id uuid NOT NULL,
 revision bigint NOT NULL,
 kind text NOT NULL CHECK(kind IN ('policy','feed','geoip')),
 logical_id text NOT NULL CHECK(length(logical_id) BETWEEN 1 AND 64),
 sha256 text NOT NULL,
 bytes bigint NOT NULL,
 PRIMARY KEY(cluster_id,revision,kind,logical_id),
 FOREIGN KEY(cluster_id,revision) REFERENCES cluster_policy_manifests ON DELETE CASCADE,
 FOREIGN KEY(cluster_id,sha256,bytes) REFERENCES cluster_policy_blobs(cluster_id,sha256,bytes)
);
CREATE INDEX cluster_policy_dependency_hash_idx ON cluster_policy_dependencies(cluster_id,sha256);
CREATE TABLE cluster_policy_heads (
 cluster_id uuid PRIMARY KEY,
 revision bigint NOT NULL,
 sha256 text NOT NULL,
 FOREIGN KEY(cluster_id,revision,sha256) REFERENCES cluster_policy_manifests(cluster_id,revision,sha256)
);
