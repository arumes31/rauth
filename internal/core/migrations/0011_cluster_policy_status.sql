-- Observational policy state is separate from authentication authority.
CREATE TABLE cluster_policy_source_state (
 singleton boolean PRIMARY KEY CHECK(singleton),
 revision bigint NOT NULL CHECK(revision>=0)
);
INSERT INTO cluster_policy_source_state VALUES(true,0);

CREATE TABLE cluster_policy_receipts (
 cluster_id uuid NOT NULL,
 node_id uuid NOT NULL,
 spki_sha256 bytea NOT NULL CHECK(octet_length(spki_sha256)=32),
 applied_revision bigint NOT NULL CHECK(applied_revision>=0),
 applied_sha256 text NOT NULL,
 desired_revision bigint NOT NULL CHECK(desired_revision>=0),
 desired_sha256 text NOT NULL,
 ready boolean NOT NULL,
 lease_expires_at timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(cluster_id,node_id),
 FOREIGN KEY(cluster_id,node_id) REFERENCES cluster_nodes ON DELETE CASCADE,
 CHECK((applied_revision=0 AND applied_sha256='') OR (applied_revision>0 AND applied_sha256 ~ '^[0-9a-f]{64}$')),
 CHECK((desired_revision=0 AND desired_sha256='') OR (desired_revision>0 AND desired_sha256 ~ '^[0-9a-f]{64}$')),
 CHECK(NOT ready OR (applied_revision>0 AND applied_revision=desired_revision AND applied_sha256=desired_sha256))
);
