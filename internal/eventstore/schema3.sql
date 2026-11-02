-- Version 3 upgrades already-populated v1/v2 ledgers without changing cursors.
ALTER TABLE event_schema_version DROP CONSTRAINT IF EXISTS event_schema_version_version_check;
ALTER TABLE event_ledgers ADD COLUMN telemetry_bytes bigint NOT NULL DEFAULT 0 CHECK(telemetry_bytes>=0);
UPDATE request_events SET size=octet_length(payload)::bigint*2+1024;
-- Version-1 normalization used a DNS-host regex; recover bracketed IPv6 hosts.
UPDATE request_events SET domain=lower(substring(url from '^https?://\[([^]]+)\]')) WHERE url ~ '^https?://\[';
UPDATE event_ledgers l SET payload_bytes=COALESCE((SELECT sum(size) FROM request_events e WHERE e.cluster_id=l.cluster_id),0),telemetry_bytes=COALESCE((SELECT sum(size) FROM request_events e WHERE e.cluster_id=l.cluster_id AND kind='telemetry'),0);
CREATE INDEX request_events_telemetry_seq ON request_events(cluster_id,seq) INCLUDE(size) WHERE kind='telemetry';
UPDATE event_schema_version SET version=3 WHERE singleton;
ALTER TABLE event_schema_version ADD CONSTRAINT event_schema_version_version_check CHECK(version IN (1,2,3));
