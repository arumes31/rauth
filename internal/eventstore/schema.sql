CREATE TABLE IF NOT EXISTS event_schema_version(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),version integer NOT NULL CHECK(version=1));
INSERT INTO event_schema_version(singleton,version) VALUES(true,1) ON CONFLICT(singleton) DO NOTHING;
CREATE TABLE IF NOT EXISTS event_ledgers(
 cluster_id uuid PRIMARY KEY,owner_role name NOT NULL,epoch uuid NOT NULL DEFAULT gen_random_uuid(),owner_token uuid,
 payload_bytes bigint NOT NULL DEFAULT 0 CHECK(payload_bytes>=0),event_count bigint NOT NULL DEFAULT 0 CHECK(event_count>=0),
 expired_count bigint NOT NULL DEFAULT 0 CHECK(expired_count>=0),pruned_through bigint NOT NULL DEFAULT 0 CHECK(pruned_through>=0),
 high_water bigint NOT NULL DEFAULT 0 CHECK(high_water>=0),UNIQUE(cluster_id,owner_role));
CREATE TABLE IF NOT EXISTS request_events(
 cluster_id uuid NOT NULL,owner_role name NOT NULL DEFAULT current_user,seq bigint NOT NULL CHECK(seq>0),
 node_id uuid NOT NULL,event_id uuid NOT NULL,occurred_at timestamptz NOT NULL,received_at timestamptz NOT NULL,
 payload bytea NOT NULL CHECK(octet_length(payload)<=8192),size bigint NOT NULL CHECK(size>0),
 PRIMARY KEY(cluster_id,seq),UNIQUE(cluster_id,node_id,event_id),
 FOREIGN KEY(cluster_id,owner_role) REFERENCES event_ledgers(cluster_id,owner_role));
CREATE INDEX IF NOT EXISTS request_events_occurred ON request_events(cluster_id,occurred_at);
CREATE INDEX IF NOT EXISTS request_events_received ON request_events(cluster_id,received_at);
ALTER TABLE event_ledgers ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_ledgers NO FORCE ROW LEVEL SECURITY;
ALTER TABLE request_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_events NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS event_ledger_owner ON event_ledgers;
CREATE POLICY event_ledger_owner ON event_ledgers USING(owner_role=current_user) WITH CHECK(owner_role=current_user);
DROP POLICY IF EXISTS request_event_owner ON request_events;
CREATE POLICY request_event_owner ON request_events USING(owner_role=current_user) WITH CHECK(owner_role=current_user);
