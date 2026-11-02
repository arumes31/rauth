-- Additive migration: version 1 may already contain committed cursor history.
ALTER TABLE event_schema_version DROP CONSTRAINT IF EXISTS event_schema_version_version_check;
DO $migration$
BEGIN
 IF (SELECT version FROM event_schema_version WHERE singleton)=1 THEN
  ALTER TABLE request_events ADD COLUMN kind text NOT NULL DEFAULT 'decision',
   ADD COLUMN node_name text NOT NULL DEFAULT '', ADD COLUMN action text NOT NULL DEFAULT '',
   ADD COLUMN country text NOT NULL DEFAULT '', ADD COLUMN source text NOT NULL DEFAULT '',
   ADD COLUMN domain text NOT NULL DEFAULT '', ADD COLUMN url text NOT NULL DEFAULT '',
   ADD COLUMN reason text NOT NULL DEFAULT '', ADD COLUMN feed_id text NOT NULL DEFAULT '',
   ADD COLUMN processing_us bigint NOT NULL DEFAULT 0 CHECK(processing_us BETWEEN 0 AND 600000000),
   ADD COLUMN latency_bucket integer NOT NULL DEFAULT -1 CHECK(latency_bucket BETWEEN -1 AND 13);
  -- Version-1 payloads were validated canonical records. No query/userinfo is recovered.
  UPDATE request_events SET
   kind=COALESCE(convert_from(payload,'UTF8')::jsonb->>'kind','decision'),
   node_name=COALESCE(convert_from(payload,'UTF8')::jsonb->>'node_name',''),
   action=COALESCE(convert_from(payload,'UTF8')::jsonb->>'action',''),
   country=COALESCE(convert_from(payload,'UTF8')::jsonb->>'country',''),
   source=COALESCE(convert_from(payload,'UTF8')::jsonb->>'source',''),
   url=COALESCE(convert_from(payload,'UTF8')::jsonb->>'url',''),
   domain=COALESCE(lower(substring(COALESCE(convert_from(payload,'UTF8')::jsonb->>'url','') from '^https?://([^/:]+)')),''),
   reason=COALESCE(convert_from(payload,'UTF8')::jsonb->>'reason',''),
   feed_id=COALESCE(convert_from(payload,'UTF8')::jsonb->>'feed_id','');
  UPDATE request_events SET domain='' WHERE domain IS NULL;
  ALTER TABLE request_events ALTER COLUMN domain SET NOT NULL;
  CREATE INDEX request_events_feed ON request_events(cluster_id,seq DESC) WHERE kind<>'telemetry';
  CREATE INDEX request_events_node_feed ON request_events(cluster_id,node_id,seq DESC) WHERE kind<>'telemetry';
  CREATE INDEX request_events_gap_time ON request_events(cluster_id,occurred_at) WHERE kind='gap';
  CREATE INDEX request_events_node_time ON request_events(cluster_id,node_id,occurred_at);
  CREATE INDEX request_events_decision_time ON request_events(cluster_id,occurred_at,seq) WHERE kind='decision';
  CREATE TABLE event_traffic_minute(
   cluster_id uuid NOT NULL,owner_role name NOT NULL DEFAULT current_user,node_id uuid NOT NULL,
   minute timestamptz NOT NULL,action text NOT NULL,country text NOT NULL,latency_bucket integer NOT NULL,
   decisions bigint NOT NULL CHECK(decisions>0),processing_us numeric NOT NULL CHECK(processing_us>=0),
   PRIMARY KEY(cluster_id,node_id,minute,action,country,latency_bucket),
   FOREIGN KEY(cluster_id,owner_role) REFERENCES event_ledgers(cluster_id,owner_role));
  CREATE INDEX event_traffic_time ON event_traffic_minute(cluster_id,minute);
  INSERT INTO event_traffic_minute(cluster_id,owner_role,node_id,minute,action,country,latency_bucket,decisions,processing_us)
   SELECT cluster_id,owner_role,node_id,date_trunc('minute',occurred_at),action,country,-1,count(*),0
   FROM request_events WHERE kind='decision' GROUP BY cluster_id,owner_role,node_id,date_trunc('minute',occurred_at),action,country;
  CREATE TABLE event_node_samples(
   cluster_id uuid NOT NULL,owner_role name NOT NULL DEFAULT current_user,seq bigint NOT NULL,
   node_id uuid NOT NULL,node_name text NOT NULL,instance_id uuid NOT NULL,
   occurred_at timestamptz NOT NULL,received_at timestamptz NOT NULL,snapshot jsonb NOT NULL,is_diagnostic boolean NOT NULL DEFAULT false,
   PRIMARY KEY(cluster_id,seq),FOREIGN KEY(cluster_id,seq) REFERENCES request_events(cluster_id,seq) ON DELETE CASCADE,
   FOREIGN KEY(cluster_id,owner_role) REFERENCES event_ledgers(cluster_id,owner_role));
  CREATE INDEX event_samples_node_time ON event_node_samples(cluster_id,node_id,occurred_at DESC);
  CREATE INDEX event_samples_diagnostic ON event_node_samples(cluster_id,node_id,is_diagnostic,occurred_at DESC);
  CREATE INDEX event_samples_time ON event_node_samples(cluster_id,occurred_at DESC);
  ALTER TABLE event_traffic_minute ENABLE ROW LEVEL SECURITY;
  CREATE POLICY event_traffic_owner ON event_traffic_minute USING(owner_role=current_user) WITH CHECK(owner_role=current_user);
  ALTER TABLE event_node_samples ENABLE ROW LEVEL SECURITY;
  CREATE POLICY event_sample_owner ON event_node_samples USING(owner_role=current_user) WITH CHECK(owner_role=current_user);
  UPDATE event_schema_version SET version=2 WHERE singleton;
 END IF;
END $migration$;
ALTER TABLE event_schema_version ADD CONSTRAINT event_schema_version_version_check CHECK(version IN (1,2));
