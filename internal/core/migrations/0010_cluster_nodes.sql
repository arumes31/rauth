-- Private RPC enrollment. Browser cookies and tailnet membership confer no grant.
CREATE TABLE cluster_nodes (
 cluster_id uuid NOT NULL CHECK(cluster_id <> '00000000-0000-0000-0000-000000000000'),
 node_id uuid NOT NULL CHECK(node_id <> '00000000-0000-0000-0000-000000000000'),
 revision bigint NOT NULL CHECK(revision > 0),
 role text NOT NULL CHECK(role IN ('control','worker')),
 service_ip inet NOT NULL CHECK(
   masklen(service_ip) = CASE family(service_ip) WHEN 4 THEN 32 ELSE 128 END
   AND (service_ip <<= inet '100.64.0.0/10' OR service_ip <<= inet 'fd7a:115c:a1e0::/48')),
 spki_pins bytea[] NOT NULL CHECK(
   array_ndims(spki_pins)=1 AND array_lower(spki_pins,1)=1
   AND cardinality(spki_pins) BETWEEN 1 AND 2
   AND array_position(spki_pins,NULL) IS NULL
   AND octet_length(spki_pins[1])=32
   AND (cardinality(spki_pins)=1 OR (octet_length(spki_pins[2])=32 AND spki_pins[1]<>spki_pins[2]))),
 scopes text[] NOT NULL CHECK(
   cardinality(scopes) BETWEEN 1 AND 4 AND array_ndims(scopes)=1
   AND array_position(scopes,NULL) IS NULL
   AND scopes <@ ARRAY['policy:read','events:write','admin:relay','status:read']::text[]),
 enabled boolean NOT NULL,
 expires_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(cluster_id,node_id),
 UNIQUE(cluster_id,service_ip)
);
