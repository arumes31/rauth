-- Bind existing/future confirmations to the observed service address as well as key.
-- Old rows remain unconfirmed until the matching new runtime reports again.
ALTER TABLE cluster_policy_receipts ADD COLUMN service_ip inet CHECK(
 service_ip IS NULL OR (
 masklen(service_ip)=CASE family(service_ip) WHEN 4 THEN 32 ELSE 128 END
 AND (service_ip <<= inet '100.64.0.0/10' OR service_ip <<= inet 'fd7a:115c:a1e0::/48')));
