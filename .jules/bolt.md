## 2026-05-27 - [FIX] N+1 Query in Active Sessions Check
**Learning:** Iterating over Redis keys returned by SCAN and performing individual HGETALL calls results in N+1 network roundtrips, significantly increasing latency especially as the number of sessions grows.
**Action:** Implemented Redis pipelines in `HasActiveSessions` to batch HGETALL requests for each batch of keys from SCAN, reducing roundtrips to 1 per batch.
