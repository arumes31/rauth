# Bolt Performance Audits

## 2024-05-27 - N+1 Query in Session and User Retrieval
**Learning:** Sequential Redis calls like `HGetAll` within loops create N+1 query patterns that significantly degrade performance as the number of items (sessions or users) grows. Redis pipelines allow batching multiple commands into a single network round-trip, dramatically reducing latency.
**Action:** Implemented Redis pipelines in `HasActiveSessions` (for session scanning) and `ListUsers` (for user retrieval). For `ListUsers`, the pipeline batches `HGetAll` calls for all usernames, while maintaining lazy-migration support by falling back to individual `GetUser` calls only for legacy records missing a UID.
