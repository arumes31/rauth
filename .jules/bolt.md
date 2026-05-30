## 2026-05-27 - Redis Pipeline Batching with Mutation Fallback
**Learning:** When optimizing an N+1 query loop into a batched Redis Pipeline (e.g., retrieving users), you must be careful if the original individual getter (e.g., `GetUser`) performed lazy migrations or state mutations (like backfilling a `UID`). Directly replacing it with a pure `HGetAll` pipeline strips out this logic.
**Action:** Use a hybrid approach: Batch all reads using the pipeline, and then iterate through the results. If a result indicates the record is legacy/incomplete (e.g., missing `UID`), selectively fallback to calling the individual mutating getter just for that specific record. This provides the performance win of batching while safely preserving necessary state migrations.

## 2026-05-27 - Redis Pipeline Batching for SCAN loops
**Learning:** In operations that scan over keys in Redis (like `HasActiveSessions` or `SyncSessionIndexes`), performing individual `HGetAll` lookups sequentially within the scan iteration loop introduces an N+1 query bottleneck. This drastically degrades performance as the dataset grows.
**Action:** Always buffer the scanned keys and process them using a Redis Pipeline (`TokenDB.Pipeline()`). Execute all queued queries with `pipe.Exec()` to process the entire page of keys in a single network roundtrip, significantly reducing latency and server load.
