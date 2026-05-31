## 2026-05-27 - Redis Pipeline Batching with Mutation Fallback
**Learning:** When optimizing an N+1 query loop into a batched Redis Pipeline (e.g., retrieving users), you must be careful if the original individual getter (e.g., `GetUser`) performed lazy migrations or state mutations (like backfilling a `UID`). Directly replacing it with a pure `HGetAll` pipeline strips out this logic.
**Action:** Use a hybrid approach: Batch all reads using the pipeline, and then iterate through the results. If a result indicates the record is legacy/incomplete (e.g., missing `UID`), selectively fallback to calling the individual mutating getter just for that specific record. This provides the performance win of batching while safely preserving necessary state migrations.

## 2026-05-31 - Redis N+1 and Variadic Command Batching
**Learning:** Sequential `HGetAll` calls in scan loops (like `HasActiveSessions` and `SyncSessionIndexes`) create severe N+1 query bottlenecks, multiplying network round-trips. Iterative `Del` and `SRem` calls inside a pipeline still incur command overhead that can be avoided.
**Action:** Accumulate keys and use Redis pipelines to batch `HGetAll` calls, and use single variadic `Del`/`SRem` operations (passing slices) instead of iterating, minimizing both network round-trips and Redis command parsing overhead.
