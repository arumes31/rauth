## 2026-05-27 - Redis Pipeline Batching with Mutation Fallback
**Learning:** When optimizing an N+1 query loop into a batched Redis Pipeline (e.g., retrieving users), you must be careful if the original individual getter (e.g., `GetUser`) performed lazy migrations or state mutations (like backfilling a `UID`). Directly replacing it with a pure `HGetAll` pipeline strips out this logic.
**Action:** Use a hybrid approach: Batch all reads using the pipeline, and then iterate through the results. If a result indicates the record is legacy/incomplete (e.g., missing `UID`), selectively fallback to calling the individual mutating getter just for that specific record. This provides the performance win of batching while safely preserving necessary state migrations.
## [PERF] Sequential RPush in Credential Deletion
- **Issue**: Functions in `internal/core/webauthn.go` were using sequential `RPush` or `LSet` calls to update a Redis list, leading to multiple round-trips.
- **Optimization**: Centralized list updates into a `saveStoredCredentials` helper that uses `UserDB.TxPipelined` to `Del` and a single variadic `RPush` in a transaction.
- **Impact**: Reduced Redis round-trips from O(N) to O(1) for credential management operations.
