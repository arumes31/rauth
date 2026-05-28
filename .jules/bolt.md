## 2026-05-27 - Redis Pipeline Batching with Mutation Fallback
**Learning:** When optimizing an N+1 query loop into a batched Redis Pipeline (e.g., retrieving users), you must be careful if the original individual getter (e.g., `GetUser`) performed lazy migrations or state mutations (like backfilling a `UID`). Directly replacing it with a pure `HGetAll` pipeline strips out this logic.
**Action:** Use a hybrid approach: Batch all reads using the pipeline, and then iterate through the results. If a result indicates the record is legacy/incomplete (e.g., missing `UID`), selectively fallback to calling the individual mutating getter just for that specific record. This provides the performance win of batching while safely preserving necessary state migrations.

## 2026-05-27 - Atomic Redis List Updates for Credentials
**Learning:** WebAuthn credential lists stored in Redis require atomic updates to prevent partial states. Using a sequence of `Del` followed by `RPush` is non-atomic and prone to race conditions or partial failures.
**Action:** Wrap `Del` and `RPush` operations within a `UserDB.TxPipelined` transaction. This ensures that the list is replaced atomically and reduces network round-trips. Additionally, utilize `LLen` for determining indices instead of loading full lists, and use `bytes.Equal` or `hex.EncodeToString` for efficient credential ID comparisons.
