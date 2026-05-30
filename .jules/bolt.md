## 2026-05-27 - Redis Pipeline Batching with Mutation Fallback
**Learning:** When optimizing an N+1 query loop into a batched Redis Pipeline (e.g., retrieving users), you must be careful if the original individual getter (e.g., `GetUser`) performed lazy migrations or state mutations (like backfilling a `UID`). Directly replacing it with a pure `HGetAll` pipeline strips out this logic.
**Action:** Use a hybrid approach: Batch all reads using the pipeline, and then iterate through the results. If a result indicates the record is legacy/incomplete (e.g., missing `UID`), selectively fallback to calling the individual mutating getter just for that specific record. This provides the performance win of batching while safely preserving necessary state migrations.

## 2026-05-27 - Atomic Redis List Updates with TxPipelined
**Learning:** Functions that update a Redis list by deleting and then re-pushing items (e.g., `webauthn_creds`) should be wrapped in a `TxPipelined` transaction to ensure atomicity and prevent partial states. Accumulating all elements into a slice and using a single variadic `RPush` also significantly reduces Redis round-trips compared to sequential individual `RPush` calls.
**Action:** Centralize list-modifying logic into a helper function (e.g., `saveStoredCredentials`) that uses `TxPipelined` and variadic `RPush`.
