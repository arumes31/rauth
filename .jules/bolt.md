## 2026-05-27 - Redis Pipeline Batching with Mutation Fallback
**Learning:** When optimizing an N+1 query loop into a batched Redis Pipeline (e.g., retrieving users), you must be careful if the original individual getter (e.g., `GetUser`) performed lazy migrations or state mutations (like backfilling a `UID`). Directly replacing it with a pure `HGetAll` pipeline strips out this logic.
**Action:** Use a hybrid approach: Batch all reads using the pipeline, and then iterate through the results. If a result indicates the record is legacy/incomplete (e.g., missing `UID`), selectively fallback to calling the individual mutating getter just for that specific record. This provides the performance win of batching while safely preserving necessary state migrations.
## [PERF] Sequential RPush and LSet in WebAuthn Credential Updates
- **Issue:** Iterative Redis operations (LSet, RPush) in loops caused excessive round-trips.
- **Fix:** Refactored credential management functions in `internal/core/webauthn.go` to use a `saveStoredCredentials` helper.
- **Optimization:** This helper accumulates JSON-marshaled credentials into a slice and uses `UserDB.TxPipelined` to execute an atomic `Del` and a single variadic `RPush`.
- **Consistency:** Changed `UpdateWebAuthnSignCount` to return an `error` and updated call sites to handle it, ensuring compliance with `errcheck` and centralized atomicity.
