## 2026-05-27 - Redis Pipeline Batching with Mutation Fallback
**Learning:** When optimizing an N+1 query loop into a batched Redis Pipeline (e.g., retrieving users), you must be careful if the original individual getter (e.g., `GetUser`) performed lazy migrations or state mutations (like backfilling a `UID`). Directly replacing it with a pure `HGetAll` pipeline strips out this logic.
**Action:** Use a hybrid approach: Batch all reads using the pipeline, and then iterate through the results. If a result indicates the record is legacy/incomplete (e.g., missing `UID`), selectively fallback to calling the individual mutating getter just for that specific record. This provides the performance win of batching while safely preserving necessary state migrations.
## 2026-05-28 - Session Invalidation Pipelines
**Learning:** Invalidation functions `InvalidateUserSessions` and `InvalidateOtherUserSessions` were using Redis pipelines to issue multiple `Del` or `SRem` commands (e.g. one `pipe.Del` per token). This still involves pushing multiple separate commands inside the pipeline. `Del` and `SRem` natively support variadic arguments. Passing all keys/members as variadic arguments to a single command inside the pipeline (or even just directly to the client) is slightly faster and reduces pipeline payload size.
**Action:** When invalidating multiple tokens or removing multiple set members, use variadic `pipe.Del(Ctx, toDel...)` and `pipe.SRem(Ctx, indexKey, toRem...)` after collecting the keys/members into slices.

## 2026-06-02 - Consolidating Unit Tests and Coverage
**Learning:** When adding missing test files for specific components (e.g., `passwords.go`), always check if partial tests already exist in misplaced locations (e.g., `twofactor_test.go`). Consolidation improves maintainability and ensures that logic is tested where it resides. Additionally, always verify boundary conditions like length limits (e.g., bcrypt's 72-byte limit) to prevent silent failures.
**Action:** Consolidate related tests into a single file (`passwords_test.go`) and expand them to cover all exported/internal logic and edge cases.

## 2026-06-02 - WebAuthn Hash Migration
**Learning:** Migrating from Redis Lists to Hashes for entity storage (like WebAuthn credentials) eliminates N+1 query patterns and O(N) mutation overhead. Using a lazy migration strategy in the getter ensures zero-downtime data transition.
**Action:** Implement lazy migration in `GetStoredCredentials` to move data from legacy List keys to Hash keys. Ensure all mutation functions (`Update*`, `Delete*`) also trigger or handle this migration to maintain data integrity.
