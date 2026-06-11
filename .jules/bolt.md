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

## 2026-06-02 - Redis Pipeline Error Handling and Global Initialization
**Learning:** When using Redis pipelines to optimize N+1 queries (e.g., in `EnsureUserUIDs`), remember that `pipe.Exec()` returns the FIRST error encountered by any command in the pipeline. If some keys are missing (`redis.Nil`), `Exec` will return `redis.Nil`. You must explicitly check for this and distinguish it from critical errors (e.g., network failure).
**Action:** Always check `if err != nil && err != redis.Nil` after `pipe.Exec()` if your pipeline includes commands that might return `redis.Nil` as a valid state (like `HGet` for a missing field). Additionally, when background goroutines use global Redis clients (like `TokenDB`), ensure they handle `nil` clients or provide a way to bypass execution during early system initialization to avoid panics in tests.

## 2026-05-27 - Reducing Allocations with bufio.Scanner
**Learning:** Parsing large embedded strings (like blocklists) using `strings.Split` creates a large slice of strings that persists until the loop finishes. This is inefficient for one-time map population.
**Action:** Use `bufio.Scanner` with `strings.NewReader` to process the string line-by-line. This minimizes temporary allocations and is significantly more memory-efficient for large text datasets.
## 2026-06-05 - Avoid Redundant Pipeline Wrapping
**Learning:** While pipelining is crucial for batching multiple commands, wrapping a *single* variadic command (like `Del(keys...)`) inside a pipeline introduces unnecessary overhead. Direct command execution via the client is faster when only one network round-trip is required.
**Action:** When performing a single bulk operation with a variadic command, call it directly on the client (e.g., `TokenDB.Del(...)`) instead of initializing and executing a pipeline.
