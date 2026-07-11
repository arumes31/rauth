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
> **Revised 2026-06-05:** Superseded for hot paths by [Optimizing string parsing](#2026-06-05---optimizing-string-parsing). Prefer `bufio.Scanner` for readability with moderate-size inputs parsed occasionally; prefer manual index-based newline parsing (`strings.IndexByte` + slicing) for hot loops, zero-allocation requirements, or very large embedded strings parsed once.

**Learning:** Parsing large embedded strings (like blocklists) using `strings.Split` creates a large slice of strings that persists until the loop finishes. This is inefficient for one-time map population.
**Action:** Use `bufio.Scanner` with `strings.NewReader` to process the string line-by-line. This minimizes temporary allocations and is significantly more memory-efficient for large text datasets than `strings.Split`. For one-time parsing of very large strings in hot paths, go a step further with index-based slicing (see 2026-06-05).
## 2026-06-05 - Avoid Redundant Pipeline Wrapping
**Learning:** While pipelining is crucial for batching multiple commands, wrapping a *single* variadic command (like `Del(keys...)`) inside a pipeline introduces unnecessary overhead. Direct command execution via the client is faster when only one network round-trip is required.
**Action:** When performing a single bulk operation with a variadic command, call it directly on the client (e.g., `TokenDB.Del(...)`) instead of initializing and executing a pipeline.

## 2026-06-08 - HGetAll vs HGet in Pipelines
**Learning:** When retrieving a single field from a Redis hash inside a pipeline loop, replacing `HGetAll` with `HGet` reduces memory allocations and parsing overhead. However, be careful to use `*redis.StringCmd` instead of `*redis.MapStringStringCmd` for the command array, and handle potential `redis.Nil` errors which `HGetAll` does not throw.
**Action:** Always prefer `HGet` over `HGetAll` when only one field is needed, even in pipelines. Update variable types and error handling accordingly.

## 2026-06-05 - Optimizing string parsing
**Learning:** Using bufio.Scanner for parsing strings in memory still requires allocating scanner structures and copying slices. A loop matching on newlines (`strings.IndexByte`) and slicing directly from the original string is significantly faster and requires zero extra allocations.
**Action:** Use index-based slicing instead of bufio.Scanner when extracting lines from embedded strings that are only parsed once.

## 2026-06-11 - Health Check Allocation and Iteration
**Learning:** Building the health-check Redis client set as a `map` forces non-deterministic iteration order and an extra allocation, while the result map can be sized up front.
**Action:** Use a preallocated `checks` map (`make(map[string]string, 4)`) and iterate the clients via a fixed slice of structs instead of a map for deterministic order and fewer allocations.

## 2026-06-11 - HGetAll vs HMGet Overhead
**Learning:** `HGetAll` reads and decodes the entire Redis hash map into memory, which incurs unnecessary overhead for authentication and routing middleware that only requires checking specific fields (like `status`, `username`, `groups`, `is_admin`). `HMGet` is significantly faster because it only fetches and transfers the requested fields over the network, returning a slice rather than a map.
**Action:** When validating sessions in middleware or routing handlers that only need partial hash data, prefer `HMGet(ctx, key, fields...)` over `HGetAll(ctx, key)` to minimize redis parsing and network serialization overhead.
## 2026-07-11 - Use Slices Instead of Maps for Pipeline Commands
**Learning:** When executing multiple Redis commands in a pipeline and needing to retrieve their results later, using a map to store the command objects (e.g., `make(map[string]*redis.StringCmd)`) adds unnecessary allocation overhead and hashing cost. Since the commands are pushed to the pipeline in a deterministic order by iterating over a slice of keys, we can just use a slice to store the command objects.
**Action:** Use `make([]*redis.CmdType, len(keys))` and iterate over the keys using the index (`for i, key := range keys`) to store and retrieve the command results.
