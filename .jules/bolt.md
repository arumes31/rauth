## 2026-05-27 - WebAuthn Redis Optimization
**Learning:** Sequential Redis operations (e.g., `Del` followed by `RPush`) can be batched using `Pipelined` to reduce network round-trips. Hex encoding for comparison using `fmt.Sprintf("%x", ...)` is less efficient than `bytes.Equal` for raw bytes or `hex.EncodeToString` for string comparisons.
**Action:** Refactored `internal/core/webauthn.go` to use Redis pipelines and more efficient byte/hex comparisons. Updated `UpdateWebAuthnSignCount` to return errors and improved caller error handling.
