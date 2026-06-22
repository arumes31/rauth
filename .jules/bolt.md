## 2024-05-18 - Safe HMGet Type Assertions
**Learning:** `go-redis` `HMGet` returns `[]interface{}` where missing fields are strictly `nil`. Direct type assertions (e.g., `val.(string)`) on `nil` values will cause a panic.
**Action:** Always use two-value safe type assertions (e.g., `if val, ok := vals[i].(string); ok`) when parsing `HMGet` results to safely handle missing or non-string fields.
