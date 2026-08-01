## 2026-08-01 - [Avoid Regex for Simple ASCII Validation]
**Learning:** In Go, using `regexp.MatchString` for simple ASCII character class validation (like `^[a-zA-Z0-9._-]+$`) introduces significant regex engine overhead compared to manual byte iteration (which reduced execution time from ~700ns/op to ~23ns/op). This is a safe and highly effective optimization pattern.
**Action:** When identifying performance bottlenecks in string validation within Go codebases, prefer manual byte iteration with a `for` loop over regex for simple, purely ASCII character classes.
