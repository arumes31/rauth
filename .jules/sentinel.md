## 2025-02-28 - [HIGH] Fix rate limit check order to prevent resource exhaustion
**Vulnerability:** The rate limit failure responses in `internal/handlers/auth.go` used the `getRD(c)` helper function to persist the redirect URL. `getRD(c)` explicitly calls `c.FormValue("rd")`. Because calling `c.FormValue` triggers Echo's underlying request body parsing, doing this inside a rate limit rejection handler forced the server to parse potentially massive, malicious request payloads before dropping the connection. This defeated the fast-path rate limiting strategy intended to prevent resource exhaustion.
**Learning:** Any helper function used within a rate limit rejection handler must be carefully reviewed to ensure it does not inadvertently trigger heavy operations, such as request body parsing (`c.FormValue`).
**Prevention:** Use `c.QueryParam` instead of `c.FormValue` in rate limit rejection handlers to avoid triggering body parsing.

