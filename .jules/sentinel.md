## 2025-05-01 - URL Validation Bypass via Scheme Allowlisting
**Vulnerability:** Open redirect and potential XSS (javascript:, data:, vbscript:) on the login redirect parameter (`rd`) in `internal/handlers/auth.go`.
**Learning:** The URL parser correctly identified absolute URLs using `parsedURL.IsAbs()`, but the validation logic only checked `h.Cfg.IsAllowedHost(parsedURL.Hostname())` without enforcing that the scheme is `http` or `https`. An attacker could bypass validation by providing a payload like `javascript://allowed-domain.com/%0Aalert(1)`, which passes the `IsAllowedHost` check but executes scripts in the browser due to the dangerous scheme.
**Prevention:** Always restrict absolute URL schemes to `http` and `https` in addition to hostname validation.
