## 2024-05-18 - Fix Open Redirect / XSS vulnerability in URL redirects
**Vulnerability:** The application was vulnerable to Open Redirect and XSS via `javascript:` URIs in the redirect flow. While absolute URLs were checked against an allowed host list, the URL scheme was not constrained, permitting exploitation.
**Learning:** URL parsing alone does not secure redirects if the scheme is not explicitly restricted. A strict allowlist of `http` and `https` schemes is required to prevent XSS payloads disguised as absolute URLs.
**Prevention:** Centralized validation logic in a new `ValidateRedirect` helper that enforces absolute URL scheme constraints and host whitelisting, ensuring all redirect destinations are sanitized uniformly across handlers.
