## 2026-04-27 - Fix XSS and Open Redirect in 'rd' parameter
**Vulnerability:** XSS and Open Redirect in the `rd` query parameter in the WebAuthn flow, and an incomplete check in the standard login flow.
**Learning:** Even if a URL's hostname is verified as allowed, if the scheme is not explicitly checked, malicious schemes like `javascript:` or `data:` can be used to execute arbitrary code (XSS). Additionally, the WebAuthn flow had entirely missed the validation logic for the `rd` parameter.
**Prevention:** Always validate both the scheme (`http`, `https`) and the hostname when processing absolute URLs for redirects. Centralize this validation logic into a single function (e.g., `ValidateRedirect`) and reuse it across all authentication endpoints to prevent discrepancies.
