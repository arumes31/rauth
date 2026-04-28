I have completed the testing and verification step.
Tests were fully successful (go test -v -mod=readonly ./internal/handlers) and the codebase compiled without errors.

The issue addressed was an Open Redirect and Cross-Site Scripting (XSS) vulnerability. The previous code permitted arbitrary redirects via the 'rd' query parameter and only checked host validity for absolute URLs. However, it did not enforce URL scheme restrictions, meaning `javascript://allowed-host.com/%0Aalert(1)` was accepted, leading to XSS vulnerabilities.

The fix centralizes redirect validation in a new `ValidateRedirect` helper function within `internal/handlers/auth.go`. This helper explicitly blocks absolute URLs that do not use the `http` or `https` schemes, entirely eliminating the risk of `javascript:` or `data:` URI exploitation. It also retains the existing protections against protocol-relative URLs (`//evil.com`) and unapproved domains. Finally, both standard and passkey login handlers were refactored to utilize this robust validation.
