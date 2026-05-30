# Sentinel Security Audits

## 2024-05-20 - Open Redirect via Absolute URL Scheme Bypass
**Vulnerability:** The open redirect logic allowed absolute URLs without verifying their scheme, opening the door for XSS via `javascript:` or `data:` schemes (e.g., `javascript://example.com/%0Aalert(1)`).
**Learning:** Checking `IsAllowedHost` is insufficient if the scheme is not explicitly restricted to `http` or `https`, as browsers will execute code for other URI schemes while still matching the hostname.
**Prevention:** Always ensure that an absolute URL's scheme is strictly limited to `http` or `https` in combination with host whitelisting when processing redirects.

## 2024-05-20 - Browser Normalization Open Redirect Bypass
**Vulnerability:** The open redirect validation `ValidateRedirectURL` failed to sanitize leading spaces and verify against `/\` and `\\` prefixes.
**Learning:** Modern browsers automatically normalize prefixes like `/\` and `\\` to `//` (protocol-relative), and leading spaces can bypass a strict `HasPrefix("//")` check.
**Prevention:** In redirect validation logic, inputs must have leading whitespace trimmed. Checks for protocol-relative bypasses must include alternative protocol-relative path prefixes (`/\` and `\\`).

## 2024-05-30 - 2FA Brute-Force Rate-Limit Bypass
**Vulnerability:** Rate limiting for 2FA attempts was checked and enforced *after* the computationally expensive cryptographic TOTP validation. An attacker could bypass the protection by continuing to brute-force the TOTP codes, since a correct guess would validate and authenticate the user before the rate limit blocked them.
**Learning:** Security checks (like rate limiting) must always occur before the protected action or validation. Failing to do so renders the protection useless against continuous automated attacks.
**Prevention:** Implement pre-execution checks (e.g., `core.IsRateLimitExceeded`) prior to sensitive or costly operations. Use a pattern that checks the limit before executing the logic, and only increments the counter after a failed execution to prevent bypasses and timing attacks.

## 2024-05-22 - Fix Username Enumeration Timing Attack
**Vulnerability:** A timing attack vulnerability existed in the login flow where the dummy bcrypt hash used to prevent username enumeration (`$2a$12$ce88271ea06248da6b12669ef405f18a52c193fcced142ee27`) was invalid and rejected immediately in under a microsecond by `golang.org/x/crypto/bcrypt`.
**Learning:** `bcrypt.CompareHashAndPassword` immediately returns an error without doing any compute if the hash length or format is invalid. To prevent timing attacks, the dummy hash MUST be a fully valid generated bcrypt hash, not just a string with the right prefix and length.
**Prevention:** Always generate dummy hashes using the actual target library (e.g., `bcrypt.GenerateFromPassword`) rather than trying to handcraft or truncate them to ensure they take the exact same compute path as a real check.

## 2024-05-30 - 2FA Brute-Force Rate-Limit Bypass in Profile Operations
**Vulnerability:** Similar to the 2FA authentication flow, profile operations like `DisableTOTP` and `ChangePassword` were lacking pre-execution rate limit checks on 2FA validation and password checks. This allowed brute-force attacks against a user's 2FA secret or password after they had already authenticated.
**Learning:** Rate-limiting logic must be applied consistently to all endpoints that perform cryptographic validation of user secrets, regardless of whether it's an authentication flow or a profile settings change.
**Prevention:** Always implement `core.IsRateLimitExceeded` before executing `totp.Validate` or `core.CheckPasswordHash`, and increment the rate limit on failure, across all relevant handlers.

## 2024-05-30 - Handler Modularization for Maintainability
**Issue:** The `Login` handler was overly long and complex, making it difficult to test and maintain.
**Learning:** Extracting logical blocks into private helper methods (`checkUserThrottling`, `verifyCredentials`, `handleAuthFailure`, etc.) improves readability and allows for better reasoning about security flows.
**Prevention:** Regularly refactor complex handlers into smaller, purpose-built private methods while ensuring all security checks (rate limiting, dummy hashes) are preserved exactly.
## 2026-05-27 - [Rate Limit Bypass & DoS in Auth]
**Vulnerability:** Rate limiting counter incremented before validating the user password, and incorrect limit configuration used for 2FA checks.
**Learning:** Incrementing limits before checking logic enables a trivial DoS, locking out users without needing their credentials. Furthermore, mixing configuration values (IP limit vs User limit) leads to incorrect protections.
**Prevention:** Always perform checks using non-incrementing helpers (like `core.IsRateLimitExceeded`) first, and only increment (e.g., `core.CheckRateLimit`) when the authorization/validation check fails. Also ensure configurations are mapped securely to their intended context.

## 2025-02-27 - Open Redirect / HTTP Parameter Injection in Auth Middleware
**Vulnerability:** In `internal/middleware/auth.go`, when a request was unauthorized, the middleware would redirect the user to `/rauthlogin?rd=` appended directly with `c.Request().RequestURI`. An attacker could exploit this by appending characters like `&` and `=` to manipulate parameters, causing HTTP Parameter Injection, or potentially bypass open redirect mitigations depending on how `rd` was processed by the login handler.
**Learning:** Raw request URIs or arbitrary user inputs must be properly URL-encoded before being interpolated into a new URL's query parameters to ensure they are treated purely as data and not structural characters.
**Prevention:** Always use `url.QueryEscape` when passing URIs or paths as query parameters in redirect flows.

## 2026-05-30 - User Record Corruption via UpdateUserEmail
**Vulnerability:** The `UpdateUserEmail` handler in `internal/handlers/admin.go` was updating user email records in Redis without verifying if the target user actually existed. Because `core.UpdateUser` uses Redis `HSet`, this operation could create "orphan" or "ghost" user hashes (e.g., `user:nonexistent`) that only contain an email field, lacking usernames, passwords, and UIDs.
**Learning:** Functions that perform partial updates on hash records must ensure the entity's existence first to maintain data integrity and prevent the creation of incomplete or corrupted records in the data store.
**Prevention:** Always use `core.GetUser` or an equivalent existence check before calling `core.UpdateUser` to ensure the target record is valid and fully initialized.
