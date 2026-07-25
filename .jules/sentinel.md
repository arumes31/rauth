# Sentinel Security Audits

## 2024-05-20 - Open Redirect via Absolute URL Scheme Bypass
**Vulnerability:** The open redirect logic allowed absolute URLs without verifying their scheme, opening the door for XSS via `javascript:` or `data:` schemes (e.g., `javascript://example.com/%0Aalert(1)`).
**Learning:** Checking `IsAllowedHost` is insufficient if the scheme is not explicitly restricted to `http` or `https`, as browsers will execute code for other URI schemes while still matching the hostname.
**Prevention:** Always ensure that an absolute URL's scheme is strictly limited to `http` or `https` in combination with host whitelisting when processing redirects.

## 2024-05-20 - Browser Normalization Open Redirect Bypass
**Vulnerability:** The open redirect validation `ValidateRedirectURL` failed to sanitize leading spaces and verify against `/\` and `\\` prefixes.
**Learning:** Modern browsers automatically normalize prefixes like `/\` and `\\` to `//` (protocol-relative), and leading spaces can bypass a prefix check.
**Prevention:** In redirect validation logic, inputs must have leading whitespace trimmed. Checks for protocol-relative bypasses must include alternative protocol-relative path prefixes (`/\` and `\\`).

## 2024-05-30 - 2FA Brute-Force Rate-Limit Bypass
**Vulnerability:** Rate limiting for 2FA attempts was checked and enforced *after* the computationally expensive cryptographic TOTP validation.
**Learning:** Security checks (like rate limiting) must always occur before the protected action or validation.
**Prevention:** Implement pre-execution checks prior to sensitive or costly operations.

## 2024-05-22 - Fix Username Enumeration Timing Attack
**Vulnerability:** A timing attack vulnerability existed in the login flow where the dummy bcrypt hash was invalid and rejected immediately.
**Learning:** `bcrypt.CompareHashAndPassword` immediately returns an error without doing any compute if the hash length or format is invalid.
**Prevention:** Always generate dummy hashes using the actual target library to ensure they take the same compute path.

## 2024-05-30 - 2FA Brute-Force Rate-Limit Bypass in Profile Operations
**Vulnerability:** Profile operations were lacking pre-execution rate limit checks on 2FA validation and password checks.
**Learning:** Rate-limiting logic must be applied consistently to all endpoints that perform cryptographic validation.
**Prevention:** Always implement rate limits before executing cryptographic checks across all relevant handlers.

## 2024-05-30 - Handler Modularization for Maintainability
**Issue:** The `Login` handler was overly long and complex.
**Learning:** Extracting logical blocks into private helper methods improves readability and security reasoning.
**Prevention:** Regularly refactor complex handlers into smaller, purpose-built methods.

## 2026-05-27 - [Rate Limit Bypass & DoS in Auth]
**Vulnerability:** Rate limiting counter incremented before validating the user password.
**Learning:** Incrementing limits before checking logic enables a trivial DoS.
**Prevention:** Perform checks using non-incrementing helpers first.

## 2025-02-27 - Open Redirect / HTTP Parameter Injection in Auth Middleware
**Vulnerability:** In `internal/middleware/auth.go`, when a request was unauthorized, the middleware would redirect the user to `/rauthlogin?rd=` appended directly with `c.Request().RequestURI`. An attacker could exploit this by appending characters like `&` and `=` to manipulate parameters, causing HTTP Parameter Injection, or potentially bypass open redirect mitigations depending on how `rd` was processed by the login handler.
**Learning:** Raw request URIs or arbitrary user inputs must be properly URL-encoded before being interpolated into a new URL's query parameters to ensure they are treated purely as data and not structural characters.
**Prevention:** Always use `url.QueryEscape` when passing URIs or paths as query parameters in redirect flows.

## 2026-06-02 - Insecure Cookie Deletion
**Vulnerability:** A cookie deletion function in `internal/handlers/webauthn.go` did not set `SameSite: http.SameSiteLaxMode` mirroring the cookie creation options, possibly allowing persistent session vulnerability or causing the browser to refuse to delete the cookie due to mismatched security attributes.
**Learning:** Browsers may refuse to delete a cookie if the security attributes (Secure, HttpOnly, SameSite) do not exactly match the original creation parameters.
**Prevention:** Always mirror the security attributes (`Secure`, `HttpOnly`, `SameSite`) when deleting a cookie by setting `MaxAge: -1`.

## 2026-06-02 - False Positive Gosec G302 on Directory Permissions
**Vulnerability:** A false positive Gosec warning G302 on `os.Chmod` expecting permissions 0600 or less, even though it was setting directory permissions to 0700.
**Learning:** `os.Chmod` with permissions greater than 0600 triggers a `gosec` G302 warning. However, for directories, 0700 or greater is expected because the execute bit is required to traverse directories.
**Prevention:** Use a `// #nosec G302` comment before `os.Chmod` for directories to prevent the false positive alert.

## 2025-02-27 - Suffix Abuse Protection in Host Validation
**Vulnerability:** Hostname validation using simple suffix matching (e.g., `strings.HasSuffix(host, domain)`) allows "suffix abuse" where an attacker can use a domain like `evil-example.com` to bypass a check intended for `example.com`.
**Learning:** Subdomain matching must always ensure that the matched suffix is either the exact domain or is preceded by a dot (e.g., `.example.com`).
**Prevention:** Always prepend a dot to the domain when using suffix matching for hostnames: `strings.HasSuffix(host, "."+domain)`. Robust test suites should include cases like `evil-domain.com`, `notdomain.com`, and deep subdomains to ensure regex or string matching logic is sound.

## 2026-06-02 - Missing Username Validation and Existence Checks in Admin User Management
**Vulnerability:** Admin user management handlers (`CreateUser`, `DeleteUser`, `ResetUser2FA`, `ChangeUserPassword`, `UpdateUserEmail`) were missing robust username validation and existence checks. They accepted raw, untrimmed inputs and proceeded to perform operations even if the target user did not exist or (in the case of creation) was invalid, potentially leading to data integrity issues or side-effects on non-existent records.
**Learning:** Even internal admin-only endpoints must rigorously validate all inputs. Assuming data is safe because it comes from an authorized user is a dangerous anti-pattern.
**Prevention:** Always use centralized validation helpers (like `core.ValidateUsername`) and explicitly verify resource existence (e.g., `core.GetUser`) before processing management actions. Trim whitespace from all user-provided identifiers.

## 2026-06-06 - 2FA Verification Account Lockout DoS
**Vulnerability:** The 2FA verification logic (`Verify2FA` and `CompleteSetup2FA`) used `ReserveRateLimitAttempt` before verifying the token, which unconditionally increments the failure count on every attempt. This allows an attacker to spam invalid 2FA attempts to trivially lock a legitimate user out of their account.
**Learning:** Security checks that consume rate limits must only increment the failure count when the check actually fails, and only perform a read-only check (`IsRateLimitExceeded`) prior to execution.
**Prevention:** Use non-mutating rate limit checks before executing sensitive operations, and conditionally apply the rate limit penalty strictly on the failure path.
## 2026-06-12 - Rate Limiting Before DB Lookups
**Vulnerability:** Rate limits on the invite redemption endpoint were checked *after* querying the Redis database for the invite token. This allowed attackers to bypass IP rate limits for invalid tokens and spam the database, causing a potential DoS.
**Learning:** Always enforce rate limiting based on the request origin (IP, user) *before* performing any backend operations like database reads to protect infrastructure from exhaustion attacks.
**Prevention:** Apply rate-limiting checks at the very beginning of the handler function, prior to any external calls or expensive computations.
## 2026-06-23 - Missing escapeHtml in innerHTML string interpolation
**Vulnerability:** DOM-based XSS vulnerability due to unescaped interpolations in custom vanilla JS modal `rauthDialog`. Both user-facing dialog messages and template variables were vulnerable to injection via `innerHTML`.
**Learning:** Developers building custom UI components (like dialog overlays) in vanilla JS sometimes use template literals + `innerHTML` directly without properly escaping inputs first, treating them like React props which inherently escape.
**Prevention:** Establish a global or reusable `escapeHtml` utility and mandate its usage for all dynamic values being interpolated into HTML template literals prior to assignment to `innerHTML`.
## 2024-05-31 - Fast-Path Rate Limiting Missing c.FormValue Exhaustion Fix
**Vulnerability:** A fast-path rate limit implementation attempting to avoid parsing `c.FormValue()` (which reads the request body and can cause exhaustion DoS with large payloads) was still indirectly parsing the form by using a global `getRD()` helper that called `c.FormValue()`.
**Learning:** When attempting to implement early fast-paths to bypass body parsing on limited connections, all helper functions utilized in the error response must be audited. Functions that conditionally fall back to form parsing (`getRD` via `c.FormValue`) will silently defeat the fast-path check, rendering the protection ineffective against resource exhaustion.
**Prevention:** In fast-path error handlers that aim to avoid parsing large bodies (like early rate limits), strictly use `c.QueryParam()` instead of shared helper functions that may fall back to parsing `c.FormValue()`.
## 2026-06-25 - [Rate Limit Fast Path Bypass]
**Vulnerability:** Fast-path rate limit implementations calling `getRD(c)` implicitly parsed the form body using `c.FormValue("rd")`, bypassing exhaustion DoS protection.
**Learning:** All helper functions in early fast-path error handlers must be carefully audited to ensure they do not perform body parsing.
**Prevention:** Use `c.QueryParam("rd")` instead of `getRD(c)` to only parse query parameters for redirects.
