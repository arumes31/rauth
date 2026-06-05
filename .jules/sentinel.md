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

## 2026-06-05 - Rate Limit Bypass & DoS in Invite Redemption
**Vulnerability:** The invite redemption endpoint (`/rauthredeem`) lacked rate-limiting controls, potentially allowing an attacker to brute force tokens or rapidly exhaust database connections via repeated invalid requests.
**Learning:** All endpoints that accept arbitrary user input and perform database interactions or sensitive logic must enforce rate limits based on client identity (e.g. IP address) to prevent resource exhaustion and brute force attempts.
**Prevention:** Apply the existing `core.CheckRateLimit` logic, using appropriate parameters such as `RateLimitRegistrationMax`, to any endpoint processing registrations or code redemptions.
