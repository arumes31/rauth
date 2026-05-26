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

## 2026-05-26 - Missing Email Validation in Administrative and Invitation Flows
**Vulnerability:** User-provided email addresses were not validated for correct format in the `CreateUser` and `UpdateUserEmail` administrative handlers, as well as in the `Create` invitation handler. This could lead to malformed data in the database and potential issues with notification emails.
**Learning:** Validating email format is essential not only for data integrity but also for security, as it prevents the injection of malformed strings into email-related processes.
**Prevention:** Always use a standard regular expression or a dedicated validation library to verify email formats at the handler level before processing or storing them.
