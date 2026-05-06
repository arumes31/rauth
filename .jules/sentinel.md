## 2024-03-24 - Rate Limiting Bypass on 2FA
**Vulnerability:** The `Verify2FA` and `CompleteSetup2FA` functions lacked user-specific rate limiting (`login_fail_user`).
**Learning:** An attacker who compromises a user's password could bypass 2FA by brute-forcing the 6-digit TOTP code across different IPs without locking the user account. Rate limits must be applied at multiple layers (IP + User) simultaneously.
**Prevention:** Apply both IP-based and user-based rate-limiting constraints to *all* authentication challenge stages. Ensure the fail counter is only incremented when the challenge actually fails, and resets upon success.

## 2025-05-02 - Fix XSS vulnerability via open redirect scheme validation
**Vulnerability:** The open redirect logic allowed absolute URLs without verifying their scheme, opening the door for XSS via `javascript:` or `data:` schemes (e.g., `javascript://example.com/%0Aalert(1)`).
**Learning:** Checking `IsAllowedHost` is insufficient if the scheme is not explicitly restricted to `http` or `https`, as browsers will execute code for other URI schemes while still matching the hostname.
**Prevention:** Always ensure that an absolute URL's scheme is strictly limited to `http` or `https` in combination with host whitelisting when processing redirects.

## 2024-05-06 - 2FA Brute Force Protection bypass
**Vulnerability:** The 2FA verification (`Verify2FA`) and 2FA setup completion (`CompleteSetup2FA`) handlers processed rate limit checks *after* performing the expensive `totp.Validate` check or checked the IP-level configuration value against user-level rate limiting keys. Additionally, the user-level lockout was missing completely in `CompleteSetup2FA` and placed too late in `Verify2FA`.
**Learning:** Checking a rate limit by incrementing *after* failure is not enough to prevent side-channel timing attacks or immediate brute force floods against TOTP validators, especially if a copy-paste error compares user counters against IP rate limit maximums (which are naturally higher). It is essential to perform a non-incrementing validation check (`IsRateLimitExceeded`) *before* executing the validation logic and to use the correct configuration limits for the key being checked.
**Prevention:** Always implement a proactive, non-incrementing check of failure counters prior to sensitive operations (like TOTP or password validation) to ensure the account is not already locked out. Validate configuration variables strictly match the scope (User vs IP) of the cache key being queried.
