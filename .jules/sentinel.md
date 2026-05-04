## 2024-03-24 - Rate Limiting Bypass on 2FA
**Vulnerability:** The `Verify2FA` and `CompleteSetup2FA` functions lacked user-specific rate limiting (`login_fail_user`).
**Learning:** An attacker who compromises a user's password could bypass 2FA by brute-forcing the 6-digit TOTP code across different IPs without locking the user account. Rate limits must be applied at multiple layers (IP + User) simultaneously.
**Prevention:** Apply both IP-based and user-based rate-limiting constraints to *all* authentication challenge stages. Ensure the fail counter is only incremented when the challenge actually fails, and resets upon success.

## 2025-05-02 - Fix XSS vulnerability via open redirect scheme validation
**Vulnerability:** The open redirect logic allowed absolute URLs without verifying their scheme, opening the door for XSS via `javascript:` or `data:` schemes (e.g., `javascript://example.com/%0Aalert(1)`).
**Learning:** Checking `IsAllowedHost` is insufficient if the scheme is not explicitly restricted to `http` or `https`, as browsers will execute code for other URI schemes while still matching the hostname.
**Prevention:** Always ensure that an absolute URL's scheme is strictly limited to `http` or `https` in combination with host whitelisting when processing redirects.
## 2026-05-04 - 2FA Rate Limit Bypass
**Vulnerability:** The application evaluated TOTP codes using `totp.Validate` before applying the user-specific rate limit check. This allowed attackers to guess thousands of 2FA codes, as the failure penalty was only applied sequentially *after* the computationally expensive TOTP logic was verified.
**Learning:** Checking the rate limit only after executing the validation logic fails open against distributed brute-force attacks.
**Prevention:** In authentication or challenge endpoints, always check rate limit capacity as a precondition (pre-check) before executing cryptographic verifications or database checks.
