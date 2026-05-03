## 2024-03-24 - Rate Limiting Bypass on 2FA
**Vulnerability:** The `Verify2FA` and `CompleteSetup2FA` functions lacked user-specific rate limiting (`login_fail_user`).
**Learning:** An attacker who compromises a user's password could bypass 2FA by brute-forcing the 6-digit TOTP code across different IPs without locking the user account. Rate limits must be applied at multiple layers (IP + User) simultaneously.
**Prevention:** Apply both IP-based and user-based rate-limiting constraints to *all* authentication challenge stages. Ensure the fail counter is only incremented when the challenge actually fails, and resets upon success.

## 2024-05-03 - Open Redirect to XSS via Absolute URLs
**Vulnerability:** The redirect parameter (`rd`) validation checked for valid hostnames for absolute URLs but failed to enforce strict protocol boundaries, allowing `javascript:` URIs to execute arbitrary code if a user clicked a crafted login link.
**Learning:** The `url.Parse().Hostname()` function ignores the URI scheme. An attacker can set `rd=javascript://allowed-host/%0Aalert(1)` to bypass the host allowlist while achieving XSS.
**Prevention:** Always explicitly whitelist `http` and `https` schemes when validating absolute URLs during redirects.
