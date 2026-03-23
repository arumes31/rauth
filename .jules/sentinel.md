## 2024-03-24 - Rate Limiting Bypass on 2FA
**Vulnerability:** The `Verify2FA` and `CompleteSetup2FA` functions lacked user-specific rate limiting (`login_fail_user`).
**Learning:** An attacker who compromises a user's password could bypass 2FA by brute-forcing the 6-digit TOTP code across different IPs without locking the user account. Rate limits must be applied at multiple layers (IP + User) simultaneously.
**Prevention:** Apply both IP-based and user-based rate-limiting constraints to *all* authentication challenge stages. Ensure the fail counter is only incremented when the challenge actually fails, and resets upon success.
