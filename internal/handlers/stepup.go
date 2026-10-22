package handlers

import (
	"net/http"
	"rauth/internal/core"

	"github.com/labstack/echo/v4"
)

// verifyStepUp re-authenticates the signed-in user before a sensitive
// credential change (adding or revoking a passkey). Users with TOTP must
// provide a current code; users without TOTP must provide their password.
// A valid session cookie alone is never enough.
func verifyStepUp(cfg *core.Config, username, otpCode, password string) *echo.HTTPError {
	userRecord, err := core.GetUser(username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "User not found")
	}

	if userRecord.TwoFactor != "" {
		p := &ProfileHandler{Cfg: cfg}
		return p.validateTOTP(username, otpCode, userRecord.TwoFactor)
	}

	if password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Current password required")
	}
	if core.IsRateLimitExceeded("login_fail_user:"+username, cfg.RateLimitLoginFailUserMax) {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many failed attempts. Please try again later.")
	}
	if !core.CheckPasswordHash(password, userRecord.Password) {
		core.CheckRateLimit("login_fail_user:"+username, cfg.RateLimitLoginFailUserMax, cfg.RateLimitLoginFailUserDecay)
		return echo.NewHTTPError(http.StatusBadRequest, "Current password incorrect")
	}
	return nil
}
