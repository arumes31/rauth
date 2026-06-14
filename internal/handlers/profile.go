package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"rauth/internal/core"
	"strings"

	"github.com/redis/go-redis/v9"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
)

type ProfileHandler struct {
	Cfg *core.Config
}

func (h *ProfileHandler) Show(c echo.Context) error {
	username := c.Get("username").(string)
	currentToken := c.Get("token").(string)
	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil {
		slog.Error("Failed to fetch user data", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load profile")
	}

	// Fetch sessions for this user efficiently
	tokens, err := core.TokenDB.SMembers(core.Ctx, "user_sessions:"+username).Result()
	if err != nil {
		slog.Error("Failed to fetch sessions from Redis", "error", err)
	}

	var sessions []map[string]string
	pipe := core.TokenDB.Pipeline()
	cmds := make(map[string]*redis.MapStringStringCmd)
	ttlCmds := make(map[string]*redis.DurationCmd)

	for _, token := range tokens {
		redisKey := "X-rauth-authtoken=" + token
		cmds[token] = pipe.HGetAll(core.Ctx, redisKey)
		ttlCmds[token] = pipe.TTL(core.Ctx, redisKey)
	}
	_, pipeErr := pipe.Exec(core.Ctx)
	if pipeErr != nil {
		slog.Error("Failed to execute session details pipeline", "error", pipeErr)
	}

	for _, token := range tokens {
		data, err := cmds[token].Result()
		if err != nil || len(data) == 0 {
			// Only clean up stale index entries if the pipeline succeeded
			// (individual key miss), not on a wholesale pipeline failure.
			if pipeErr == nil {
				core.RemoveSessionIndex(username, token)
			}
			continue
		}
		data["token"] = token
		data["is_current"] = "0"
		if token == currentToken {
			data["is_current"] = "1"
		}
		ttl := ttlCmds[token].Val()
		data["ttl"] = fmt.Sprintf("%d", int(ttl.Seconds()))

		// Use Client Hints if available to enhance the friendly UA
		ua := data["user_agent"]
		friendlyUA := core.FormatUserAgent(ua)
		if model := data["ua_ch_model"]; model != "" && model != "Unknown" {
			friendlyUA += fmt.Sprintf(" [%s]", strings.Trim(model, "\""))
		}
		if mobile := data["ua_ch_mobile"]; mobile == "?1" {
			if !strings.Contains(friendlyUA, "[Mobile]") {
				friendlyUA += " [Mobile]"
			}
		}

		data["friendly_ua"] = friendlyUA
		data["device_icon"] = core.GetDeviceIcon(ua)
		sessions = append(sessions, data)
	}

	// Personal Logs
	rawLogs, err := core.AuditDB.LRange(core.Ctx, "user_audit_logs:"+username, 0, 99).Result()
	if err != nil {
		slog.Error("Failed to fetch audit logs", "error", err)
	}

	var logs []core.AuditLog
	for _, l := range rawLogs {
		var log core.AuditLog
		if err := json.Unmarshal([]byte(l), &log); err != nil {
			continue
		}
		logs = append(logs, log)
	}

	passkeys := core.GetStoredCredentials(username)

	return c.Render(http.StatusOK, "profile.html", map[string]interface{}{
		"username":      username,
		"email":         userData["email"],
		"groups":        userData["groups"],
		"isAdmin":       userData["is_admin"] == "1",
		"has2FA":        userData["2fa_secret"] != "",
		"recoveryCount": core.CountRecoveryCodes(username),
		"sessions":      sessions,
		"logs":          logs,
		"passkeys":      passkeys,
		"csrf":          c.Get("csrf"),
	})
}

// GenerateRecoveryCodes issues a fresh batch of single-use 2FA recovery codes
// after re-verifying the user's current TOTP code, and displays them once.
func (h *ProfileHandler) GenerateRecoveryCodes(c echo.Context) error {
	username := c.Get("username").(string)

	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal error")
	}
	if userData["2fa_secret"] == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Enable TOTP before generating recovery codes")
	}

	otpCode := c.FormValue("otp_code")
	if herr := h.validateTOTP(username, otpCode, userData["2fa_secret"]); herr != nil {
		return herr
	}

	codes, err := core.GenerateRecoveryCodes(username)
	if err != nil {
		slog.Error("Failed to generate recovery codes", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate recovery codes")
	}

	core.LogAudit("2FA_RECOVERY_CODES_GENERATED", username, c.RealIP(), nil)
	// The freshly generated codes are sensitive; keep them out of any cache.
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")
	return c.Render(http.StatusOK, "recovery_codes.html", map[string]interface{}{
		"codes":    codes,
		"username": username,
	})
}

func (h *ProfileHandler) RenamePasskey(c echo.Context) error {
	username := c.Get("username").(string)
	credID := c.FormValue("id")
	nickname := c.FormValue("nickname")

	if credID == "" || nickname == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ID and Nickname are required")
	}

	if err := core.UpdateWebAuthnNickname(username, credID, nickname); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to rename passkey")
	}

	core.LogAudit("PASSKEY_RENAME", username, c.RealIP(), map[string]interface{}{"nickname": nickname})
	return c.Redirect(http.StatusFound, "/rauthprofile?success=passkey_renamed")
}

func (h *ProfileHandler) RevokePasskey(c echo.Context) error {
	username := c.Get("username").(string)
	credID := c.FormValue("id")

	if credID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "ID is required")
	}

	if err := core.DeleteWebAuthnCredential(username, credID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke passkey")
	}

	// Send notification email
	email, _ := core.UserDB.HGet(core.Ctx, "user:"+username, "email").Result()
	if email != "" {
		device := core.FormatDevice(c.Request().UserAgent(),
			c.Request().Header.Get("Sec-CH-UA-Platform"),
			c.Request().Header.Get("Sec-CH-UA-Mobile"),
			c.Request().Header.Get("Sec-CH-UA-Model"))
		go core.Send2FAModifiedNotification(core.TwoFactorNotificationOptions{Email: email, Username: username, Action: "Removed (Passkey)", IP: c.RealIP(), Device: device})
	}

	core.LogAudit("PASSKEY_REVOKE", username, c.RealIP(), nil)
	return c.Redirect(http.StatusFound, "/rauthprofile?success=passkey_revoked")
}

func (h *ProfileHandler) DisableTOTP(c echo.Context) error {
	username := c.Get("username").(string)
	otpCode := c.FormValue("otp_code")

	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal error")
	}

	if userData["2fa_secret"] != "" {
		if err := h.validateTOTP(username, otpCode, userData["2fa_secret"]); err != nil {
			return c.JSON(err.Code, map[string]string{"error": err.Message.(string)})
		}
	}

	if err := core.UpdateUser(username, map[string]interface{}{"2fa_secret": ""}); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to disable TOTP")
	}
	// Recovery codes are tied to TOTP; clear them so stale codes can't be used.
	core.ClearRecoveryCodes(username)

	// Send notification email
	if userData["email"] != "" {
		device := core.FormatDevice(c.Request().UserAgent(),
			c.Request().Header.Get("Sec-CH-UA-Platform"),
			c.Request().Header.Get("Sec-CH-UA-Mobile"),
			c.Request().Header.Get("Sec-CH-UA-Model"))
		go core.Send2FAModifiedNotification(core.TwoFactorNotificationOptions{Email: userData["email"], Username: username, Action: "Disabled (TOTP)", IP: c.RealIP(), Device: device})
	}

	core.LogAudit("USER_DISABLE_TOTP", username, c.RealIP(), nil)
	return c.Redirect(http.StatusFound, "/rauthprofile?success=totp_disabled")
}

func (h *ProfileHandler) TerminateSession(c echo.Context) error {
	username := c.Get("username").(string)
	token := c.FormValue("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Token is required")
	}

	redisKey := "X-rauth-authtoken=" + token
	// ⚡ Bolt optimization: Use HGet instead of HGetAll to avoid fetching/parsing unnecessary fields since we only need 'username'.
	sessionUsername, err := core.TokenDB.HGet(core.Ctx, redisKey, "username").Result()
	if err != nil || sessionUsername == "" {
		return c.Redirect(http.StatusFound, "/rauthprofile")
	}

	// Security: Ensure user owns this session
	if sessionUsername != username {
		slog.Warn("Unauthorized session termination attempt", "user", username, "target_token", token)
		return echo.NewHTTPError(http.StatusForbidden, "You can only terminate your own sessions")
	}

	core.RemoveSessionIndex(username, token)
	core.TokenDB.Del(core.Ctx, redisKey)
	logToken := token
	if len(logToken) > 8 {
		logToken = logToken[:8] + "..."
	}
	core.LogAudit("USER_TERMINATE_SESSION", username, c.RealIP(), map[string]interface{}{"token": logToken})

	return c.Redirect(http.StatusFound, "/rauthprofile?success=session_terminated")
}

func (h *ProfileHandler) TerminateAllOtherSessions(c echo.Context) error {
	username := c.Get("username").(string)
	currentToken := c.Get("token").(string)

	core.InvalidateOtherUserSessions(username, currentToken)
	core.LogAudit("USER_TERMINATE_ALL_OTHER_SESSIONS", username, c.RealIP(), nil)

	return c.Redirect(http.StatusFound, "/rauthprofile?success=sessions_terminated")
}

func (h *ProfileHandler) ChangePassword(c echo.Context) error {
	username := c.Get("username").(string)
	current := c.FormValue("current_password")
	newPass := c.FormValue("new_password")
	confirm := c.FormValue("confirm_password")
	otpCode := c.FormValue("otp_code")

	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil {
		slog.Error("Failed to fetch user data for password change", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal error")
	}

	if core.IsRateLimitExceeded("login_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax) {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many failed attempts. Please try again later."})
	}
	if !core.CheckPasswordHash(current, userData["password"]) {
		core.CheckRateLimit("login_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Current password incorrect"})
	}

	// 2FA Verification if enabled
	if userData["2fa_secret"] != "" {
		if err := h.validateTOTP(username, otpCode, userData["2fa_secret"]); err != nil {
			return c.JSON(err.Code, map[string]string{"error": err.Message.(string)})
		}
	}

	if newPass != confirm {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Passwords do not match"})
	}

	if err := core.ValidatePassword(newPass, h.Cfg); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	hash, err := core.HashPassword(newPass)
	if err != nil {
		slog.Error("Failed to hash new password", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update password")
	}

	if err := core.UpdateUser(username, map[string]interface{}{"password": hash}); err != nil {
		slog.Error("Failed to update user password in Redis", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update password")
	}

	// Send notification email
	if userData["email"] != "" {
		device := core.FormatDevice(c.Request().UserAgent(),
			c.Request().Header.Get("Sec-CH-UA-Platform"),
			c.Request().Header.Get("Sec-CH-UA-Mobile"),
			c.Request().Header.Get("Sec-CH-UA-Model"))
		go core.SendPasswordChangeNotification(userData["email"], username, c.RealIP(), device)
	}

	// Security Hardening: Invalidate all other sessions. The current session
	// stays alive so the success redirect to the profile page does not bounce
	// the user straight back to the login form.
	currentToken, _ := c.Get("token").(string)
	core.InvalidateOtherUserSessions(username, currentToken)

	slog.Info("Password changed by user", "user", username)
	core.LogAudit("USER_CHANGE_PASSWORD", username, c.RealIP(), nil)

	return c.Redirect(http.StatusFound, "/rauthprofile?success=password_changed")
}

func (h *ProfileHandler) validateTOTP(username, otpCode, encryptedSecret string) *echo.HTTPError {
	if otpCode == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "2FA code required")
	}
	if core.IsRateLimitExceeded("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax) {
		return echo.NewHTTPError(http.StatusTooManyRequests, "Too many failed attempts. Please try again later.")
	}
	secret := core.Decrypt2FASecret(encryptedSecret, h.Cfg.ServerSecret)
	if !totp.Validate(otpCode, secret) {
		core.CheckRateLimit("2fa_fail_user:"+username, h.Cfg.RateLimitLoginFailUserMax, h.Cfg.RateLimitLoginFailUserDecay)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid 2FA code")
	}
	// Enforce single-use of the TOTP code (same replay protection as the login
	// flow), so an intercepted code cannot be replayed to repeat or chain
	// sensitive profile actions within its validity window.
	if core.TOTPCodeReused(username, otpCode) {
		return echo.NewHTTPError(http.StatusBadRequest, "This code was already used. Please wait for a new code.")
	}
	return nil
}
