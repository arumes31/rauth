package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"rauth/internal/core"

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

	// Fetch sessions for this user
	keys, err := core.TokenDB.Keys(core.Ctx, "X-rauth-authtoken=*").Result()
	if err != nil {
		slog.Error("Failed to fetch sessions from Redis", "error", err)
	}

	var sessions []map[string]string
	for _, k := range keys {
		data, err := core.TokenDB.HGetAll(core.Ctx, k).Result()
		if err != nil {
			continue
		}
		if data["username"] == username {
			token := k[18:] // Remove prefix "X-rauth-authtoken="
			data["token"] = token
			data["is_current"] = "0"
			if token == currentToken {
				data["is_current"] = "1"
			}
			data["ttl"] = fmt.Sprintf("%d", int(core.TokenDB.TTL(core.Ctx, k).Val().Seconds()))
			sessions = append(sessions, data)
		}
	}

	// Personal Logs
	rawLogs, err := core.AuditDB.LRange(core.Ctx, "audit_logs", 0, 500).Result()
	if err != nil {
		slog.Error("Failed to fetch audit logs", "error", err)
	}

	var logs []core.AuditLog
	for _, l := range rawLogs {
		var log core.AuditLog
		if err := json.Unmarshal([]byte(l), &log); err != nil {
			continue
		}
		if log.Username == username {
			logs = append(logs, log)
		}
	}

	passkeys := core.GetStoredCredentials(username)

	return c.Render(http.StatusOK, "profile.html", map[string]interface{}{
		"username":  username,
		"email":     userData["email"],
		"groups":    userData["groups"],
		"isAdmin":   userData["is_admin"] == "1",
		"has2FA":    userData["2fa_secret"] != "",
		"sessions":  sessions,
		"logs":      logs,
		"passkeys":  passkeys,
		"csrf":      c.Get("csrf"),
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
	return c.Redirect(http.StatusFound, "/rauthprofile")
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

	core.LogAudit("PASSKEY_REVOKE", username, c.RealIP(), nil)
	return c.Redirect(http.StatusFound, "/rauthprofile")
}

func (h *ProfileHandler) TerminateSession(c echo.Context) error {
	username := c.Get("username").(string)
	token := c.FormValue("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Token is required")
	}

	redisKey := "X-rauth-authtoken=" + token
	data, err := core.TokenDB.HGetAll(core.Ctx, redisKey).Result()
	if err != nil || len(data) == 0 {
		return c.Redirect(http.StatusFound, "/rauthprofile")
	}

	// Security: Ensure user owns this session
	if data["username"] != username {
		slog.Warn("Unauthorized session termination attempt", "user", username, "target_token", token)
		return echo.NewHTTPError(http.StatusForbidden, "You can only terminate your own sessions")
	}

	core.TokenDB.Del(core.Ctx, redisKey)
	core.LogAudit("USER_TERMINATE_SESSION", username, c.RealIP(), map[string]interface{}{"token": token[:8] + "..."})

	return c.Redirect(http.StatusFound, "/rauthprofile")
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

	if !core.CheckPasswordHash(current, userData["password"]) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Current password incorrect"})
	}

	// 2FA Verification if enabled
	if userData["2fa_secret"] != "" {
		if otpCode == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "2FA code required"})
		}
		secret := core.Decrypt2FASecret(userData["2fa_secret"], h.Cfg.ServerSecret)
		if !totp.Validate(otpCode, secret) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid 2FA code"})
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
	userRecord, _ := core.GetUser(username)
	if userRecord.Email != "" {
		go core.SendPasswordChangeNotification(userRecord.Email, username, c.RealIP())
	}

	// Security Hardening: Invalidate all other sessions
	core.InvalidateUserSessions(username)

	slog.Info("Password changed by user", "user", username)
	core.LogAudit("USER_CHANGE_PASSWORD", username, c.RealIP(), nil)

	return c.Redirect(http.StatusFound, "/rauthprofile?success=1")
}
