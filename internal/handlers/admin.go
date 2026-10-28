package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"rauth/internal/core"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

type AdminHandler struct {
	Cfg *core.Config
}

func (h *AdminHandler) Dashboard(c echo.Context) error {
	users, err := core.ListUsers()
	if err != nil {
		slog.Error("Failed to list users", "error", err)
	}

	// Fetch sessions using Pipeline to avoid N+1 queries
	var sessions []map[string]string
	var keys []string
	var cursor uint64
	for {
		var keysChunk []string
		var err error
		keysChunk, cursor, err = core.TokenDB.Scan(core.Ctx, cursor, "X-rauth-authtoken=*", 1000).Result()
		if err != nil {
			slog.Error("Failed to scan sessions from Redis", "error", err)
			break
		}
		keys = append(keys, keysChunk...)
		if cursor == 0 {
			break
		}
	}

	if len(keys) > 0 {
		pipe := core.TokenDB.Pipeline()
		hGetAllCmds := make([]*redis.MapStringStringCmd, len(keys))
		ttlCmds := make([]*redis.DurationCmd, len(keys))

		for i, k := range keys {
			hGetAllCmds[i] = pipe.HGetAll(core.Ctx, k)
			ttlCmds[i] = pipe.TTL(core.Ctx, k)
		}

		_, err := pipe.Exec(core.Ctx)
		if err != nil && err != redis.Nil {
			slog.Error("Pipeline execution failed", "error", err)
		}

		for i, k := range keys {
			data, err := hGetAllCmds[i].Result()
			if err != nil {
				continue
			}
			if len(data) == 0 {
				continue
			}
			data["token"] = strings.TrimPrefix(k, "X-rauth-authtoken=")
			if data["token"] == k {
				slog.Warn("AdminDashboard: token key missing expected prefix", "key", k)
			}
			data["ttl"] = fmt.Sprintf("%d", int(ttlCmds[i].Val().Seconds()))

			// Use Client Hints if available to enhance the friendly UA
			ua := data["user_agent"]
			data["friendly_ua"] = core.FormatDevice(ua, "", data["ua_ch_mobile"], data["ua_ch_model"])
			data["device_icon"] = core.GetDeviceIcon(ua)
			sessions = append(sessions, data)
		}
	}

	// Fetch Audit Logs
	rawLogs, err := core.AuditDB.LRange(core.Ctx, "audit_logs", 0, 99).Result()
	if err != nil {
		slog.Error("Failed to fetch audit logs from Redis", "error", err)
	}

	var logs []core.AuditLog
	if len(rawLogs) > 0 {
		// Fallback approach: The combined JSON unmarshaling fails entirely if
		// even a single log entry is malformed, breaking fault tolerance.
		// We revert to looping, but pre-allocate the slice to save memory overhead.
		logs = make([]core.AuditLog, 0, len(rawLogs))
		for _, l := range rawLogs {
			var log core.AuditLog
			if err := json.Unmarshal([]byte(l), &log); err != nil {
				continue
			}
			logs = append(logs, log)
		}
	}

	// Step-up for bypass rule changes asks for TOTP if the admin has it,
	// otherwise the current password.
	adminHas2FA := false
	if adminName, ok := c.Get("username").(string); ok {
		if rec, err := core.GetUser(adminName); err == nil {
			adminHas2FA = rec.TwoFactor != ""
		}
	}

	return c.Render(http.StatusOK, "management.html", map[string]interface{}{
		"username":        c.Get("username"),
		"root_user":       h.Cfg.InitialUser,
		"users":           users,
		"sessions":        sessions,
		"logs":            logs,
		"csrf":            c.Get("csrf"),
		"bypass_rules":    bypassRuleViews(),
		"bypass_host_hdr": h.Cfg.AuthBypassHostHeader,
		"bypass_uri_hdr":  h.Cfg.AuthBypassURIHeader,
		"admin_has_2fa":   adminHas2FA,
	})
}

func (h *AdminHandler) CreateUser(c echo.Context) error {
	user := strings.TrimSpace(c.FormValue("new_username"))
	pass := c.FormValue("new_password")
	email := strings.TrimSpace(c.FormValue("new_email"))
	isAdmin := c.FormValue("is_admin") == "on"

	if user == "" || pass == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username and password are required")
	}

	if err := core.ValidateUsername(user); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if _, err := core.GetUser(user); err == nil {
		return echo.NewHTTPError(http.StatusConflict, "User already exists")
	}

	if email != "" {
		if err := core.ValidateEmail(email); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	}

	if err := core.ValidatePassword(pass, h.Cfg); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := core.CreateUser(user, pass, email, isAdmin, ""); err != nil {
		slog.Warn("Failed to create user", "user", user, "error", err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Send Welcome Email (Asynchronous)
	if email != "" {
		go core.SendAccountCreatedNotification(email, user)
	}

	slog.Info("User created by admin", "admin", c.Get("username"), "user", user)
	core.LogAudit("ADMIN_CREATE_USER", c.Get("username").(string), c.RealIP(), map[string]interface{}{"target": user})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=user_created")
}

func (h *AdminHandler) DeleteUser(c echo.Context) error {
	target := strings.TrimSpace(c.FormValue("username"))
	if target == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if err := core.ValidateUsername(target); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// INITIAL_USER identifies the bootstrap administrator, even when renamed
	// from the default "admin" in the deployment configuration.
	if target == h.Cfg.InitialUser {
		return echo.NewHTTPError(http.StatusForbidden, "Cannot delete the root administrator")
	}

	if _, err := core.GetUser(target); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	admin := c.Get("username").(string)
	if target == admin {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot delete yourself")
	}

	if err := core.DeleteUser(target); err != nil {
		slog.Error("Failed to delete user", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user")
	}

	slog.Info("User deleted by admin", "admin", admin, "user", target)
	core.LogAudit("ADMIN_DELETE_USER", admin, c.RealIP(), map[string]interface{}{"target": target})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=user_deleted")
}

func (h *AdminHandler) ResetUser2FA(c echo.Context) error {
	target := strings.TrimSpace(c.FormValue("username"))
	if target == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if err := core.ValidateUsername(target); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if _, err := core.GetUser(target); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	admin := c.Get("username").(string)
	if target == admin {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot reset your own 2FA via management. Use profile settings.")
	}

	if herr := h.guardRootAdmin(target, admin); herr != nil {
		return herr
	}

	err := core.UpdateUser(target, map[string]interface{}{"2fa_secret": ""})
	if err != nil {
		slog.Error("Failed to reset 2FA for user", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to reset 2FA")
	}
	// Reset every second factor: recovery codes are tied to TOTP, and a passkey
	// logs in without password or TOTP, so leaving one in place would let
	// whoever enrolled it (e.g. an attacker being evicted) straight back in.
	core.ClearRecoveryCodes(target)
	if err := core.DeleteAllWebAuthnCredentials(target); err != nil {
		slog.Error("Failed to clear passkeys during 2FA reset", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to reset 2FA")
	}

	// Security Hardening: revoke every session and pending login of this user.
	if herr := revokeUserAccess(target); herr != nil {
		return herr
	}

	slog.Info("2FA reset by admin", "admin", admin, "user", target)
	core.LogAudit("ADMIN_RESET_2FA", admin, c.RealIP(), map[string]interface{}{"target": target})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=2fa_reset")
}

func (h *AdminHandler) ChangeUserPassword(c echo.Context) error {
	target := strings.TrimSpace(c.FormValue("username"))
	if target == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if err := core.ValidateUsername(target); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if _, err := core.GetUser(target); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	newPass := c.FormValue("new_password")
	if newPass == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Password is required")
	}

	admin := c.Get("username").(string)
	if target == admin {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot change your own password via management. Use profile settings.")
	}
	if herr := h.guardRootAdmin(target, admin); herr != nil {
		return herr
	}

	if err := core.ValidatePassword(newPass, h.Cfg); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	hash, err := core.HashPassword(newPass)
	if err != nil {
		slog.Error("Failed to hash new password for user", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
	}

	if err := core.UpdateUser(target, map[string]interface{}{"password": hash}); err != nil {
		slog.Error("Failed to update user password in Redis", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update password")
	}

	// Security Hardening: revoke every session and pending login of this user,
	// including a half-finished 2FA setup started with the old password.
	if herr := revokeUserAccess(target); herr != nil {
		return herr
	}

	slog.Info("Password changed by admin", "admin", admin, "user", target)
	core.LogAudit("ADMIN_CHANGE_PASSWORD", admin, c.RealIP(), map[string]interface{}{"target": target})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=password_changed")
}

func (h *AdminHandler) UpdateUserEmail(c echo.Context) error {
	target := strings.TrimSpace(c.FormValue("username"))
	if target == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if err := core.ValidateUsername(target); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if _, err := core.GetUser(target); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	newEmail := strings.TrimSpace(c.FormValue("new_email"))
	if newEmail == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email is required")
	}

	if err := core.ValidateEmail(newEmail); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	admin := c.Get("username").(string)
	if herr := h.guardRootAdmin(target, admin); herr != nil {
		return herr
	}
	if err := core.UpdateUser(target, map[string]interface{}{"email": newEmail}); err != nil {
		slog.Error("Failed to update user email in Redis", "user", target, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update email")
	}

	slog.Info("User email updated by admin", "admin", admin, "user", target, "email", newEmail)
	core.LogAudit("ADMIN_UPDATE_EMAIL", admin, c.RealIP(), map[string]interface{}{"target": target, "email": newEmail})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=email_updated")
}

func (h *AdminHandler) InvalidateSession(c echo.Context) error {
	token := c.FormValue("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Token is required")
	}
	admin := c.Get("username").(string)

	redisKey := "X-rauth-authtoken=" + token
	// ⚡ Bolt optimization: Use HGet instead of HGetAll since we only need the username
	username, err := core.TokenDB.HGet(core.Ctx, redisKey, "username").Result()
	if err == nil && username != "" {
		core.RemoveSessionIndex(username, token)
	}

	if err := core.TokenDB.Del(core.Ctx, redisKey).Err(); err != nil {
		slog.Error("Failed to invalidate session", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to invalidate session")
	}

	slog.Info("Session invalidated by admin", "admin", admin)
	logToken := token
	if len(token) > 8 {
		logToken = token[:8] + "..."
	}
	core.LogAudit("ADMIN_INVALIDATE_SESSION", admin, c.RealIP(), map[string]interface{}{"token": logToken})
	return c.Redirect(http.StatusFound, "/rauthmgmt?success=session_terminated")
}

// guardRootAdmin stops other administrators from taking over the bootstrap
// (INITIAL_USER) account by resetting its credentials or its notification
// e-mail. The root administrator manages its own account from the profile page.
func (h *AdminHandler) guardRootAdmin(target, admin string) error {
	if target == h.Cfg.InitialUser && admin != h.Cfg.InitialUser {
		return echo.NewHTTPError(http.StatusForbidden, "Only the root administrator can change the root administrator account")
	}
	return nil
}

// revokeUserAccess invalidates every session and pending login of a user. The
// generation bump catches sessions the index misses (concurrently minted,
// dropped from the index) and pending 2FA/setup tokens; the index sweep
// removes the indexed sessions immediately.
func revokeUserAccess(username string) error {
	_, bumpErr := core.BumpAuthGeneration(username)
	// Sweep the index even if the bump failed, so indexed sessions still die.
	if err := core.InvalidateUserSessions(username); err != nil {
		slog.Warn("Session index sweep failed", "user", username, "error", err)
	}
	if bumpErr != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to revoke sessions")
	}
	return nil
}
