package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"rauth/internal/core"

	"github.com/labstack/echo/v4"
)

type ProfileHandler struct {
	Cfg *core.Config
}

func (h *ProfileHandler) Show(c echo.Context) error {
	username := c.Get("username").(string)
	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil {
		slog.Error("Failed to fetch user data", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to load profile")
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

	return c.Render(http.StatusOK, "profile.html", map[string]interface{}{
		"username": username,
		"email":    userData["email"],
		"groups":   userData["groups"],
		"isAdmin":  userData["is_admin"] == "1",
		"logs":     logs,
		"csrf":     c.Get("csrf"),
	})
}

func (h *ProfileHandler) ChangePassword(c echo.Context) error {
	username := c.Get("username").(string)
	current := c.FormValue("current_password")
	newPass := c.FormValue("new_password")
	confirm := c.FormValue("confirm_password")

	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil {
		slog.Error("Failed to fetch user data for password change", "user", username, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Internal error")
	}

	if !core.CheckPasswordHash(current, userData["password"]) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Current password incorrect"})
	}

	if newPass != confirm {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Passwords do not match"})
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

	slog.Info("Password changed by user", "user", username)
	core.LogAudit("USER_CHANGE_PASSWORD", username, c.RealIP(), nil)

	return c.Redirect(http.StatusFound, "/rauthprofile?success=1")
}
