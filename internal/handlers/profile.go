package handlers

import (
	"net/http"
	"rauth/internal/core"
	"github.com/labstack/echo/v4"
	"encoding/json"
)

type ProfileHandler struct {
	Cfg *core.Config
}

func (h *ProfileHandler) Show(c echo.Context) error {
	username := c.Get("username").(string)
	userData, _ := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()

	// Personal Logs
	rawLogs, _ := core.AuditDB.LRange(core.Ctx, "audit_logs", 0, 500).Result()
	var logs []core.AuditLog
	for _, l := range rawLogs {
		var log core.AuditLog
		json.Unmarshal([]byte(l), &log)
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

	userData, _ := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if !core.CheckPasswordHash(current, userData["password"]) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Current password incorrect"})
	}

	if newPass != confirm {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Passwords do not match"})
	}

	hash, _ := core.HashPassword(newPass)
	core.UpdateUser(username, map[string]interface{}{"password": hash})
	core.LogAudit("USER_CHANGE_PASSWORD", username, c.RealIP(), nil)

	return c.Redirect(http.StatusFound, "/rauthprofile?success=1")
}
