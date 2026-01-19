package handlers

import (
	"fmt"
	"net/http"
	"rauth/internal/core"
	"github.com/labstack/echo/v4"
	"encoding/json"
)

type AdminHandler struct {
	Cfg *core.Config
}

func (h *AdminHandler) Dashboard(c echo.Context) error {
	users, _ := core.ListUsers()
	
	// Fetch sessions
	keys, _ := core.TokenDB.Keys(core.Ctx, "X-rcloudauth-authtoken=*").Result()
	var sessions []map[string]string
	for _, k := range keys {
		data, _ := core.TokenDB.HGetAll(core.Ctx, k).Result()
		data["token"] = k[25:] // Remove prefix
		data["ttl"] = fmt.Sprintf("%d", int(core.TokenDB.TTL(core.Ctx, k).Val().Seconds()))
		sessions = append(sessions, data)
	}

	// Fetch Audit Logs
	rawLogs, _ := core.AuditDB.LRange(core.Ctx, "audit_logs", 0, 99).Result()
	var logs []core.AuditLog
	for _, l := range rawLogs {
		var log core.AuditLog
		json.Unmarshal([]byte(l), &log)
		logs = append(logs, log)
	}

	return c.Render(http.StatusOK, "management.html", map[string]interface{}{
		"username": c.Get("username"),
		"users":    users,
		"sessions": sessions,
		"logs":     logs,
	})
}

func (h *AdminHandler) CreateUser(c echo.Context) error {
	user := c.FormValue("new_username")
	pass := c.FormValue("new_password")
	email := c.FormValue("new_email")
	isAdmin := c.FormValue("is_admin") == "on"

	if err := core.CreateUser(user, pass, email, isAdmin); err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	
	core.LogAudit("ADMIN_CREATE_USER", c.Get("username").(string), c.RealIP(), map[string]interface{}{"target": user})
	return c.Redirect(http.StatusFound, "/rauthmgmt")
}

func (h *AdminHandler) DeleteUser(c echo.Context) error {
	target := c.FormValue("username")
	admin := c.Get("username").(string)
	if target == admin {
		return c.String(http.StatusBadRequest, "Cannot delete yourself")
	}

	core.DeleteUser(target)
	core.LogAudit("ADMIN_DELETE_USER", admin, c.RealIP(), map[string]interface{}{"target": target})
	return c.Redirect(http.StatusFound, "/rauthmgmt")
}

func (h *AdminHandler) InvalidateSession(c echo.Context) error {
	token := c.FormValue("token")
	admin := c.Get("username").(string)
	
	core.TokenDB.Del(core.Ctx, "X-rcloudauth-authtoken="+token)
	core.LogAudit("ADMIN_INVALIDATE_SESSION", admin, c.RealIP(), map[string]interface{}{"token": token[:8] + "..."})
	return c.Redirect(http.StatusFound, "/rauthmgmt")
}