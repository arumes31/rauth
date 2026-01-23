package handlers

import (

	"encoding/json"

	"fmt"

	"log/slog"

	"net/http"

	"rauth/internal/core"



	"github.com/labstack/echo/v4"

)



type AdminHandler struct {

	Cfg *core.Config

}



func (h *AdminHandler) Dashboard(c echo.Context) error {

	users, err := core.ListUsers()

	if err != nil {

		slog.Error("Failed to list users", "error", err)

	}

	

	// Fetch sessions

	keys, err := core.TokenDB.Keys(core.Ctx, "X-rcloudauth-authtoken=*").Result()

	if err != nil {

		slog.Error("Failed to fetch sessions from Redis", "error", err)

	}



	var sessions []map[string]string

	for _, k := range keys {

		data, err := core.TokenDB.HGetAll(core.Ctx, k).Result()

		if err != nil {

			continue

		}

		data["token"] = k[25:] // Remove prefix

		data["ttl"] = fmt.Sprintf("%d", int(core.TokenDB.TTL(core.Ctx, k).Val().Seconds()))

		sessions = append(sessions, data)

	}



	// Fetch Audit Logs

	rawLogs, err := core.AuditDB.LRange(core.Ctx, "audit_logs", 0, 99).Result()

	if err != nil {

		slog.Error("Failed to fetch audit logs from Redis", "error", err)

	}



	var logs []core.AuditLog

	for _, l := range rawLogs {

		var log core.AuditLog

		if err := json.Unmarshal([]byte(l), &log); err != nil {

			continue

		}

		logs = append(logs, log)

	}



	return c.Render(http.StatusOK, "management.html", map[string]interface{}{

		"username": c.Get("username"),

		"users":    users,

		"sessions": sessions,

		"logs":     logs,

		"csrf":     c.Get("csrf"),

	})

}



func (h *AdminHandler) CreateUser(c echo.Context) error {

	user := c.FormValue("new_username")

	pass := c.FormValue("new_password")

	email := c.FormValue("new_email")

	isAdmin := c.FormValue("is_admin") == "on"



	if user == "" || pass == "" {

		return echo.NewHTTPError(http.StatusBadRequest, "Username and password are required")

	}



	if err := core.CreateUser(user, pass, email, isAdmin); err != nil {

		slog.Warn("Failed to create user", "user", user, "error", err)

		return echo.NewHTTPError(http.StatusBadRequest, err.Error())

	}

	

	slog.Info("User created by admin", "admin", c.Get("username"), "user", user)

	core.LogAudit("ADMIN_CREATE_USER", c.Get("username").(string), c.RealIP(), map[string]interface{}{"target": user})

	return c.Redirect(http.StatusFound, "/rauthmgmt")

}



func (h *AdminHandler) DeleteUser(c echo.Context) error {

	target := c.FormValue("username")

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

	return c.Redirect(http.StatusFound, "/rauthmgmt")

}



func (h *AdminHandler) InvalidateSession(c echo.Context) error {

	token := c.FormValue("token")

	admin := c.Get("username").(string)

	

	if err := core.TokenDB.Del(core.Ctx, "X-rcloudauth-authtoken="+token).Err(); err != nil {

		slog.Error("Failed to invalidate session", "error", err)

		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to invalidate session")

	}



	slog.Info("Session invalidated by admin", "admin", admin)

	core.LogAudit("ADMIN_INVALIDATE_SESSION", admin, c.RealIP(), map[string]interface{}{"token": token[:8] + "..."})

	return c.Redirect(http.StatusFound, "/rauthmgmt")

}
