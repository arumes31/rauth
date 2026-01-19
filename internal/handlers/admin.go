package handlers

import (
	"net/http"
	"rauth/internal/core"
	"github.com/labstack/echo/v4"
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
		data["ttl"] = fmt.Sprintf("%d", core.TokenDB.TTL(core.Ctx, k).Val().Seconds())
		sessions = append(sessions, data)
	}

	return c.Render(http.StatusOK, "management.html", map[string]interface{}{
		"username": c.Get("username"),
		"users":    users,
		"sessions": sessions,
	})
}

func (h *AdminHandler) CreateUser(c echo.Context) error {
	user := c.FormValue("new_username")
	pass := c.FormValue("new_password")
	email := c.FormValue("new_email")
	isAdmin := c.FormValue("is_admin") == "on"

	if err := core.CreateUser(user, pass, email, isAdmin); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	
	core.LogAudit("ADMIN_CREATE_USER", c.Get("username").(string), c.RealIP(), map[string]interface{}{"target": user})
	return c.Redirect(http.StatusFound, "/rauthmgmt")
}
