package handlers

import (
	"fmt"
	"net/http"
	"rauth/internal/core"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
)

type AuthHandler struct {
	Cfg *core.Config
}

func (h *AuthHandler) Validate(c echo.Context) error {
	cookie, err := c.Cookie("X-rcloudauth-authtoken")
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	token, err := core.DecryptToken(cookie.Value, h.Cfg.ServerSecret)
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	redisKey := "X-rcloudauth-authtoken=" + token
	data, err := core.TokenDB.HGetAll(core.Ctx, redisKey).Result()
	if err != nil || len(data) == 0 {
		return c.NoContent(http.StatusUnauthorized)
	}

	if data["status"] != "valid" {
		return c.NoContent(http.StatusUnauthorized)
	}

	// RBAC check
	requiredGroup := c.Request().Header.Get("X-RAuth-Required-Group")
	if requiredGroup != "" {
		userData, _ := core.UserDB.HGetAll(core.Ctx, "user:"+data["username"]).Result()
		groups := strings.Split(userData["groups"], ",")
		found := false
		for _, g := range groups {
			if strings.TrimSpace(g) == requiredGroup {
				found = true
				break
			}
		}
		if !found {
			return c.String(http.StatusForbidden, "Missing group "+requiredGroup)
		}
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) Login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
	if err != nil || len(userData) == 0 {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"error": "Invalid credentials",
		})
	}

	if !core.CheckPasswordHash(password, userData["password"]) {
		core.LogAudit("LOGIN_FAILED", username, c.RealIP(), nil)
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{
			"error": "Invalid credentials",
		})
	}

	if userData["2fa_secret"] != "" {
		// Set session pending 2FA
		sess, _ := c.Cookie("session_id") // Simple session implementation needed
		_ = sess
		// ... handle 2FA redirect ...
	}

	// For now, issue token directly if no 2FA
	h.issueToken(c, username)
	return nil
}

func (h *AuthHandler) issueToken(c echo.Context, username string) {
	// ... logic to issue token, set cookie, and redirect ...
}
