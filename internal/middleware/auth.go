package middleware

import (
	"net/http"
	"rauth/internal/core"
	"github.com/labstack/echo/v4"
)

func AuthMiddleware(cfg *core.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("X-rcloudauth-authtoken")
			if err != nil {
				return c.Redirect(http.StatusFound, "/login?rd="+c.Request().RequestURI)
			}

			token, err := core.DecryptToken(cookie.Value, cfg.ServerSecret)
			if err != nil {
				return c.Redirect(http.StatusFound, "/login")
			}

			data, err := core.TokenDB.HGetAll(core.Ctx, "X-rcloudauth-authtoken="+token).Result()
			if err != nil || data["status"] != "valid" {
				return c.Redirect(http.StatusFound, "/login")
			}

			c.Set("username", data["username"])
			c.Set("token", token)
			return next(c)
		}
	}
}

func AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		username := c.Get("username").(string)
		userData, _ := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
		
		if userData["is_admin"] != "1" {
			return c.String(http.StatusForbidden, "Admin access required")
		}
		return next(c)
	}
}
