package middleware

import (
	"log/slog"
	"net/http"
	"rauth/internal/core"

	"github.com/labstack/echo/v4"
)

func AuthMiddleware(cfg *core.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("X-rauth-authtoken")
			if err != nil {
				// Sanitize the redirect URI to prevent open redirect in the rd param itself
				rd := c.Request().RequestURI
				return c.Redirect(http.StatusFound, "/rauthlogin?rd="+rd)
			}

			token, err := core.DecryptToken(cookie.Value, cfg.ServerSecret)
			if err != nil || token == "" {
				slog.Warn("Failed to decrypt auth token or token empty", "ip", c.RealIP(), "error", err)
				return c.Redirect(http.StatusFound, "/rauthlogin")
			}

			data, err := core.TokenDB.HGetAll(core.Ctx, "X-rauth-authtoken="+token).Result()
			if err != nil {
				slog.Error("Redis error in auth middleware", "error", err)
				return c.Redirect(http.StatusFound, "/rauthlogin")
			}

			if len(data) == 0 || data["status"] != "valid" {
				return c.Redirect(http.StatusFound, "/rauthlogin")
			}

			c.Set("username", data["username"])
			c.Set("token", token)

			// Set headers for Nginx auth_request to forward to upstream
			c.Response().Header().Set("X-RAuth-User", data["username"])
			c.Response().Header().Set("X-RAuth-Groups", data["groups"])
			
			isAdmin := "0"
			if userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+data["username"]).Result(); err == nil {
				isAdmin = userData["is_admin"]
			}
			c.Response().Header().Set("X-RAuth-Admin", isAdmin)

			return next(c)
		}
	}
}

func AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		username, ok := c.Get("username").(string)
		if !ok {
			return c.Redirect(http.StatusFound, "/rauthlogin")
		}

		userData, err := core.UserDB.HGetAll(core.Ctx, "user:"+username).Result()
		if err != nil {
			slog.Error("Failed to fetch user data in admin middleware", "user", username, "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
		}
		
		if userData["is_admin"] != "1" {
			slog.Warn("Unauthorized admin access attempt", "user", username, "ip", c.RealIP())
			return echo.NewHTTPError(http.StatusForbidden, "Admin access required")
		}
		return next(c)
	}
}
