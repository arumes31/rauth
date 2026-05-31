package middleware

import (
	"log/slog"
	"net/http"
	"net/url"
	"rauth/internal/core"

	"github.com/labstack/echo/v4"
)

func AuthMiddleware(cfg *core.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("X-rauth-authtoken")
			if err != nil {
				// Sanitize the redirect URI to prevent open redirect in the rd param itself
				rd := url.QueryEscape(c.Request().RequestURI)
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

			// is_admin is stamped into the token at issue time. Fall back to a
			// single-field user lookup only for legacy sessions that predate it.
			isAdmin := data["is_admin"]
			if isAdmin == "" {
				if v, err := core.UserDB.HGet(core.Ctx, "user:"+data["username"], "is_admin").Result(); err == nil {
					isAdmin = v
				}
			}
			if isAdmin == "" {
				isAdmin = "0"
			}
			c.Set("is_admin", isAdmin)

			// Set headers for Nginx auth_request to forward to upstream
			c.Response().Header().Set("X-RAuth-User", data["username"])
			c.Response().Header().Set("X-RAuth-Groups", data["groups"])
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

		// AuthMiddleware already resolved admin status into the context; reuse it
		// rather than re-fetching the whole user hash.
		isAdmin, _ := c.Get("is_admin").(string)
		if isAdmin == "" {
			v, err := core.UserDB.HGet(core.Ctx, "user:"+username, "is_admin").Result()
			if err != nil {
				slog.Error("Failed to fetch admin status in admin middleware", "user", username, "error", err)
				return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
			}
			isAdmin = v
		}

		if isAdmin != "1" {
			slog.Warn("Unauthorized admin access attempt", "user", username, "ip", c.RealIP())
			return echo.NewHTTPError(http.StatusForbidden, "Admin access required")
		}
		return next(c)
	}
}
