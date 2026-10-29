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

			// Fetch the full session so the same geo/device binding enforced on
			// /rauthvalidate can be applied to rauth's own pages.
			redisKey := "X-rauth-authtoken=" + token
			data, err := core.TokenDB.HGetAll(core.Ctx, redisKey).Result()
			if err != nil {
				slog.Error("Redis error in auth middleware", "error", err)
				return c.Redirect(http.StatusFound, "/rauthlogin")
			}

			if data["status"] != "valid" {
				return c.Redirect(http.StatusFound, "/rauthlogin")
			}

			username := data["username"]
			if username == "" {
				slog.Warn("Session missing username field", "ip", c.RealIP())
				return c.Redirect(http.StatusFound, "/rauthlogin")
			}

			// Reject sessions of deleted accounts or ones issued before the
			// user's last credential change (see core.BumpAuthGeneration). Not
			// deleted here: SessionAuthorized also fails closed on transient
			// Redis errors, which must not destroy a valid session.
			if !core.SessionAuthorized(data) {
				return c.Redirect(http.StatusFound, "/rauthlogin")
			}

			if !core.SessionBindingValid(cfg, c.Request(), token, redisKey, data, c.RealIP()) {
				return c.Redirect(http.StatusFound, "/rauthlogin")
			}

			c.Set("username", username)
			c.Set("token", token)
			// The generation this request was authorized under, for writes that
			// must not land after a concurrent revocation (passkey registration).
			c.Set("auth_gen", core.SessionGen(data))

			// is_admin is stamped into the token at issue time. Fall back to a
			// single-field user lookup only for legacy sessions that predate it.
			isAdmin := data["is_admin"]
			if isAdmin == "" {
				if v, err := core.UserIsAdmin(username); err == nil && v {
					isAdmin = "1"
				}
			}
			if isAdmin == "" {
				isAdmin = "0"
			}
			c.Set("is_admin", isAdmin)

			groups := data["groups"]

			// Set headers for Nginx auth_request to forward to upstream
			c.Response().Header().Set("X-RAuth-User", username)
			c.Response().Header().Set("X-RAuth-Groups", groups)
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

		// Check admin status against the live user record rather than the value
		// stamped into the session at login, so a demotion takes effect on the
		// admin UI immediately instead of after the session expires.
		isAdmin, err := core.UserIsAdmin(username)
		if err != nil {
			slog.Error("Failed to fetch admin status in admin middleware", "user", username, "error", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
		}

		if !isAdmin {
			slog.Warn("Unauthorized admin access attempt", "user", username, "ip", c.RealIP())
			return echo.NewHTTPError(http.StatusForbidden, "Admin access required")
		}
		return next(c)
	}
}
