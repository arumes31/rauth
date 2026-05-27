package middleware

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func UACHMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform, Sec-CH-UA-Mobile, Sec-CH-UA-Model")

			// Only negotiate Critical-CH on idempotent GET/HEAD requests to prevent non-idempotent retries (like POST logins)
			if c.Request().Method == http.MethodGet || c.Request().Method == http.MethodHead {
				c.Response().Header().Set("Critical-CH", "Sec-CH-UA-Platform, Sec-CH-UA-Mobile, Sec-CH-UA-Model")
			}

			c.Response().Header().Add("Vary", "Sec-CH-UA-Platform")
			c.Response().Header().Add("Vary", "Sec-CH-UA-Mobile")
			c.Response().Header().Add("Vary", "Sec-CH-UA-Model")
			return next(c)
		}
	}
}
