package middleware

import (
	"log/slog"
	"rauth/internal/core"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
)

func LoggingMiddleware() echo.MiddlewareFunc {
	return echoMiddleware.RequestLoggerWithConfig(echoMiddleware.RequestLoggerConfig{
		LogStatus:   true,
		LogURI:      true,
		LogMethod:   true,
		LogRemoteIP: true,
		LogLatency:  true,
		LogError:    true,
		HandleError: true,
		LogValuesFunc: func(c echo.Context, v echoMiddleware.RequestLoggerValues) error {
			xForwardedFor := c.Request().Header.Get("X-Forwarded-For")
			if xForwardedFor == "" {
				xForwardedFor = "-"
			}

			cfIP := c.Request().Header.Get("CF-Connecting-IP")
			if cfIP == "" {
				cfIP = "-"
			}

			geoIP := core.GetCountryCode(v.RemoteIP)

			if v.Error == nil {
				slog.Info("request",
					slog.String("ip", v.RemoteIP),
					slog.String("x_forwarded_for", xForwardedFor),
					slog.String("cf_ip", cfIP),
					slog.String("geo", geoIP),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Duration("latency", v.Latency),
				)
			} else {
				slog.Error("request error",
					slog.String("ip", v.RemoteIP),
					slog.String("x_forwarded_for", xForwardedFor),
					slog.String("cf_ip", cfIP),
					slog.String("geo", geoIP),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Duration("latency", v.Latency),
					slog.String("err", v.Error.Error()),
				)
			}
			return nil
		},
	})
}
