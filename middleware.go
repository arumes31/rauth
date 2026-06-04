package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"rauth/internal/core"
	"strings"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
)

func setupMiddleware(e *echo.Echo) {
	// Order matters: Secure headers and BodyLimit run first, then Client Hints
	// and the request logger, then Recover and CSRF last. Keeping the logger
	// ahead of Recover/CSRF ensures every request — including CSRF rejections —
	// is logged.
	setupSecurityMiddleware(e)
	setupClientHintsMiddleware(e)
	setupLoggingMiddleware(e)
	e.Use(echoMiddleware.Recover())
	setupErrorHandlers(e)
	setupCSRFMiddleware(e)
}

func setupSecurityMiddleware(e *echo.Echo) {
	// Security headers and hardening. Secure()'s defaults leave HSTS disabled
	// and set no CSP, so configure both explicitly. The CSP allows inline
	// scripts/styles because the templates rely on inline <script> blocks and
	// style="" attributes (matrix/glassmorphism UI).
	e.Use(echoMiddleware.SecureWithConfig(echoMiddleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "SAMEORIGIN",
		// HSTS with preload is a hard-to-reverse commitment: it emits
		// `includeSubDomains; preload`, so every subdomain of COOKIE_DOMAIN MUST
		// be served exclusively over HTTPS before this is left enabled (and
		// before submitting the domain to the preload list). If any subdomain
		// needs plain HTTP, set HSTSPreloadEnabled:false and/or lower HSTSMaxAge.
		HSTSMaxAge:            31536000,
		HSTSPreloadEnabled:    true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
	}))
	e.Use(echoMiddleware.BodyLimit("1M"))
}

func setupCSRFMiddleware(e *echo.Echo) {
	// CSRF Protection
	e.Use(echoMiddleware.CSRFWithConfig(echoMiddleware.CSRFConfig{ // #nosec G101
		TokenLookup:    "header:X-CSRF-Token,form:csrf",
		CookieName:     "_csrf",
		CookiePath:     "/",
		CookieHTTPOnly: true,
		CookieSecure:   true,
		CookieSameSite: http.SameSiteLaxMode,
	}))
}

func setupLoggingMiddleware(e *echo.Echo) {
	// Structured logging middleware
	e.Use(echoMiddleware.RequestLoggerWithConfig(echoMiddleware.RequestLoggerConfig{
		LogStatus:     true,
		LogURI:        true,
		LogMethod:     true,
		LogRemoteIP:   true,
		LogLatency:    true,
		LogError:      true,
		HandleError:   true,
		LogValuesFunc: logRequest,
	}))
}

func logRequest(c echo.Context, v echoMiddleware.RequestLoggerValues) error {
	req := c.Request()

	// client_ip is the IP resolved by CreateIPExtractor (honouring the
	// configured trust settings). The raw forwarding headers are logged
	// only when present so the common case stays uncluttered and, when
	// the resolved IP looks wrong, the chain is visible for debugging.
	attrs := []slog.Attr{
		slog.String("client_ip", v.RemoteIP),
		slog.String("method", v.Method),
		slog.String("uri", v.URI),
		slog.Int("status", v.Status),
		slog.Duration("latency", v.Latency),
		slog.String("geo", core.GetCountryCode(v.RemoteIP)),
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		attrs = append(attrs, slog.String("x_forwarded_for", xff))
	}
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		attrs = append(attrs, slog.String("x_real_ip", xri))
	}
	if cf := req.Header.Get("CF-Connecting-IP"); cf != "" {
		attrs = append(attrs, slog.String("cf_ip", cf))
	}

	level := slog.LevelInfo
	msg := "request"
	if v.Error != nil {
		level = slog.LevelError
		msg = "request error"
		attrs = append(attrs, slog.String("err", v.Error.Error()))
	}
	slog.LogAttrs(req.Context(), level, msg, attrs...)
	return nil
}

func setupClientHintsMiddleware(e *echo.Echo) {
	// User-Agent Client Hints negotiation middleware
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
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
	})
}

func setupErrorHandlers(e *echo.Echo) {
	// Custom HTTP Error Handler
	e.HTTPErrorHandler = customHTTPErrorHandler

	// Explicitly set NotFoundHandler to use our error handler
	echo.NotFoundHandler = func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusNotFound)
	}
}

func customHTTPErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}

	code := http.StatusInternalServerError
	message := "An unexpected error occurred."
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		if he.Message != nil {
			message = fmt.Sprintf("%v", he.Message)
		}
	}

	// API and forward-auth endpoints expect machine-readable responses, not
	// the HTML error page. The /rauthvalidate endpoint in particular is
	// polled by nginx auth_request and must stay body-less.
	path := c.Request().URL.Path
	switch {
	case path == "/rauthvalidate":
		_ = c.NoContent(code)
		return
	case strings.HasPrefix(path, "/webauthn/") || path == "/metrics" || path == "/health":
		if jsonErr := c.JSON(code, map[string]interface{}{"error": message, "code": code}); jsonErr != nil {
			slog.Error("Failed to render JSON error", "error", jsonErr)
		}
		return
	}

	errorData := getErrorPageData(code)

	if renderErr := c.Render(code, "error.html", errorData); renderErr != nil {
		slog.Error("Failed to render error page", "error", renderErr)
	}
}

func getErrorPageData(code int) map[string]interface{} {
	data := map[string]interface{}{
		"Code":    code,
		"Title":   "Error",
		"Message": "An unexpected error occurred.",
		"Icon":    "bi-exclamation-triangle",
		"Color":   "warning",
	}

	switch code {
	case http.StatusNotFound:
		data["Title"] = "Page Not Found"
		data["Message"] = "The identity you are looking for does not exist or has moved to another dimension."
		data["Icon"] = "bi-exclamation-octagon"
		data["Color"] = "danger"
	case http.StatusForbidden:
		data["Title"] = "Access Forbidden"
		data["Message"] = "You do not have the required clearance to access this sector."
		data["Icon"] = "bi-shield-lock"
		data["Color"] = "danger"
	case http.StatusInternalServerError:
		data["Title"] = "System Error"
		data["Message"] = "Something went wrong in the core. Our engineers have been notified."
		data["Icon"] = "bi-cpu"
		data["Color"] = "primary"
	default:
		// Generic handler for other codes
		data["Title"] = http.StatusText(code)
	}

	return data
}
