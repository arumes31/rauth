package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"rauth/internal/middleware"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templateFS embed.FS

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	// Initialize slog
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := core.LoadConfig()

	if err := core.InitRedis(cfg); err != nil {
		slog.Error("Redis initialization failed", "error", err)
		os.Exit(1)
	}

	if err := core.InitWebAuthn(cfg); err != nil {
		slog.Error("WebAuthn initialization failed", "error", err)
	}

	// Startup Initialization
	initializeSystem(cfg)

	e := echo.New()
	e.HideBanner = true

	// Configure real IP extraction from headers behind reverse proxies
	e.IPExtractor = func(req *http.Request) string {
		if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return cfIP
		}
		if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				cleaned := strings.TrimSpace(ips[0])
				if cleaned != "" {
					return cleaned
				}
			}
		}
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err == nil {
			return host
		}
		return req.RemoteAddr
	}

	// Setup everything
	setupMiddleware(e, cfg)
	setupRenderer(e)
	setupRoutes(e, cfg)

	go func() {
		if err := e.Start(":80"); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}

func setupMiddleware(e *echo.Echo, cfg *core.Config) {
	// Security headers and hardening
	e.Use(echoMiddleware.Secure())
	e.Use(echoMiddleware.BodyLimit("1M"))

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

	// Structured logging middleware
	e.Use(echoMiddleware.RequestLoggerWithConfig(echoMiddleware.RequestLoggerConfig{
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
	}))

	e.Use(echoMiddleware.Recover())

	// Custom HTTP Error Handler
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		code := http.StatusInternalServerError
		if he, ok := err.(*echo.HTTPError); ok {
			code = he.Code
		}

		errorData := map[string]interface{}{
			"Code":    code,
			"Title":   "Error",
			"Message": "An unexpected error occurred.",
			"Icon":    "bi-exclamation-triangle",
			"Color":   "warning",
		}

		switch code {
		case http.StatusNotFound:
			errorData["Title"] = "Page Not Found"
			errorData["Message"] = "The identity you are looking for does not exist or has moved to another dimension."
			errorData["Icon"] = "bi-exclamation-octagon"
			errorData["Color"] = "danger"
		case http.StatusForbidden:
			errorData["Title"] = "Access Forbidden"
			errorData["Message"] = "You do not have the required clearance to access this sector."
			errorData["Icon"] = "bi-shield-lock"
			errorData["Color"] = "danger"
		case http.StatusInternalServerError:
			errorData["Title"] = "System Error"
			errorData["Message"] = "Something went wrong in the core. Our engineers have been notified."
			errorData["Icon"] = "bi-cpu"
			errorData["Color"] = "primary"
		default:
			// Generic handler for other codes
			errorData["Title"] = http.StatusText(code)
		}

		if renderErr := c.Render(code, "error.html", errorData); renderErr != nil {
			slog.Error("Failed to render error page", "error", renderErr)
		}
	}

	// Explicitly set NotFoundHandler to use our error handler
	echo.NotFoundHandler = func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusNotFound)
	}

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

func setupRenderer(e *echo.Echo) {
	funcMap := template.FuncMap{
		"formatTime": func(input interface{}) string {
			var timestamp int64
			switch v := input.(type) {
			case int64:
				timestamp = v
			case int:
				timestamp = int64(v)
			case string:
				timestamp, _ = strconv.ParseInt(v, 10, 64)
			default:
				return "N/A"
			}
			if timestamp == 0 {
				return "N/A"
			}
			return time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
		},
		"formatSeconds": func(s string) string {
			sec, _ := strconv.Atoi(s)
			return fmt.Sprintf("%dm %ds", sec/60, sec%60)
		},
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
		"statusColor": func(action string) string {
			if action == "LOGIN_SUCCESS" || action == "2FA_SETUP_SUCCESS" {
				return "text-success"
			}
			if action == "LOGIN_FAILED" || action == "2FA_FAILED" || action == "COUNTRY_CHANGE_DETECTED" {
				return "text-danger"
			}
			return "text-info"
		},
	}

	renderer := &TemplateRenderer{
		templates: template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html")),
	}
	e.Renderer = renderer
}

func setupRoutes(e *echo.Echo, cfg *core.Config) {
	e.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(staticFS))))

	authHandler := &handlers.AuthHandler{Cfg: cfg}
	adminHandler := &handlers.AdminHandler{Cfg: cfg}
	profileHandler := &handlers.ProfileHandler{Cfg: cfg}
	webauthnHandler := &handlers.WebAuthnHandler{Cfg: cfg}
	healthHandler := &handlers.HealthHandler{Cfg: cfg}
	inviteHandler := &handlers.InviteHandler{Cfg: cfg}

	// Public Routes
	e.GET("/", authHandler.Root)
	e.GET("/rauthvalidate", authHandler.Validate)
	e.GET("/rauthlogin", authHandler.Login)
	e.POST("/rauthlogin", authHandler.Login)
	e.POST("/verify-2fa", authHandler.Verify2FA)
	e.GET("/rauthsetup2fa", authHandler.Setup2FA)
	e.POST("/rauthsetup2fa", authHandler.CompleteSetup2FA)
	e.GET("/rauthredeem", inviteHandler.RedeemPage)
	e.POST("/rauthredeem", inviteHandler.Redeem)

	e.GET("/health", healthHandler.Check)

	// WebAuthn Public Login
	e.GET("/webauthn/login/begin", webauthnHandler.BeginLogin)
	e.POST("/webauthn/login/finish", webauthnHandler.FinishLogin)

	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()), func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if cfg.IsIPAllowed(c.RealIP(), cfg.MetricsAllowedIPs) {
				return next(c)
			}
			slog.Warn("Metrics access denied", "ip", c.RealIP())
			return echo.NewHTTPError(http.StatusForbidden, "Access Denied")
		}
	})

	// Protected Routes
	protected := e.Group("")
	protected.Use(middleware.AuthMiddleware(cfg))

	// WebAuthn Protected Registration
	protected.GET("/webauthn/register/begin", webauthnHandler.BeginRegistration)
	protected.POST("/webauthn/register/finish", webauthnHandler.FinishRegistration)

	protected.POST("/logout", func(c echo.Context) error {
		// Get token from context (set by AuthMiddleware)
		if token, ok := c.Get("token").(string); ok {
			if username, ok := c.Get("username").(string); ok {
				core.RemoveSessionIndex(username, token)
			}
			core.TokenDB.Del(core.Ctx, "X-rauth-authtoken="+token)
		}

		cookie := &http.Cookie{
			Name:     "X-rauth-authtoken",
			Value:    "",
			Path:     "/",
			Domain:   cfg.CookieDomains[0],
			Expires:  time.Now().Add(-1 * time.Hour),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		c.SetCookie(cookie)
		return c.Redirect(http.StatusFound, "/rauthlogin")
	})

	// Profile Routes
	protected.GET("/rauthprofile", profileHandler.Show)
	protected.POST("/rauthprofile/password", profileHandler.ChangePassword)
	protected.POST("/rauthprofile/session/terminate", profileHandler.TerminateSession)
	protected.POST("/rauthprofile/session/terminate-others", profileHandler.TerminateAllOtherSessions)
	protected.POST("/rauthprofile/passkey/rename", profileHandler.RenamePasskey)
	protected.POST("/rauthprofile/passkey/revoke", profileHandler.RevokePasskey)
	protected.POST("/rauthprofile/disable-totp", profileHandler.DisableTOTP)

	// Admin Routes
	admin := protected.Group("/rauthmgmt")
	admin.Use(middleware.AdminMiddleware)
	admin.GET("", adminHandler.Dashboard)
	admin.POST("/user/create", adminHandler.CreateUser)
	admin.POST("/user/delete", adminHandler.DeleteUser)
	admin.POST("/user/reset-2fa", adminHandler.ResetUser2FA)
	admin.POST("/user/change-password", adminHandler.ChangeUserPassword)
	admin.POST("/user/update-email", adminHandler.UpdateUserEmail)
	admin.POST("/session/invalidate", adminHandler.InvalidateSession)
	admin.POST("/invite/create", inviteHandler.Create)
}

func initializeSystem(cfg *core.Config) {
	// Start GeoIP Updater
	core.StartGeoUpdater(cfg)

	if cfg.InitialUser != "" && cfg.InitialPassword != "" {
		slog.Info("Checking initial user", "user", cfg.InitialUser)
		err := core.CreateUser(cfg.InitialUser, cfg.InitialPassword, cfg.InitialEmail, true, cfg.Initial2FASecret)
		if err == nil {
			slog.Info("Initial admin user created")
		} else {
			slog.Info("Initial user already exists or check failed", "error", err)
		}
	}

	// Background metrics updater
	go func() {
		for {
			// Count active sessions
			var count int64
			iter := core.TokenDB.Scan(core.Ctx, 0, "X-rauth-authtoken=*", 0).Iterator()
			for iter.Next(core.Ctx) {
				count++
			}
			core.ActiveSessionsGauge.Set(float64(count))
			time.Sleep(1 * time.Minute)
		}
	}()
}
